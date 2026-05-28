import json
import re
import shlex
import time
import hashlib
from agents.base_agent import BaseAgent
from utils.display import section, info, warning, success
from config import USE_REMOTE_VPS
from core.target_context import TargetContext
from intelligence.waf_fingerprinter import WafFingerprinter
from core.robust_parser import extract_json, extract_json_list
from core.result_contracts import FragileParseFixer
import config_paths

class ReconAgent(BaseAgent):
    def _preflight(self) -> tuple[bool, str]:
        """Verify core tools are available. Only hard-block if BOTH nmap and curl are missing."""
        self.log.info("Performing pre-flight dependency checks...")
        # Hard-required: nmap (port scan) + curl (HTTP probes). Everything else is optional.
        HARD_REQUIRED = ["nmap", "curl"]
        # Optional: warn but don't block
        try:
            rules = self._load_rules("recon")
            optional_tools = rules.get("core_tools", ["masscan", "dig", "subfinder"])
            optional_tools = [t for t in optional_tools if t not in HARD_REQUIRED]
        except Exception:
            optional_tools = ["masscan", "dig", "subfinder"]

        missing_hard = [t for t in HARD_REQUIRED if not self.tools.ensure_installed(t)]
        if missing_hard:
            return False, f"Missing critical recon tools (hard block): {', '.join(missing_hard)}"

        missing_opt = [t for t in optional_tools if not self.tools.ensure_installed(t)]
        if missing_opt:
            self.log.warning(f"Optional recon tools missing (degraded mode): {', '.join(missing_opt)}")

        return True, ""


    def _verify_subdomain(self, subdomain: str, wildcard_ips: set,
                           is_cdn: bool = False, silent: bool = False) -> tuple[bool, str | None]:
        """
        Post-enumeration filter to eliminate wildcard DNS / CDN noise.
        """
        infra = self._get_infra_rules()
        dns_resolver = infra.get("global_dns_resolver", "1.1.1.1")
        
        r_dig = self.safe_run_tool(
            "dig", f"dig @{dns_resolver} +short {subdomain}", self.session.target,
            silent=silent
        )
        out = r_dig.stdout
        resolved_ips = set(
            line.strip() for line in out.strip().splitlines()
            if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', line.strip())
        )

        if not resolved_ips:
            return False, None

        if wildcard_ips and (resolved_ips == wildcard_ips or
                              resolved_ips.issubset(wildcard_ips)):
            return False, None

        clean_sub = re.sub(r'^https?://', '', subdomain).strip('/').lstrip('.')
        
        r = self.safe_run_tool(
            "curl",
            f"curl -sI --max-time 5 http://{clean_sub}",
            self.session.target,
            silent=silent
        )
        combined = (r.stdout + r.stderr).upper()
        
        if any(x in combined for x in ["DEPLOYMENT_NOT_FOUND", "DEPLOYMENT_NOT_READY",
                                         "ERR_NGROK_3200", "NO_RESPONSE", "DIRECT_ACCESS_FORBIDDEN"]):
            return False, None

        if not r.success:
            return False, None

        return True, list(resolved_ips)[0]

    def _emit_ai_recon_findings(self, tool_name: str, target: str, parsed: dict) -> int:
        if not isinstance(parsed, dict):
            return 0

        added = 0
        tool = (tool_name or "").lower()

        if tool in {"nmap", "masscan"}:
            services = parsed.get("services", {}) if tool == "nmap" else {}
            if services:
                for port, svc in list(services.items())[:30]:
                    proto = svc.get("protocol", "tcp")
                    service = svc.get("service", "?")
                    version = svc.get("version", "")
                    detail = f"Port {port}/{proto}: {service} {version}".strip()
                    sev = "medium"
                    try:
                        sev = "info" if int(port) in (80, 443) else "medium"
                    except Exception:
                        pass
                    self.add_finding("open_port", target, detail, sev)
                    added += 1
            else:
                for port in parsed.get("open_ports", [])[:30]:
                    sev = "medium"
                    try:
                        sev = "info" if int(port) in (80, 443) else "medium"
                    except Exception:
                        pass
                    self.add_finding("open_port", target, f"Port {port}/tcp discovered", sev)
                    added += 1

        elif tool == "sslscan":
            findings = parsed.get("findings", []) if isinstance(parsed.get("findings"), list) else []
            for finding in findings[:20]:
                lower = finding.lower()
                sev = "high" if any(k in lower for k in ("weak protocol", "expired", "self-signed", "not trusted")) else "medium"
                self.add_finding("ssl_observation", target, finding, sev)
                added += 1

            protocols = parsed.get("protocols", {}) if isinstance(parsed.get("protocols"), dict) else {}
            if protocols and not findings:
                enabled = [k for k, v in protocols.items() if str(v).lower() == "enabled"]
                if enabled:
                    self.add_finding("ssl_observation", target, f"Enabled protocols: {', '.join(enabled)}", "info")
                    added += 1

        elif tool == "whatweb":
            tech = parsed.get("technologies", {}) if isinstance(parsed.get("technologies"), dict) else {}
            for key, value in list(tech.items())[:15]:
                self.add_finding("tech_stack", target, f"{key}: {value}", "info")
                added += 1
            for finding in parsed.get("findings", [])[:10]:
                self.add_finding("web_fingerprint", target, finding, "info")
                added += 1

        elif tool in {"gobuster", "ffuf", "feroxbuster"}:
            for finding in parsed.get("findings", [])[:30]:
                self.add_finding("discovered_endpoint", target, finding, "info")
                added += 1
                # If a directory is found, consider it a potential app root (base path)
                if finding.endswith("/") or "Status: 301" in finding or "Dir" in finding:
                    path = finding.split()[0].split("?")[0]
                    if not path.startswith("/"):
                        path = "/" + path
                    if not path.endswith("/"):
                        path += "/"
                    self.add_finding("app_root", target, path, "info")

        elif tool == "nikto":
            try:
                rules = self._load_rules("recon")
                NIKTO_NOISE = rules.get("nikto_noise", [
                    "no cgi directories found", "items checked", "host(s) tested",
                    "target hostname", "target ip", "target port", "target host",
                    "start time", "end time", "nikto v", "server:", "host maximum execution time",
                    "no web server found", "0 host(s)", "1 host(s)", "error:",
                    "root page", "redirects to",
                ])
            except Exception:
                NIKTO_NOISE = [
                    "no cgi directories found", "items checked", "host(s) tested",
                    "target hostname", "target ip", "target port", "target host",
                    "start time", "end time", "nikto v", "server:", "host maximum execution time",
                    "no web server found", "0 host(s)", "1 host(s)", "error:",
                    "root page", "redirects to", "using encoding:", "uncommon header",
                ]

            for finding in parsed.get("findings", [])[:20]:
                lower = finding.lower()
                if any(noise in lower for noise in NIKTO_NOISE):
                    continue
                self.add_finding("web_vulnerability_hint", target, finding, "medium")
                added += 1

        elif tool == "nuclei":
            for vuln in parsed.get("findings", [])[:30]:
                template_id = vuln.get("template_id") or "unknown-template"
                name = vuln.get("name") or "Unnamed finding"
                sev = str(vuln.get("severity", "info")).lower()
                self.add_finding("vulnerability_hint", target, f"{template_id}: {name}", sev)
                added += 1

        elif tool == "wafw00f":
            if parsed.get("is_behind_waf"):
                waf_name = parsed.get("waf_name") or "WAF"
                self.add_finding("waf_detected", target, f"AI recon confirmed {waf_name}", "medium")
                added += 1

        # â”€â”€ GENERIC SENSITIVE DATA EXTRACTOR â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
        # Universal regex fallback to catch critical items in raw tool outputs
        # that specific parsers might miss.
        raw_out = str(parsed.get("raw", "")) or str(parsed)
        SENSITIVE_REGEX = {
            "private_key": r"-----BEGIN [A-Z ]+ PRIVATE KEY-----",
            "cloud_secret": r"(?:AKIA|ASIA)[0-9A-Z]{16}",
            "shadow_entry": r"^[a-z_][a-z0-9_-]*:\$1\$\w+\$.*",
        }
        for name, regex in SENSITIVE_REGEX.items():
            matches = re.findall(regex, raw_out, re.IGNORECASE | re.MULTILINE)
            for m in list(set(matches))[:5]:
                match_str = m if isinstance(m, str) else str(m)
                self.add_finding("encrypted_data" if name == "hash" else name, target, f"Sensitive {name} found: {match_str[:50]}...", "critical")
                added += 1

        return added

    async def run(self) -> dict:
        section("PHASE 2 - Reconnaissance")
        self.store.set_phase_status(self.session.engagement_id, "recon", "running")

        # ── TARGET NORMALIZATION (Robust V6) ─────────────────────────────────
        # V6 FIX: NEVER use scope._normalize_target() here - it strips the scheme
        # returning a bare host. Downstream safe_run_tool then re-prefixes with http://,
        # causing str.replace("novalink.lk", "http://novalink.lk") to corrupt any
        # command already containing https://novalink.lk/ -> "https://http://novalink.lk/".
        raw_target = self.session.target
        try:
            _tc = TargetContext.from_input(raw_target)
            target = _tc.base_url   # e.g. "https://novalink.lk" (canonical, scheme preserved)
            host   = _tc.host       # e.g. "novalink.lk"        (bare hostname for DNS/nmap)
        except Exception:
            target = TargetContext.normalize_url(raw_target)
            host   = re.sub(r"^https?://", "", target).split("/")[0].split(":")[0]
        results = {}

        try:
            rules = self._load_rules("recon")
        except Exception:
            rules = {}

        infra = self._get_infra_rules()
        dns_resolver = infra.get("global_dns_resolver", "1.1.1.1")
        
        # Track executed commands to avoid loops
        executed_commands = set()
        max_recon_loops = rules.get("max_recon_loops", 3)
        current_loop = 0

        # ── INITIAL PROBE ──
        # Always run these fast probes to give AI a starting point
        info("Running initial discovery probe...")
        
        # 1. WAF & Baseline - target is already a full URL with scheme
        fingerprinter = WafFingerprinter()
        target_url = target   # already canonical e.g. "https://novalink.lk"
        fingerprint = fingerprinter.fingerprint_target(target_url)
        waf_signals = []
        if isinstance(fingerprint, dict):
            for key in (
                "blocking_status_codes",
                "blocking_headers",
                "request_methods_blocked",
                "path_patterns_blocked",
                "payload_patterns_blocked",
                "ip_rotation_required",
                "user_agent_sensitive",
            ):
                value = fingerprint.get("behaviors", {}).get(key)
                if value:
                    waf_signals.append(key)

        if fingerprint and (fingerprint.get("confidence", 0) > 0.3 or waf_signals):
            results["waf_fingerprint"] = fingerprint
            results["waf_present"] = True
            results["waf_type"] = fingerprint.get("waf_type") or fingerprint.get("detected_patterns", ["unknown"])[0]
            self.add_finding("waf_detected", target, f"Behavioral WAF: {results['waf_type']}", "medium")

            # Persist immediately so later tool calls in the same engagement can
            # adopt WAF-aware evasion without waiting for the phase to finish.
            try:
                self.store.set_phase_data(self.session.engagement_id, "recon", {
                    "waf_present": True,
                    "waf_type": results["waf_type"],
                    "waf_fingerprint": fingerprint,
                    "waf_bypass_url": None,
                })
                self.store.set(f"{self.session.engagement_id}:waf_fingerprint", json.dumps(fingerprint))
            except Exception as _persist_waf_err:
                self.log.debug(f"Immediate WAF persistence failed (non-fatal): {_persist_waf_err}")
            
            # ── V6: PROACTIVE WAF BYPASS ──
            info("WAF detected. Triggering proactive Bypass Orchestrator...")
            bypass_res = self._waf_orchestrator.execute_bypass(self.session.engagement_id, target)
            if bypass_res and bypass_res.get("success"):
                bypass_url = bypass_res.get("bypass_url")
                if bypass_url:
                    info(f"Proactive WAF Bypass SUCCESS: Origin discovered at {bypass_url}")
                    self.add_finding("waf_bypass", target, f"Bypass found via {bypass_res.get('strategy')}. Origin: {bypass_url}", "high")
                    results["waf_bypass_url"] = bypass_url
                elif bypass_res.get("is_evasion_only"):
                    info(f"Proactive WAF Evasion ACTIVE: Using {bypass_res.get('strategy')} mutation tactics.")
                    self.add_finding("waf_evasion", target, f"Evasion tactics activated via {bypass_res.get('strategy')}", "low")
                
                # Persist bypass data
                try:
                    p_data = {
                        "waf_present": True,
                        "waf_type": results["waf_type"],
                        "waf_fingerprint": fingerprint,
                        "waf_bypass_url": bypass_url,
                        "waf_bypass_strategy": bypass_res.get("strategy"),
                    }
                    if bypass_res.get("is_evasion_only"):
                        p_data["waf_evasion_headers"] = bypass_res.get("details", {}).get("headers")
                    
                    self.store.set_phase_data(self.session.engagement_id, "recon", p_data)
                except Exception as _persist_bypass_err:
                    self.log.debug(f"Immediate bypass persistence failed (non-fatal): {_persist_bypass_err}")
            else:
                info("Proactive WAF Bypass failed. Evasion tactics will be used.")
        
        r_base = self.safe_run_tool("curl", f"curl -sL --max-time 12 {target}", target, silent=True)
        baseline_size = len(r_base.stdout)
        
        # 2. DNS (use bare host - dig/nmap do not accept full URLs)
        for record in ["A", "MX", "NS", "TXT"]:
            self.safe_run_tool("dig", f"dig @{dns_resolver} {record} {host} +short", target)

        # ── AI RECON LOOP ──
        _tool_usage_counts = {}
        while current_loop < max_recon_loops:
            current_loop += 1
            section(f"RECON LOOP {current_loop}/{max_recon_loops}")
            
            findings_summary = "\n".join([f"- {f.get('type')}: {f.get('detail')[:100]}" for f in self._findings[-30:]])
            
            recon_prompt = f"""### CONTEXT
Target: {target}
Bare Hostname: {host}
Baseline Size: {baseline_size}
WAF: {fingerprint.get('waf_type') if fingerprint else 'None detected'}

### CURRENT FINDINGS
{findings_summary}

### MISSION
You are the GHOSTWIRE V6 Recon Orchestrator. Decide the NEXT 3-5 Linux shell commands to maximize discovery.
Avoid repeats. Prefer: nmap, masscan, subfinder, gobuster, nikto, nuclei, whatweb, sslscan, ffuf.
DO NOT perform UDP scans (e.g. nmap -sU) as they are too slow and will timeout.

### PREVIOUSLY EXECUTED COMMANDS
{chr(10).join(executed_commands) if executed_commands else "None"}

### RULES
- Return ONLY a JSON array of objects: [{{"command": "...", "reason": "...", "timeout": <integer_seconds>}}]
- CRITICAL - Set a realistic timeout for each tool. Quick probes (curl/dig) = 60s. Heavy scanners (nmap/gobuster/nuclei/ffuf) = 900s. Do NOT hardcode 200s for heavy scanners.
- CRITICAL - Target format by tool type:
  * HTTP tools (nikto, gobuster, ffuf, nuclei, whatweb, curl): use full URL -> {target}
  * Raw-socket / SSL tools (nmap, masscan, sslscan, dig, subfinder): use bare hostname -> {host}
  * sslscan MUST receive bare hostname ONLY, e.g. `sslscan {host}` - never `sslscan https://...`
- CRITICAL - DO NOT repeat any previously executed commands or run the same tool blindly. If previous commands yielded nothing, change your strategy or return an empty array [].
- If you have enough info for exploitation, return an empty array [].
- CRITICAL - For directory/file fuzzing (gobuster, ffuf, dirb), you MUST use `{{WORDLIST}}` as a literal placeholder for the wordlist argument. NEVER hardcode `/usr/share/wordlists/...` or any other path. I will inject the correct AI-led wordlist path.

### BANNED TOOLS
{chr(10).join([f"- {tool}" for tool in _tool_usage_counts if _tool_usage_counts[tool] >= 2]) or "None"}
CRITICAL: DO NOT prescribe any tool from the BANNED TOOLS list. You have exhausted them.
"""
            ai_resp = self.think(recon_prompt)
            prescriptions = extract_json_list(ai_resp)
            
            if not prescriptions:
                info("AI indicates recon is sufficient or no next steps identified.")
                break
                
            for p in prescriptions:
                if not isinstance(p, dict): continue
                cmd = p.get("command")
                if not cmd or cmd in executed_commands: continue
                
                info(f"AI Prescription: {p.get('reason', 'Strategic Discovery')}")
                
                # AI-Led Wordlist Injection (consistent with ExploitationAgent)
                if ("gobuster" in cmd or "ffuf" in cmd) and ("{WORDLIST}" in cmd):
                    wl = self._provision_target_wordlist()
                    if wl:
                        cmd = cmd.replace("{WORDLIST}", shlex.quote(wl))
                    else:
                        cmd = cmd.replace("{WORDLIST}", f"{config_paths.VPS_TEMP_DIR}/ai_wordlist.txt")
                
                # ── Scheme sanitizer: raw-socket tools must never receive https:// ──
                # Even with the prompt fix the AI occasionally generates
                # `sslscan https://host` or `nmap -sV https://host`.
                # Strip the scheme here as a safety net before execution.
                _RAW_TOOLS = ("sslscan", "nmap", "masscan", "dig", "subfinder", "nikto")
                primary_tmp = self._extract_primary_tool(cmd) or ""
                if primary_tmp in _RAW_TOOLS:
                    import re as _re2
                    schemeless_target = _re2.sub(r'^https?://', '', target)
                    cmd = cmd.replace(f" {target}", f" {schemeless_target}")
                
                # Phase 3 Fix: Extract primary tool from command instead of using phantom "ai_recon"
                primary = self._extract_primary_tool(cmd)
                if not primary:
                    self.log.debug(f"Could not extract tool from AI recon prescription: {cmd[:80]}...")
                    continue
                
                r_tool = self.safe_run_tool(primary, cmd, target, timeout=p.get("timeout", 600))
                executed_commands.add(cmd)
                _tool_usage_counts[primary] = _tool_usage_counts.get(primary, 0) + 1
                
                # Parse and add findings
                if primary:
                    try:
                        p_data = self.tools.parser.parse(primary, r_tool.stdout, r_tool.stderr)
                        self._emit_ai_recon_findings(primary, target, p_data)
                    except Exception as e:
                        self.log.error(f"CRITICAL: Failed to emit recon findings from {primary}: {e}", exc_info=True)
                        raise

        # ── FINAL RECON SUMMARY ──
        # Summarize everything learned for the exploitation phase
        info("Finalizing recon findings...")
        
        final_summary_prompt = f"""### MISSION
Analyze all findings from the iterative recon loop for target: {target}.
Provide a concise tactical summary of the attack surface and identified vectors.

### FINDINGS
{chr(10).join([f"- {f.get('type')}: {f.get('detail')[:150]}" for f in self._findings])}

### OUTPUT
Return a single paragraph summarizing the tech stack, entry points, and exploitation readiness.
"""
        ai_summary = self.think(final_summary_prompt)
        
        # Cleanup: Extract core metrics for the bundle
        open_ports = []
        services = {}
        base_paths = {"/"}
        for f in self._findings:
            if f.get("type") == "open_port":
                p_match = re.search(r'Port (\d+)', f.get("detail", ""))
                if p_match:
                    p_num = int(p_match.group(1))
                    open_ports.append(p_num)
                    svc_match = re.search(r'Port \d+/\w+: ([\w-]+)', f.get("detail", ""))
                    if svc_match:
                        services[str(p_num)] = {"service": svc_match.group(1), "protocol": "tcp"}
            elif f.get("type") == "app_root":
                base_paths.add(f.get("detail", "/"))

        is_behind = any(f.get("type") == "waf_detected" for f in self._findings)
        waf_info = next((f.get("detail") for f in self._findings if f.get("type") == "waf_detected"), "None detected")
        root_ip = next((re.search(r'IP: ([\d.]+)', f.get("detail", "")).group(1) 
                       for f in self._findings if f.get("type") == "subdomain" and f.get("target") == target 
                       and re.search(r'IP: ([\d.]+)', f.get("detail", ""))), None)

        bundle = {
            "open_ports": sorted(list(set(open_ports))),
            "services": services,
            "base_paths": sorted(list(base_paths)),
            "ai_analysis": ai_summary,
            "waf_present": is_behind,
            "waf_type": waf_info,
            "waf_fingerprint": fingerprint or {},
            "waf_bypass_url": results.get("waf_bypass_url"),
            "is_cdn": is_behind,
            "baseline_size": baseline_size,
            "resolved_ip": root_ip,
        }

        # ===== AI REASONING LAYER: Structure raw findings and create tactical context =====
        # This is the key layer that transforms messy raw output into structured tactical guidance
        try:
            info("Processing recon findings through AI reasoning layer...")
            
            # Reasoning components are now available via self (BaseAgent)
            
            # Collect all tool outputs for structured analysis
            all_tool_outputs = []
            for finding in self._findings:
                # Each finding came from a tool; reconstruct it for analysis
                all_tool_outputs.append({
                    "tool": finding.get("source_tool", "unknown"),
                    "target": target,
                    "command": finding.get("command", ""),
                    "stdout": finding.get("detail", "")[:3000]  # First 3K chars
                })
            
            # Structure the findings through AI analysis
            if all_tool_outputs:
                structured_findings = self.analyzer.structure_recon_phase_output(all_tool_outputs)
                info(f"Structured {len(structured_findings.get('all_findings', []))} findings from recon tools")
                
                # Register findings in awareness module
                for finding in structured_findings.get("all_findings", []):
                    self.awareness.register_finding(finding)
                
                # Get AI reasoning about what findings mean tactically
                tactical_reasoning = self.reasoning.reason_about_findings(
                    structured_findings,
                    target,
                    mode=self.session.mode if hasattr(self.session, 'mode') else "pentest"
                )
                
                # Register tactical assumptions
                for tactic in tactical_reasoning.get("exploitation_tactics", []):
                    assumption_id = self.awareness.register_assumption(
                        f"Try {tactic.get('tactic')} on {tactic.get('target')}",
                        confidence=tactic.get("probability_of_success", 0.5)
                    )
                    info(f"[REASONING] {tactic.get('tactic')}: {tactic.get('reasoning', '')[:100]}")
                
                # Register knowledge gaps - guard against string entries from fallback reasoning
                for gap in tactical_reasoning.get("knowledge_gaps", []):
                    if isinstance(gap, dict):
                        self.awareness.register_knowledge_gap(gap)
                    elif isinstance(gap, str) and gap:
                        self.awareness.register_knowledge_gap({"gap": gap, "why_it_matters": "unknown", "how_to_find_out": "manual"})
                
                # Add reasoning to bundle for exploitation phase
                bundle["structured_findings"] = structured_findings
                bundle["tactical_reasoning"] = tactical_reasoning
                bundle["system_awareness"] = self.awareness.get_current_knowledge_state()
                
                success(f"AI reasoning complete. System confidence: {bundle['system_awareness'].get('overall_confidence', 'unknown')}")
        except Exception as reasoning_err:
            self.log.warning(f"AI reasoning layer failed (non-fatal): {reasoning_err}")
            # Continue without reasoning layer

        self.store.set_phase_data(self.session.engagement_id, "recon", bundle)
        if fingerprint:
            try:
                self.store.set(f"{self.session.engagement_id}:waf_fingerprint", json.dumps(fingerprint))
            except Exception:
                pass
        # Verify persistence immediately to avoid downstream preflight skips.
        persisted = self.store.get_phase_data(self.session.engagement_id, "recon")
        if not persisted:
            self.log.warning("Recon phase_data write verification failed; retrying persist.")
            self.store.set_phase_data(self.session.engagement_id, "recon", bundle)

        # ── EVIDENCE GRAPH ─────────────────────────────────────────────────
        # Formalise recon output into a structured graph so ExploitationAgent
        # can query facts deterministically instead of guessing from freetext.
        try:
            graph_nodes = []
            services = bundle.get("services", {}) if isinstance(bundle, dict) else {}
            for port, svc in services.items():
                graph_nodes.append({
                    "node_type": "open_port",
                    "node_key": str(port),
                    "attributes": {
                        "service": svc.get("service", "unknown"),
                        "protocol": svc.get("protocol", "tcp"),
                        "version": svc.get("version", ""),
                        "is_web": svc.get("service", "").lower() in (
                            "http", "https", "http-proxy", "ssl/http"
                        ),
                    },
                })
            for port in open_ports:
                if str(port) not in {n["node_key"] for n in graph_nodes}:
                    graph_nodes.append({
                        "node_type": "open_port",
                        "node_key": str(port),
                        "attributes": {"service": "unknown", "protocol": "tcp"},
                    })
            if is_behind:
                graph_nodes.append({
                    "node_type": "waf",
                    "node_key": str(waf_info),
                    "attributes": {"confidence": 1.0},
                })
            elif results.get("waf_fingerprint"):
                fp = results["waf_fingerprint"]
                graph_nodes.append({
                    "node_type": "waf",
                    "node_key": str(fp.get("waf_type", "behavioral_waf")),
                    "attributes": {"confidence": fp.get("confidence", 0.5)},
                })
            if root_ip:
                graph_nodes.append({
                    "node_type": "resolved_ip",
                    "node_key": root_ip,
                    "attributes": {"is_cdn": bundle.get("is_cdn", False)},
                })
            if graph_nodes:
                self.store.store_evidence_graph(self.session.engagement_id, graph_nodes)
                info(f"Evidence graph written: {len(graph_nodes)} nodes.")
        except Exception as _eg_err:
            self.log.warning(f"Evidence graph write failed (non-fatal): {_eg_err}")

        # ===== STEALTH: IP ROTATION (only if Tor is configured) =====
        if self._ip_rotator is not None:
            try:
                self.rotate_tor_ip()
            except Exception as _tor_err:
                self.log.warning(f"Post-recon Tor rotation failed (non-fatal): {_tor_err}")

        # Publish event so other agents know recon is done
        self.bus.publish("recon", "exploitation", {
            "event": "recon_complete",
            **bundle
        })

        return self.finish_phase(bundle)
