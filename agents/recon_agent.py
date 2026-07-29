import json
import re
import shlex
import time
from agents.base_agent import BaseAgent
from utils.display import section, info, success, warning
from core.target_context import TargetContext
from intelligence.waf_fingerprinter import WafFingerprinter
from core.robust_parser import extract_json_list
from core.tripwire_detector import TripwireDetector
from core.target_graph import TargetGraph, resolve_scope_entry, quick_resolve_ip


class ReconAgent(BaseAgent):
    def _preflight(self) -> tuple[bool, str]:
        """Verify tool availability dynamically without strict hardcoding."""
        self.log.info("Performing autonomous pre-flight dependency checks...")
        basic_candidates = ["curl", "wget", "nmap", "nc", "python3"]
        available_tools = [t for t in basic_candidates if self.tools.ensure_installed(t)]
        if not available_tools:
            return False, "No usable network exploration tools found on host environment."
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

    def _emit_ai_recon_findings(
            self, tool_name: str, target: str, parsed: dict) -> int:
        if not isinstance(parsed, dict):
            return 0

        # Temporarily override self.add_finding to inject the correct
        # source_tool, then ALWAYS restore it via try/finally. The restore used
        # to be the method's last sequential line, so ANY exception (or early
        # return) in the ~280-line body skipped it, leaving the instance's
        # add_finding PERMANENTLY monkey-patched — every later finding then got
        # mis-attributed to the failed tool, and re-entry nested the wrappers.
        # Capture the REAL bound class method (never a possibly-leaked prior
        # wrapper) so the restore can't re-install a stale override.
        original_add_finding = type(self).add_finding.__get__(self, type(self))

        def custom_add_finding(finding_type: str, target: str, detail: str,
                               severity: str = "info", source_tool: str = None, command: str = None):
            return original_add_finding(
                finding_type, target, detail, severity, source_tool=source_tool or tool_name, command=command)
        self.add_finding = custom_add_finding
        try:
            return self._emit_recon_findings_body(tool_name, target, parsed)
        finally:
            self.add_finding = original_add_finding

    def _emit_recon_findings_body(
            self, tool_name: str, target: str, parsed: dict) -> int:
        added = 0
        tool = (tool_name or "").lower()

        if tool in {"nmap", "masscan"}:
            raw_ports = []
            services = parsed.get("services", {}) if tool == "nmap" else {}
            if services:
                raw_ports = [int(p)
                             for p in services.keys() if str(p).isdigit()]
            else:
                raw_ports = [
                    int(p) for p in parsed.get(
                        "open_ports",
                        []) if str(p).isdigit()]

            # Tripwire/Honeypot detection & active defense bypass gate.
            #
            # CRITICAL: an "everything is open" result (e.g. 500+/65535 ports)
            # is FAR more often a scan artifact than a real honeypot —
            # connect-scanning (nmap -sT) through a SOCKS/Tor proxy makes every
            # port report "open" because the proxy accepts every CONNECT, and
            # tarpits do the same. Asserting "honeypot confirmed" from the port
            # COUNT alone (and then banning all scanning at confidence 1.0)
            # poisoned entire engagements. So: high density is only a
            # *suspicion*; we require banner-similarity CORROBORATION before we
            # ever claim an active-defense system. Uncorroborated high density
            # is treated as an unreliable scan we simply prune.
            detector = TripwireDetector(remote_executor=self._ssh)
            clean_host = re.sub(
                r"^https?://", "", target).split("/")[0].split(":")[0]
            density_suspicious = detector.is_honeypot_active(raw_ports)
            banner_corroborated = False
            if len(raw_ports) >= 5:
                try:
                    banner_corroborated = detector.check_banner_similarity(
                        clean_host, raw_ports)
                except Exception as _bs_err:
                    self.log.debug(
                        f"banner-similarity check failed: {_bs_err}")

            # Real active defense = corroborated by identical banners across
            # ports. (Either path that corroborates counts.)
            confirmed_honeypot = banner_corroborated
            # Unreliable scan = many "open" ports but banners do NOT corroborate
            # → almost certainly a proxy/tarpit artifact, not real services.
            unreliable_scan = density_suspicious and not banner_corroborated

            if confirmed_honeypot:
                self.add_finding(
                    "tripwire_detected",
                    target,
                    "Active defense portspoof / honeypot system confirmed on target host "
                    "(corroborated by near-identical banners across ports). Engaging web-only stealth bypass.",
                    "high")
                pruned_ports = detector.prune_honeypot_ports(
                    clean_host, raw_ports)
                if services:
                    services = {
                        str(p): svc for p,
                        svc in services.items() if int(p) in pruned_ports}
                # ALWAYS prune open_ports too (not just in the else). The emission
                # below falls back to parsed["open_ports"] whenever `services` is
                # empty — and the services-filter can EMPTY it — so leaving
                # open_ports unpruned re-emitted all the spoofed ports as findings.
                parsed["open_ports"] = pruned_ports
                if hasattr(self, "awareness") and self.awareness:
                    self.awareness.register_assumption(
                        "Host appears protected by Portspoof/honeypots; prefer web-layer probing.",
                        confidence=0.8)
            elif unreliable_scan:
                # Do NOT claim a honeypot and do NOT ban scanning. Just discard
                # the implausible port list, keeping only verified-live web
                # ports so downstream phases work from real data.
                self.log.warning(
                    f"[RECON] {len(raw_ports)} ports reported open on {clean_host} but banners "
                    f"do not corroborate a honeypot — treating as an UNRELIABLE scan "
                    f"(likely SOCKS/Tor connect-scan or tarpit). Pruning to verified live ports.")
                pruned_ports = detector.prune_honeypot_ports(
                    clean_host, raw_ports)
                if services:
                    services = {
                        str(p): svc for p,
                        svc in services.items() if int(p) in pruned_ports}
                # ALWAYS prune open_ports too (see confirmed_honeypot branch): the
                # emission below uses parsed["open_ports"] whenever `services` is
                # empty, so an unpruned list re-emits every spoofed Tor port as a
                # MEDIUM open_port finding (pollutes findings + sends exploitation
                # chasing dead services).
                parsed["open_ports"] = pruned_ports
                self.add_finding(
                    "unreliable_port_scan",
                    target,
                    f"Port scan returned an implausible number of open ports ({len(raw_ports)}); "
                    f"output discarded as a proxy/tarpit artifact. Verified live web ports: {pruned_ports}.",
                    "info")

            if services:
                for port, svc in list(services.items())[:30]:
                    proto = svc.get("protocol", "tcp")
                    service = svc.get("service", "?")
                    version = svc.get("version", "")
                    detail = f"Port {port}/{proto}: {service} {version}".strip()
                    sev = "medium"
                    try:
                        sev = "info" if int(port) in (80, 443) else "medium"
                    except Exception as _e:
                        import logging
                        logging.getLogger(__name__).debug(
                            f'Swallowed exception in recon_agent.py: {_e}')
                    self.add_finding("open_port", target, detail, sev)
                    added += 1
            else:
                ports_list = parsed.get("open_ports", [])[:30]
                for port in ports_list:
                    sev = "medium"
                    try:
                        sev = "info" if int(port) in (80, 443) else "medium"
                    except Exception as _e:
                        import logging
                        logging.getLogger(__name__).debug(
                            f'Swallowed exception in recon_agent.py: {_e}')
                    self.add_finding(
                        "open_port", target, f"Port {port}/tcp discovered", sev)
                    added += 1

        elif tool == "sslscan":
            findings = parsed.get(
                "findings",
                []) if isinstance(
                parsed.get("findings"),
                list) else []
            for finding in findings[:20]:
                lower = finding.lower()
                sev = "high" if any(
                    k in lower for k in (
                        "weak protocol",
                        "expired",
                        "self-signed",
                        "not trusted")) else "medium"
                self.add_finding("ssl_observation", target, finding, sev)
                added += 1

            protocols = parsed.get(
                "protocols",
                {}) if isinstance(
                parsed.get("protocols"),
                dict) else {}
            if protocols and not findings:
                enabled = [
                    k for k, v in protocols.items() if str(v).lower() == "enabled"]
                if enabled:
                    self.add_finding(
                        "ssl_observation", target, f"Enabled protocols: {
                            ', '.join(enabled)}", "info")
                    added += 1

        elif tool == "whatweb":
            tech = parsed.get(
                "technologies",
                {}) if isinstance(
                parsed.get("technologies"),
                dict) else {}
            for key, value in list(tech.items())[:15]:
                self.add_finding(
                    "tech_stack", target, f"{key}: {value}", "info")
                added += 1
            for finding in parsed.get("findings", [])[:10]:
                self.add_finding("web_fingerprint", target, finding, "info")
                added += 1

        elif tool in {"gobuster", "ffuf", "feroxbuster"}:
            for finding in parsed.get("findings", [])[:30]:
                self.add_finding(
                    "discovered_endpoint", target, finding, "info")
                added += 1
                # If a directory is found, consider it a potential app root
                # (base path)
                if finding.endswith(
                        "/") or "Status: 301" in finding or "Dir" in finding:
                    path = finding.split()[0].split("?")[0]
                    if not path.startswith("/"):
                        path = "/" + path
                    if not path.endswith("/"):
                        path += "/"
                    self.add_finding("app_root", target, path, "info")

        elif tool == "subfinder":
            # V7 FIX: Dynamic AI-driven classification to remove hardcoded
            # keyword lists
            subdomains = parsed.get("subdomains", [])

            # Subdomain classification removed to save tokens and prevent
            # severity bloating

            for domain in subdomains:
                # Force info severity for all subdomains to prevent fake High
                # severity vulnerabilities in the final report
                self.add_finding("subdomain", target, domain, "info")
                added += 1

        elif tool in {"httpx", "curl"}:
            raw_lines = parsed.get("raw_lines", [])
            for line in raw_lines[:20]:
                line = line.strip()
                if not line:
                    continue
                if "HTTP/" in line or "200 OK" in line or line.startswith(
                        "http"):
                    self.add_finding("web_server_live",
                                     target, line[:100], "info")
                    added += 1

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
            except Exception as e:
                import logging as __logging_tmp
                __logging_tmp.getLogger(__name__).debug(
                    f"Silenced exception: {e}")
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
                self.add_finding(
                    "web_vulnerability_hint", target, finding, "info")
                added += 1

        elif tool == "nuclei":
            for vuln in parsed.get("findings", [])[:30]:
                template_id = vuln.get("template_id") or "unknown-template"
                name = vuln.get("name") or "Unnamed finding"
                sev = str(vuln.get("severity", "info")).lower()
                self.add_finding("vulnerability_hint", target,
                                 f"{template_id}: {name}", sev)
                added += 1

        elif tool == "wafw00f":
            if parsed.get("is_behind_waf"):
                waf_name = parsed.get("waf_name") or "WAF"
                self.add_finding(
                    "waf_detected",
                    target,
                    f"AI recon confirmed {waf_name}",
                    "medium")
                added += 1

        elif parsed.get("discovered_urls") or parsed.get("parameters"):
            # Crawler / parameter-discovery tools with no dedicated parser
            # (katana, gau, hakrawler, waybackurls, arjun, paramspider, …):
            # ingest their URLs and parameters into the attack surface.
            for u in (parsed.get("discovered_urls") or [])[:60]:
                self.add_finding("discovered_endpoint", target, str(u)[:200], "info")
                added += 1
            for p in (parsed.get("parameters") or [])[:40]:
                self.add_finding("discovered_param", target,
                                 f"Parameter: {p}", "info")
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
                self.add_finding("encrypted_data" if name == "hash" else name, target,
                                 f"Sensitive {name} found: {match_str[:50]}...", "critical")
                added += 1

        return added

    def _parse_ai_response(self, response: str) -> list | dict | None:
        return extract_json_list(response)

    # ═══════════════════════════════════════════════════════════════════════
    #  MULTI-TARGET HELPERS
    # ═══════════════════════════════════════════════════════════════════════

    def _build_scope_target_list(self) -> list[str]:
        """
        Build a deduplicated list of canonical host strings from session.scope.
        CIDR ranges are kept as-is (nmap/masscan handle them).
        Returns primary target first, then additional scope targets.
        """
        seen: set[str] = set()
        result: list[str] = []

        # Primary always goes first
        try:
            primary_host = TargetContext.from_input(self.session.target).host
        except Exception as e:
            import logging as __logging_tmp
            __logging_tmp.getLogger(__name__).debug(f"Silenced exception: {e}")
            primary_host = self.session.target

        for raw_entry in (self.session.scope or [self.session.target]):
            hosts = resolve_scope_entry(raw_entry)
            for h in hosts:
                if h and h not in seen:
                    seen.add(h)
                    # Insert primary at position 0
                    if h == primary_host:
                        result.insert(0, h)
                    else:
                        result.append(h)

        if not result:
            result = [primary_host]

        return result

    def _scan_cidr_range(self, cidr: str) -> dict:
        """
        Run a fast nmap ping-sweep + top-100 port scan over a CIDR range.
        Returns a mini bundle with live_hosts and open_ports per host.
        """
        info(f"[CIDR SCOPE] Sweeping range {cidr}...")
        r = self.safe_run_tool(
            "nmap",
            f"nmap -sn -T4 --host-timeout 30s -n {cidr}",
            cidr,
            timeout=300,
        )
        live_hosts = re.findall(r'Nmap scan report for ([\d.]+)', r.stdout)
        live_hosts += re.findall(
            r'Nmap scan report for \S+ \(([\d.]+)\)', r.stdout)
        live_hosts = list(set(live_hosts))
        info(f"[CIDR SCOPE] {len(live_hosts)} live hosts in {cidr}")

        host_ports: dict[str, list[int]] = {}
        for ip in live_hosts[:20]:   # cap to prevent runaway
            r2 = self.safe_run_tool(
                "nmap",
                f"nmap -T4 -F -n --host-timeout 2m {ip}",
                ip,
                timeout=150,
            )
            ports = [
                int(m) for m in re.findall(
                    r'(\d+)/tcp\s+open',
                    r2.stdout)]
            if ports:
                host_ports[ip] = ports

        return {"cidr": cidr, "live_hosts": live_hosts,
                "host_ports": host_ports}

    def _materialize_hosts_file(self, primary_host: str) -> tuple[str | None, int]:
        """Write all currently-known hosts (primary + discovered subdomains) to a
        stable file the tools can read, returning (path, count).

        This is the robustness fix for `httpx -l <file>` / `naabu -l <file>`: the
        AI references an input file, but nothing guaranteed it existed — so the
        tool failed with "no such file" on every repair. Now there is always a
        real, current hosts file to point `-l` at, for any user/environment.
        Hosts are written WITHOUT scheme (one per line) — httpx adds the scheme.
        """
        try:
            import posixpath
            import config_paths
            # Collect hosts: primary + every subdomain-ish finding detail.
            hosts = set()
            ph = re.sub(r"^https?://", "", primary_host or "").split("/")[0]
            if ph:
                hosts.add(ph)
            for f in self._findings:
                ft = (f.get("type", "") or "").lower()
                if "subdomain" in ft or ft in ("live_host", "discovered_host", "new_host"):
                    detail = str(f.get("detail", ""))
                    for m in re.findall(r'([a-zA-Z0-9][a-zA-Z0-9.\-]+\.[a-zA-Z]{2,})', detail):
                        hosts.add(m.lower().rstrip("."))
            hosts = sorted(h for h in hosts if h)
            if not hosts:
                return None, 0

            if self.tools.remote:
                path = posixpath.join(config_paths.WSL_TEMP_DIR, "recon_hosts.txt")
                self.tools.remote.execute(f"mkdir -p {posixpath.dirname(path)}")
                self.tools.remote.execute(f"rm -f {path}")
                chunk_size = 40
                for i in range(0, len(hosts), chunk_size):
                    chunk = "\n".join(hosts[i:i + chunk_size])
                    self.tools.remote.execute(
                        f"echo -n {shlex.quote(chunk + chr(10))} >> {path}")
            else:
                from pathlib import Path as _P
                p = _P(self.session.results_dir) / "raw" / "recon_hosts.txt"
                p.parent.mkdir(parents=True, exist_ok=True)
                p.write_text("\n".join(hosts) + "\n", encoding="utf-8")
                path = str(p)
            return path, len(hosts)
        except Exception as _hf_err:
            self.log.debug(f"hosts-file materialization failed (non-fatal): {_hf_err}")
            return None, 0

    def _analyze_cross_target_relationships(
        self,
        per_target_bundles: dict,
        target_graph: TargetGraph,
    ) -> TargetGraph:
        """
        Populate the TargetGraph with data extracted from each recon bundle,
        then run relationship detection.
        Also scan HTML/JS content on each target for references to other scope targets.
        """
        scope_hosts = list(per_target_bundles.keys())

        for host, bundle in per_target_bundles.items():
            if not isinstance(bundle, dict):
                continue

            # Resolve IP
            ip = bundle.get("resolved_ip") or quick_resolve_ip(host)

            # Extract cert info from findings if available
            cert_cn = None
            cert_sans = []
            nameservers = []
            mx_records = []

            for f in bundle.get("all_findings_snapshot", []):
                detail = f.get("detail", "").lower()
                ftype = f.get("type", "")
                if ftype == "ssl_observation":
                    cn_m = re.search(r'common name[:\s]+([\w.*-]+)', detail)
                    if cn_m:
                        cert_cn = cn_m.group(1)
                    san_m = re.findall(r'dns:(\S+)', detail)
                    cert_sans.extend(san_m)
                elif ftype == "dns_record" or "ns " in detail:
                    ns_m = re.findall(
                        r'([\w.-]+\.(?:com|net|org|io|cloud|info|co))', detail)
                    nameservers.extend(ns_m[:4])
                elif ftype == "dns_record" and "mx" in detail:
                    mx_m = re.findall(
                        r'([\w.-]+\.(?:com|net|org|io|cloud))', detail)
                    mx_records.extend(mx_m[:4])

            target_graph.add_target(
                host=host,
                ip=ip,
                cert_cn=cert_cn,
                cert_sans=cert_sans,
                nameservers=nameservers,
                mx_records=mx_records,
                open_ports=bundle.get("open_ports", []),
                is_primary=(host == TargetContext.from_input(
                    self.session.target).host if self.session.target else False),
            )

            # Credentials found during recon?
            for f in bundle.get("all_findings_snapshot", []):
                if f.get("type") in ("valid_credential", "credential_exposed"):
                    target_graph.add_credential(host, f.get("detail", "")[:80])

        # Detect structural relationships
        target_graph.analyze()

        # Cross-reference HTML content for internal scope references
        for host, bundle in per_target_bundles.items():
            html_content = bundle.get("homepage_html", "")
            if not html_content:
                continue
            for other_host in scope_hosts:
                if other_host == host:
                    continue
                if other_host in html_content:
                    target_graph.add_internal_reference(
                        src_host=host,
                        referenced_host=other_host,
                        context=f"Content on {host} contains reference to {other_host}",
                    )
                    self.add_finding(
                        "cross_target_reference", host,
                        f"Page on {host} references scope target {other_host}",
                        "medium",
                    )

        return target_graph

    # ═══════════════════════════════════════════════════════════════════════
    #  SINGLE-TARGET RECON CORE  (extracted so run() can loop over scope)
    # ═══════════════════════════════════════════════════════════════════════

    def _extract_attack_surface(self, html: str, endpoint_details: list) -> dict:
        """Parse already-collected HTML + discovered endpoints into a concrete
        attack surface: forms (action/method/inputs), parameter names, and
        parameterised endpoints. Pure evidence extraction — no attack logic,
        nothing hardcoded about which params are vulnerable."""
        forms = []
        params = set()
        param_endpoints = set()

        text = html or ""
        # Forms + their inputs
        for fm in re.finditer(r"<form\b[^>]*>(.*?)</form>", text, re.I | re.S):
            block = fm.group(0)
            action_m = re.search(r"action\s*=\s*['\"]?([^'\"\s>]+)", block, re.I)
            method_m = re.search(r"method\s*=\s*['\"]?([a-zA-Z]+)", block, re.I)
            inputs = re.findall(
                r"<(?:input|textarea|select)\b[^>]*\bname\s*=\s*['\"]?([^'\"\s>]+)",
                block, re.I)
            for i in inputs:
                params.add(i)
            forms.append({
                "action": (action_m.group(1) if action_m else "")[:200],
                "method": (method_m.group(1).upper() if method_m else "GET"),
                "inputs": sorted(set(inputs))[:20],
            })
            if len(forms) >= 40:
                break

        # Parameters from query strings in HTML links and discovered endpoints
        for blob in [text] + list(endpoint_details or []):
            for q in re.finditer(r"[?&]([a-zA-Z0-9_\-\[\]]{1,40})=", blob or ""):
                params.add(q.group(1))
            for url in re.finditer(r"(?:href|src|action)\s*=\s*['\"]?([^'\"\s>]*\?[^'\"\s>]+)", blob or "", re.I):
                param_endpoints.add(url.group(1)[:200])
        for ep in (endpoint_details or []):
            tok = ep.split()[0] if ep.split() else ep
            if "?" in tok:
                param_endpoints.add(tok[:200])

        # Drop noisy/static params
        noise = {"v", "ver", "cache", "_", "ts", "t", "utm_source", "utm_medium",
                 "utm_campaign", "fbclid", "gclid"}
        clean_params = sorted({p for p in params if p.lower() not in noise})

        return {
            "forms": forms[:40],
            "parameters": clean_params[:60],
            "param_endpoints": sorted(param_endpoints)[:40],
        }

    def _run_recon_for_target(self, raw_target: str) -> dict:
        """
        Execute the full recon pipeline for a single target.
        Returns the recon bundle dict for that target.
        """
        # ── TARGET NORMALIZATION ──────────────────────────────────────────
        # V6 FIX: NEVER use scope._normalize_target() here - it strips the scheme
        # returning a bare host. Downstream safe_run_tool then re-prefixes with http://,
        # causing str.replace("novalink.lk", "http://novalink.lk") to corrupt any
        # command already containing https://novalink.lk/ ->
        # "https://http://novalink.lk/".
        try:
            _tc = TargetContext.from_input(raw_target)
            # e.g. "https://novalink.lk" (canonical, scheme preserved)
            target = _tc.base_url
            # e.g. "novalink.lk"        (bare hostname for DNS/nmap)
            host = _tc.host
        except Exception as e:
            import logging as __logging_tmp
            __logging_tmp.getLogger(__name__).debug(f"Silenced exception: {e}")
            # Fallback: TargetContext has no normalize_url(); derive forms directly.
            target = raw_target
            host = re.sub(
                r"^https?://",
                "",
                target).split("/")[0].split(":")[0]
        results = {}

        section(f"RECON — Target: {host}")
        info(f"[MULTI-SCOPE] Running recon pipeline for: {host}")

        try:
            rules = self._load_rules("recon")
        except Exception as e:
            import logging as __logging_tmp
            __logging_tmp.getLogger(__name__).debug(f"Silenced exception: {e}")
            rules = {}

        infra = self._get_infra_rules()
        dns_resolver = infra.get("global_dns_resolver", "1.1.1.1")

        # Track executed commands to avoid loops, using dict to preserve
        # insertion order
        executed_commands = {}
        max_recon_loops = rules.get("max_recon_loops", 20)
        current_loop = 0

        # ── INITIAL PROBE ──
        # Always run these fast probes to give AI a starting point
        info("Running initial discovery probe...")

        # 1. WAF & Baseline - target is already a full URL with scheme
        target_url = target   # already canonical e.g. "https://novalink.lk"

        # The behavioral fingerprinter fires ~50 direct HTTP probes (incl.
        # injection-looking ones). Those use a local `requests` session, NOT the
        # WSL/Tor tool path — so when stealth/Tor is active they would leak the
        # real IP. We can't cleanly route a Windows-side session through WSL's
        # Tor, so in stealth mode we SKIP the local probe and let WAF detection
        # come from the proxied tool path (curl/whatweb headers). Evasion is
        # reactive now (W6.7), so nothing is lost by not asserting a WAF upfront.
        _tor_active = (
            getattr(self, "_ip_rotator", None) is not None
            and getattr(self._ip_rotator, "_tor_verified", False))
        if _tor_active:
            info("Stealth/Tor active — skipping local-IP behavioral WAF probe "
                 "(avoids deanonymization); WAF will be detected via proxied tools.")
            fingerprint = {"target": target_url, "behaviors": {},
                           "detected_patterns": [], "confidence": 0.0,
                           "similar_to_known": [], "skipped_for_stealth": True}
        else:
            def _waf_probe_progress(done, total, name):
                info(f"  WAF probe {done}/{total}: {name.replace('_', ' ')}…")
            fingerprinter = WafFingerprinter(
                time_budget=40.0, progress_cb=_waf_probe_progress)
            fingerprint = fingerprinter.fingerprint_target(target_url)
        waf_signals = []
        # V6 Fix: Adopt WAF analysis from planning phase
        try:
            import json
            plan_analysis_json = self.store.get(
                f"{self.session.engagement_id}:waf_bypass_analysis")
            if plan_analysis_json:
                plan_analysis = json.loads(plan_analysis_json)
                self.log.info(
                    "[PLANNING ADOPTION] Adopting WAF analysis from planning phase.")
                if plan_analysis.get("recommended_bypass"):
                    waf_signals.append("planning_recommendation")
                    if not fingerprint or fingerprint.get(
                            "confidence", 0) <= 0.3:
                        fingerprint = {
                            "timestamp": time.time(),
                            "target": target_url,
                            "behaviors": plan_analysis.get("layer_analysis", {}),
                            "detected_patterns": [plan_analysis.get("recommended_bypass")],
                            "confidence": 0.8,
                            "similar_to_known": []
                        }
        except Exception as plan_err:
            self.log.warning(
                f"Error adopting planning WAF analysis: {plan_err}")
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

        if fingerprint and fingerprint.get("confidence", 0) >= 0.5:
            results["waf_fingerprint"] = fingerprint
            results["waf_present"] = True
            results["waf_type"] = fingerprint.get("waf_type") or fingerprint.get(
                "detected_patterns", ["unknown"])[0]
            self.add_finding(
                "waf_detected", target, f"Behavioral WAF: {
                    results['waf_type']}", "medium")

            # Capture baseline WAF response size for gobuster/ffuf exclusion
            waf_resp = self.tools.run(
                "curl",
                f"curl -s -o /dev/null -w \"%{{size_download}}\" {target_url}/nonexistent-path-test-12345",
                "recon",
                silent=True)
            if waf_resp.success:
                try:
                    import re as _re_tmp
                    _m = _re_tmp.search(r'\d+', waf_resp.stdout)
                    if _m:
                        baseline_size = int(_m.group(0))
                        self.store.set("waf_baseline_size", str(baseline_size))
                        self.log.info(
                            f"Captured WAF baseline response size: {baseline_size} bytes")
                except ValueError:
                    pass

            # Persist immediately so later tool calls in the same engagement can
            # adopt WAF-aware evasion without waiting for the phase to finish.
            try:
                self.store.set_phase_data(self.session.engagement_id, "recon", {
                    "waf_present": True,
                    "waf_type": results["waf_type"],
                    "waf_fingerprint": fingerprint,
                    "waf_bypass_url": None,
                })
                self.store.set(
                    f"{self.session.engagement_id}:waf_fingerprint", json.dumps(fingerprint))
            except Exception as _persist_waf_err:
                self.log.debug(
                    f"Immediate WAF persistence failed (non-fatal): {_persist_waf_err}")

            # ── V6: PROACTIVE WAF BYPASS ──
            info("WAF detected. Triggering proactive Bypass Orchestrator...")
            bypass_res = self._waf_orchestrator.execute_bypass(
                self.session.engagement_id, target)
            if bypass_res and bypass_res.get("success"):
                bypass_url = bypass_res.get("bypass_url")
                if bypass_url:
                    info(
                        f"Proactive WAF Bypass SUCCESS: Origin discovered at {bypass_url}")
                    self.add_finding(
                        "waf_bypass", target, f"Bypass found via {
                            bypass_res.get('strategy')}. Origin: {bypass_url}", "high")
                    results["waf_bypass_url"] = bypass_url
                elif bypass_res.get("is_evasion_only"):
                    info(
                        f"Proactive WAF Evasion ACTIVE: Using {
                            bypass_res.get('strategy')} mutation tactics.")
                    self.add_finding(
                        "waf_evasion", target, f"Evasion tactics activated via {
                            bypass_res.get('strategy')}", "low")

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
                        p_data["waf_evasion_headers"] = bypass_res.get(
                            "details", {}).get("headers")

                    self.store.set_phase_data(
                        self.session.engagement_id, "recon", p_data)
                except Exception as _persist_bypass_err:
                    self.log.debug(
                        f"Immediate bypass persistence failed (non-fatal): {_persist_bypass_err}")
            else:
                info("Proactive WAF Bypass failed. Evasion tactics will be used.")

        r_base = self.safe_run_tool(
            "curl",
            f"curl -sL --max-time 12 {target}",
            target,
            silent=True)
        baseline_size = len(r_base.stdout)
        # Persist the baseline RESPONSE BODY (not just its size). The hypothesis
        # engine's differential proof gate measures similarity-to-normal against
        # this; it was being fed `waf_baseline_size` (a number), so similarity
        # was ~0 for every response and the "identical to baseline" rejection
        # could never fire — every claimed differential auto-passed the gate.
        try:
            if (r_base.stdout or "").strip():
                self.store.set("waf_baseline_body", (r_base.stdout or "")[:6000])
        except Exception as _bb_err:
            self.log.debug(f"baseline body persist failed (non-fatal): {_bb_err}")

        # 2. DNS (use bare host - dig/nmap do not accept full URLs)
        for record in ["A", "MX", "NS", "TXT"]:
            self.safe_run_tool(
                "dig", f"dig @{dns_resolver} {record} {host} +short", target)

        # ── AI RECON LOOP ──
        _tool_usage_counts = {}
        min_recon_loops = rules.get("min_recon_loops", 8)
        max_recon_loops = rules.get("max_recon_loops", 20)
        _consecutive_empty_loops = 0   # FIX G
        _prev_finding_count = len(self._findings)

        while current_loop < max_recon_loops:
            current_loop += 1
            section(
                f"RECON LOOP {current_loop} (Min: {min_recon_loops}, Max: {max_recon_loops})")

            import time as _time_module
            if hasattr(self, "_phase_deadline") and self._phase_deadline and _time_module.monotonic(
            ) > self._phase_deadline:
                self.log.warning(
                    f"Phase deadline exceeded. Aborting recon phase early at loop {current_loop}.")
                break

            # W1.2 — token-budget circuit breaker. Stop issuing new AI calls
            # once recon has burned its budget (prevents a repair storm from
            # draining the whole TPD on one phase) but only after the minimum
            # loops so we never bail before doing real work.
            if current_loop > min_recon_loops and self.is_phase_budget_exhausted():
                self.log.warning(
                    f"Recon token budget exhausted at loop {current_loop}. Wrapping up phase.")
                break

            # FIX D: Signal awareness injection on loop 1 and every 5th loop
            # only
            self._awareness_needed = (
                current_loop == 1 or current_loop %
                5 == 0)

            # FIX G: Track consecutive empty loops
            _cur_fc = len(self._findings)
            if _cur_fc <= _prev_finding_count and current_loop > 1:
                _consecutive_empty_loops += 1
            else:
                _consecutive_empty_loops = 0
            _prev_finding_count = _cur_fc

            # Categorize findings for structured AI context
            categorized = {
                "subdomains": [],
                "ports": [],
                "tech_stack": [],
                "vulnerabilities": [],
                "emails": [],
                "paths": [],
                "other": []}
            for f in self._findings:
                ft = f.get('type', '')
                detail = f.get('detail', '')[:120]
                if 'subdomain' in ft or 'dns' in ft:
                    categorized['subdomains'].append(detail)
                elif 'port' in ft or 'service' in ft:
                    categorized['ports'].append(detail)
                elif 'tech' in ft or 'cms' in ft or 'waf' in ft or 'stack' in ft:
                    categorized['tech_stack'].append(detail)
                elif 'vuln' in ft or 'exposure' in ft or 'misconfig' in ft:
                    categorized['vulnerabilities'].append(detail)
                elif 'email' in ft:
                    categorized['emails'].append(detail)
                elif 'path' in ft or 'directory' in ft:
                    categorized['paths'].append(detail)
                else:
                    categorized['other'].append(detail)

            # FIX C: cap items per category at 5 for high-signal, count-only
            # for low-signal
            findings_structured = ""
            for cat, items in categorized.items():
                if items:
                    if cat in ('vulnerabilities', 'paths'):
                        # Full detail for high-signal categories (max 5)
                        findings_structured += f"\n{cat.upper()} ({len(items)}):\n"
                        for item in items[-5:]:
                            findings_structured += f"  - {item}\n"
                    elif cat in ('subdomains', 'ports', 'tech_stack'):
                        # Show last 5 items, summary for older ones
                        findings_structured += f"\n{cat.upper()} ({len(items)}):\n"
                        for item in items[-5:]:
                            findings_structured += f"  - {item}\n"
                        if len(items) > 5:
                            findings_structured += f"  ... and {
                                len(items) - 5} more\n"
                    else:
                        # FIX C: count-only for emails / other noise
                        findings_structured += f"  [{
                            cat.upper()}: {
                            len(items)} items — suppressed]\n"

            # High-value pivoting is the AI's judgment, NOT a hardcoded keyword
            # list. The full findings are already in CURRENT FINDINGS above; the
            # model decides which leads are most valuable for THIS target and
            # chases them first (see the PRIORITISE rule below). The old
            # keyword-scan (api/.env/admin/...) was exactly the hardcoding we
            # don't want, and it only saw the last 15 findings so early
            # high-value finds fell out of the window.
            pivot_instruction = (
                "\n### PRIORITISE\n"
                "From CURRENT FINDINGS, use YOUR OWN judgment to decide which "
                "leads are the highest-value attack surface for THIS specific "
                "target, and investigate those DEEPER first before generic "
                "scanning. Do not wait to be told which are interesting.\n")

            # ── EVIDENCE-GATED stage tracking (not activity-based) ───────────
            # A stage is "complete" ONLY when it produced its EVIDENCE — not just
            # because a tool string was executed. `executed_commands[cmd]=True` is
            # set UNCONDITIONALLY (even when the tool failed or found nothing), so
            # the old `if 'subfinder' in executed_commands` marked DISCOVERY done
            # on a failed subfinder and steered the AI off a stage that actually
            # produced nothing. Three honest buckets so the AI can tell "done"
            # from "tried and got nothing" from "not tried". Also tracks the
            # 6th, highest-value stage (ATTACK-SURFACE) the old tracker omitted.
            _present_types = {(_f.get("type") or "") for _f in self._findings}

            def _have(*types):
                return any(t in _present_types for t in types)

            def _ran(*tools):
                return any(any(t in c for t in tools) for c in executed_commands)

            # (stage, evidence finding-types, tools that attempt it)
            _stage_defs = [
                ("DISCOVERY", ("subdomain",),
                 ("subfinder", "amass", "assetfinder", "dnsenum")),
                ("PROBING", ("web_server_live",),
                 ("httpx", "curl -sI", "curl -si")),
                ("SCANNING", ("open_port",), ("nmap", "masscan", "naabu")),
                ("FINGERPRINTING", ("tech_stack",), ("whatweb", "sslscan")),
                ("FUZZING", ("discovered_endpoint", "discovered_path", "app_root"),
                 ("gobuster", "ffuf", "dirsearch", "dirb", "feroxbuster")),
                ("ATTACK-SURFACE", ("discovered_param", "discovered_form", "parameter"),
                 ("katana", "gau", "hakrawler", "waybackurls", "arjun", "paramspider")),
            ]
            completed_stages = []
            attempted_empty_stages = []
            remaining_stages = []
            for _sname, _ev, _tools in _stage_defs:
                if _have(*_ev):
                    completed_stages.append(_sname)
                elif _ran(*_tools):
                    attempted_empty_stages.append(_sname)
                else:
                    remaining_stages.append(_sname)

            # ── Deterministic subdomain-probe BACKSTOP ───────────────────────
            # PROBING exists to hit the DISCOVERED subdomains, but that depended
            # entirely on the AI choosing to run `httpx -l`. If subdomains were
            # found but never probed, probe them ourselves (ONCE per target) so
            # they can't be silently dropped — the recon twin of "discovered then
            # forgotten". Live ones become web_server_live findings and flip
            # PROBING to genuinely complete for this loop's prompt.
            if not hasattr(self, "_auto_probed_targets"):
                self._auto_probed_targets = set()
            if (target not in self._auto_probed_targets
                    and "DISCOVERY" in completed_stages
                    and "PROBING" not in completed_stages):
                try:
                    _subs = [f.get("detail", "").strip() for f in self._findings
                             if f.get("type") == "subdomain" and f.get("detail")]
                    _subs = list(dict.fromkeys(_subs))[:40]
                    if _subs:
                        self._auto_probed_targets.add(target)
                        info(f"[RECON BACKSTOP] AI hadn't probed discovered "
                             f"subdomains — probing {len(_subs)} for liveness.")
                        _live = self.check_liveness(_subs) or {}
                        _n_live = 0
                        for _d, _st in _live.items():
                            try:
                                _alive = int(_st) > 0
                            except (TypeError, ValueError):
                                _alive = bool(_st)
                            if _alive:
                                _n_live += 1
                                self.add_finding(
                                    "web_server_live", _d,
                                    f"{_d} (HTTP {_st}) — live [backstop probe]",
                                    "info")
                        if _n_live and "PROBING" in remaining_stages:
                            remaining_stages.remove("PROBING")
                            completed_stages.append("PROBING")
                        if _n_live and "PROBING" in attempted_empty_stages:
                            attempted_empty_stages.remove("PROBING")
                            completed_stages.append("PROBING")
                except Exception as _bse:
                    self.log.debug(
                        f"subdomain probe backstop failed (non-fatal): {_bse}")

            env_snapshot = self._get_environment_snapshot()

            # FIX E: Build compressed command history BEFORE the f-string
            _rec_cmds = list(executed_commands)[-10:]
            _rgroups: dict = {}
            for _c in _rec_cmds:
                _tn = _c.split()[0] if _c.split() else _c
                _rgroups.setdefault(_tn, []).append(_c)
            _rcmd_lines = []
            for _tn, _cl in _rgroups.items():
                # Show enough of each command (not just the first 6 words) so the
                # AI recognizes EXACT repeats and stops re-proposing them \u2014 the
                # 6-word truncation made distinct commands look identical, so the
                # AI kept re-prescribing dupes that the dedup then skipped.
                if len(_cl) == 1:
                    _rcmd_lines.append(f"  {_cl[0][:90]}")
                else:
                    _rcmd_lines.append(
                        f"  {_tn} (\u00d7{len(_cl)}): {_cl[-1][:90]}")
            _recon_cmd_hist = "\n".join(
                _rcmd_lines) if _rcmd_lines else "None yet — this is your first move."

            # FIX G: Smart nano throttle BEFORE building the full prompt
            if _consecutive_empty_loops >= 2 and current_loop > min_recon_loops:
                # HARD exhaustion stop: after several no-progress loops past the
                # minimum, STOP — don't grind to max_loops generating garbage.
                # The old pivot only stopped when the AI returned [], but an
                # UNCONSTRAINED nano AI (no tool list / no state injected) always
                # returns SOME command — so recon flailed for many loops firing
                # nonsense like `git log` / `wget --spider` that can't do recon.
                if _consecutive_empty_loops >= 4:
                    info(f"[RECON DONE] {_consecutive_empty_loops} consecutive "
                         f"no-progress loops past minimum — recon exhausted, stopping.")
                    break
                info(
                    f"[TOKEN SAVE] {_consecutive_empty_loops} empty recon loops — nano pivot")
                # Constrain the pivot to REAL recon tools + what's already been
                # tried, so it can't free-associate non-recon garbage. (Same tool
                # set the full prompt advertises — guidance, not a new decision.)
                _tried = ", ".join(sorted({c.split()[0] for c in executed_commands if c.split()}))[:160]
                _nano = (
                    f"Recon on {target} found nothing new in the last "
                    f"{_consecutive_empty_loops} loops. Tools already used: {_tried or 'none'}.\n"
                    "Suggest ONE genuinely unexplored recon command, using ONLY a real "
                    "recon tool (subfinder, httpx, gobuster, ffuf, nuclei, whatweb, "
                    "katana, gau, hakrawler, arjun, nmap, nikto, sslscan, curl, dig) "
                    "against the target or a discovered host. If recon is genuinely "
                    "exhausted, return []. No bash pipes (|), && or ;.\n"
                    'Return JSON: [{"command": "...", "reason": "...", "timeout": 120}]'
                )
                try:
                    _nr = self.think(_nano, mode="nano")
                    _np = extract_json_list(_nr)
                except RuntimeError:
                    _np = []
                if not _np:
                    if current_loop >= min_recon_loops:
                        break
                    continue
                for _cmd_item in _np[:2]:
                    if isinstance(_cmd_item, dict):
                        _nc = _cmd_item.get("command", "")
                        _pt = self._extract_primary_tool(_nc) if _nc else None
                        if _nc and _pt and _nc not in executed_commands:
                            _pv_r = self.safe_run_tool(
                                _pt, _nc, target, timeout=_cmd_item.get(
                                    "timeout", 120))
                            executed_commands[_nc] = True
                            # Parse the pivot's output. The MAIN recon loop parses
                            # every result; this path silently discarded any host/
                            # subdomain/endpoint the pivot discovered — a real
                            # "recon found nothing new" cause right when recon is
                            # already struggling.
                            try:
                                _pv_parsed = self.tools.parser.parse(
                                    _pt, _pv_r.stdout, _pv_r.stderr)
                                self._emit_ai_recon_findings(
                                    _pt, target, _pv_parsed)
                            except Exception as _pve:
                                self.log.debug(
                                    f"recon nano-pivot parse failed for {_pt}: {_pve}")
                continue

            # W1.1 — proxy-awareness note: full-range connect-scans through
            # Tor/SOCKS report every port "open" (proxy accepts every CONNECT).
            _tor_active = (
                hasattr(self, "_ip_rotator")
                and self._ip_rotator is not None
                and getattr(self._ip_rotator, "_tor_verified", False)
            )
            _proxy_ops_note = (
                "\n### OPS NOTE — TOR/SOCKS PROXY ACTIVE\n"
                "All TCP connections route through Tor. Full-range connect-scans "
                "(`nmap -sT -p1-65535` or `nmap -p-`) report EVERY port open because "
                "the proxy accepts every CONNECT — the results are meaningless garbage. "
                "Use `nmap --top-ports 200 -T4` or explicit web ports "
                "(`-p 80,443,8080,8443,8888,3000,4443,9000`) ONLY. "
                "Do NOT run `-p1-65535` or `-p-` under any circumstances.\n"
            ) if _tor_active else ""

            # Materialize the current known hosts to a real file so the AI can
            # point `httpx -l` / `naabu -l` at something that actually exists
            # (prevents the "no such file" failure → futile repair loop).
            _hosts_path, _hosts_n = self._materialize_hosts_file(host)
            _hosts_note = ""
            if _hosts_path and _hosts_n:
                _hosts_note = (
                    f"\n### DISCOVERED HOSTS FILE (ready to use)\n"
                    f"{_hosts_n} known host(s) are written to: {_hosts_path}\n"
                    f"To probe them, use `httpx -l {_hosts_path}` (NOT a made-up filename, "
                    f"and NOT piping). For a single host use `httpx -u <host>`. "
                    f"Do NOT invent input-file paths — only this file is guaranteed to exist.\n")

            recon_prompt = f"""### WSL ENVIRONMENT SNAPSHOT
{env_snapshot}{_proxy_ops_note}{_hosts_note}
### CONTEXT
Target: {target}
Bare Hostname: {host}
Baseline Size: {baseline_size}
WAF: {fingerprint.get('waf_type') if fingerprint else 'None detected'}

### CURRENT FINDINGS
{findings_structured}
{pivot_instruction}
### MISSION & PLAYBOOK
You are the GHOSTWIRE V6 Recon Orchestrator, an intelligent, human-like bug bounty hunter. 
Your goal is to follow a structured, professional recon methodology across multiple loops:
1. DISCOVERY: Find subdomains (`subfinder`, etc.)
2. PROBING: Probe discovered subdomains for live web servers (`httpx -u <subdomain>`, `curl -sI`).
3. SCANNING: Port scan live targets (`nmap`, `masscan`).
4. FINGERPRINTING: Identify tech stacks on live web servers (`whatweb`, `sslscan`).
5. FUZZING: Directory fuzzing on interesting web roots (`ffuf`, `gobuster`).
6. ATTACK-SURFACE MAPPING: Crawl live apps for real endpoints, parameters and forms (`katana`, `gau`, `hakrawler`, `waybackurls`) and discover hidden parameters (`arjun`, `paramspider`). This is the highest-value recon stage: the exploitation brain reasons about parameters/forms/endpoints to find NOVEL bugs, so surface as many concrete injection points as you can.

### PROGRESS STATUS (evidence-based — a stage is DONE only if it produced results)
Completed (produced results): {', '.join(completed_stages) if completed_stages else 'None'}
Tried but FOUND NOTHING (vary the technique/tool, or accept as empty and move on): {', '.join(attempted_empty_stages) if attempted_empty_stages else 'None'}
Not yet attempted: {', '.join(remaining_stages) if remaining_stages else 'None'}
Loop {current_loop}/{max_recon_loops} — {'Explore broadly' if current_loop <= 3 else 'Focus on gaps and high-value leads'}

Decide the NEXT 3-5 Linux shell commands based on the CURRENT FINDINGS and the PLAYBOOK progression. Do NOT blindly skip to fuzzing if you haven't discovered live subdomains yet!
Prefer tools like: nmap, masscan, subfinder, httpx, gobuster, nikto, nuclei, whatweb, sslscan, ffuf, katana, gau, hakrawler, arjun (missing tools auto-install on first use).
DO NOT perform UDP scans (e.g. nmap -sU).

### PREVIOUSLY EXECUTED COMMANDS
{_recon_cmd_hist}

### RULES
- Return ONLY a JSON array of objects: [{{"command": "...", "reason": "...", "timeout": <integer_seconds>}}]
- CRITICAL - Set a realistic timeout for each tool. Quick probes (curl/dig/httpx) = 60s. Heavy scanners = 900s.
- PIVOTING - You MUST feed findings from one step into the next! If subfinder found 5 subdomains, your next command MUST be `httpx` or `curl` to probe them. Think like a hacker.
- CRITICAL - DO NOT use bash pipes (`|`), `&&`, or `;` to chain commands. Execute ONE tool per command. The system parses outputs per-tool, so piping `subfinder | httpx` will break the parser and hang the system. If you want to probe subdomains, first run `subfinder`, read the results, and then run `httpx` on the discovered domains in your NEXT loop.
- CRITICAL - DO NOT repeat any previously executed commands or run the same tool blindly. If previous commands yielded nothing, change your strategy or return an empty array [].
- CRITICAL - Do NOT return an empty array [] unless you have thoroughly exhausted all discovery, probing, scanning, and fingerprinting phases. If you only see INFO findings, keep exploring!
- CRITICAL - Focus on the main target domain ({host}) AND all discovered live subdomains. Do not fixate on one subdomain and ignore others.

{self.get_tool_syntax_guide(phase="recon")}

### BANNED TOOLS
{chr(10).join([f"- {tool}" for tool in _tool_usage_counts if _tool_usage_counts[tool] >= 3]) or "None"}
CRITICAL: DO NOT prescribe any tool from the BANNED TOOLS list. You have exhausted them.
"""
            # FIX B/D: use slim mode for mid-phase loops to inject failures
            # while saving tokens
            _recon_think_mode = "full" if current_loop == 1 else "slim"
            self._skip_awareness_injection = True  # mode param controls this now
            try:
                ai_resp = self.think(recon_prompt, mode=_recon_think_mode)
            except RuntimeError:
                # Backend exhaustion — wait for recovery, don't quit
                recovery_sec = self.ai.get_shortest_recovery_time()
                if recovery_sec and recovery_sec < 300:  # Wait up to 5 min
                    self.log.warning(
                        f"All backends exhausted. Waiting {recovery_sec}s for key recovery...")
                    time.sleep(recovery_sec + 5)
                    continue  # Retry the same loop iteration
                else:
                    self.log.warning(
                        "All backends exhausted. No recovery in sight. Pausing 60s...")
                    time.sleep(60)
                    continue

            prescriptions = extract_json_list(ai_resp)

            # ── PASS 2: proactive grounding ──
            # The think() above is pass 1 (drafts from memory). Before we fire
            # anything, rewrite each command against the tool's REAL --help so
            # we generate correct syntax up front instead of failing into the
            # retry/repair loop (the old 75-min recon bottleneck).
            if prescriptions:
                prescriptions = self._ground_prescriptions(
                    prescriptions, phase="recon")

            if not prescriptions:
                if current_loop < min_recon_loops:
                    self.log.warning(
                        f"AI returned empty prescriptions early in recon! Raw resp: {ai_resp[:200]}")
                    self.log.warning(
                        f"Min loops ({min_recon_loops}) not reached. Forcing continuation.")
                    _consecutive_empty_loops = max(_consecutive_empty_loops, 2)
                    continue
                else:
                    info(
                        f"AI indicates recon is sufficient or no next steps identified after {current_loop} loops.")
                    break
            commands_executed_this_loop = 0
            for p in prescriptions:
                if not isinstance(p, dict):
                    continue
                cmd = p.get("command")
                if not cmd:
                    continue
                if cmd in executed_commands:
                    self.log.warning(
                        f"AI prescribed a duplicate command. Skipping: {cmd[:80]}")
                    continue

                info(
                    f"AI Prescription: {
                        p.get(
                            'reason',
                            'Strategic Discovery')}")

                # AI-Led Wordlist Injection (consistent with ExploitationAgent)
                if ("gobuster" in cmd or "ffuf" in cmd) and (
                        "{WORDLIST}" in cmd):
                    wl = self._provision_target_wordlist()
                    if wl:
                        cmd = cmd.replace("{WORDLIST}", shlex.quote(wl))
                    else:
                        # Use the canonical, env-consistent wordlist path (not a
                        # hardcoded host-specific one). This matches the path the
                        # provisioner and env-snapshot advertise, so the file the
                        # AI is told about is the file that actually gets written.
                        import config_paths as _cp
                        cmd = cmd.replace(
                            "{WORDLIST}",
                            f"{_cp.WSL_TEMP_DIR}/ai_wordlist.txt")

                # NOTE: missing input-file repair (the AI referencing a host
                # list file that was never written, e.g. the hallucinated
                # `live_subdomains.txt`) is now handled UNIVERSALLY for every
                # tool by ToolManager._validate_and_fix_command /
                # _canonical_substitute at execution time — no per-tool redirect
                # needed here. The prompt note above still proactively hands the
                # AI the real hosts-file path so it is less likely to invent one.

                # ── Auto-inject WAF Baseline Exclusions ──
                baseline_str = self.store.get("waf_baseline_size")
                if results.get("waf_present") and baseline_str and str(
                        baseline_str).strip():
                    if "gobuster " in cmd and "--exclude-length" not in cmd:
                        cmd += f" --exclude-length {baseline_str}"
                        # gobuster -b (status blacklist) DEFAULTS to "404"; adding
                        # "-b 403" alone REPLACES it so every 404 path is reported
                        # as a finding (noise). Keep 404 AND add the WAF's 403.
                        if "-b " not in cmd and "-b=" not in cmd:
                            cmd += " -b 404,403"
                    elif "ffuf " in cmd and "-fs" not in cmd:
                        cmd += f" -fs {baseline_str.strip()}"

                # ── Scheme sanitizer: raw-socket tools must never receive https:// ──
                # Even with the prompt fix the AI occasionally generates
                # `sslscan https://host` or `nmap -sV https://host`.
                # Strip the scheme here as a safety net before execution.
                _RAW_TOOLS = (
                    "sslscan",
                    "nmap",
                    "masscan",
                    "dig",
                    "subfinder",
                    "nikto")
                primary_tmp = self._extract_primary_tool(cmd) or ""
                if primary_tmp in _RAW_TOOLS:
                    import re as _re2
                    schemeless_target = _re2.sub(r'^https?://', '', target)
                    cmd = _re2.sub(
                        r'https?://' +
                        _re2.escape(schemeless_target),
                        schemeless_target,
                        cmd)

                # Phase 3 Fix: Extract primary tool from command instead of
                # using phantom "ai_recon"
                primary = self._extract_primary_tool(cmd)
                if not primary:
                    self.log.debug(
                        f"Could not extract tool from AI recon prescription: {cmd[:80]}...")
                    continue

                r_tool = self.safe_run_tool(
                    primary, cmd, target, timeout=p.get(
                        "timeout", 600))
                # Store the RAW prescription too, not just the post-mutation cmd:
                # the {WORDLIST}/WAF-exclusion/scheme rewrites above transform cmd,
                # so storing only the mutated form let the planner re-prescribe the
                # identical raw command every loop and re-run it (same defect fixed
                # in ExploitationAgent). The dedup check at the loop top uses raw.
                executed_commands[cmd] = True
                executed_commands[p.get("command")] = True
                commands_executed_this_loop += 1
                _tool_usage_counts[primary] = _tool_usage_counts.get(
                    primary, 0) + 1

                # Parse and add findings
                if primary:
                    try:
                        p_data = self.tools.parser.parse(
                            primary, r_tool.stdout, r_tool.stderr)
                        self._emit_ai_recon_findings(primary, target, p_data)
                    except Exception as e:
                        self.log.error(
                            f"CRITICAL: Failed to emit recon findings from {primary}: {e}",
                            exc_info=True)
                        raise

            if commands_executed_this_loop == 0:
                self.log.warning(
                    f"No new commands were successfully prescribed in loop {current_loop}. Breaking recon early to prevent hang.")
                break

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
        ai_summary = self.think(
            final_summary_prompt,
            mode="nano")  # FIX B: summary needs no env context

        # Cleanup: Extract core metrics for the bundle
        open_ports = []
        masscan_ports = []
        services = {}
        base_paths = {"/"}
        # Extract subdomains with their severity so exploitation can prioritise
        # them
        discovered_subdomains: list[dict] = []
        _seen_subs: set = set()
        for f in self._findings:
            if f.get("type") == "open_port":
                p_match = re.search(r'Port (\d+)', f.get("detail", ""))
                if p_match:
                    p_num = int(p_match.group(1))
                    open_ports.append(p_num)
                    if f.get("source_tool") == "masscan":
                        masscan_ports.append(p_num)
                    svc_match = re.search(
                        r'Port \d+/\w+: ([\w-]+)',
                        f.get(
                            "detail",
                            ""))
                    if svc_match:
                        services[str(p_num)] = {
                            "service": svc_match.group(1), "protocol": "tcp"}
            elif f.get("type") == "app_root":
                base_paths.add(f.get("detail", "/"))
            elif f.get("type") == "subdomain":
                sub_domain = f.get("detail", "").strip()
                if sub_domain and sub_domain not in _seen_subs:
                    _seen_subs.add(sub_domain)
                    discovered_subdomains.append({
                        "domain": sub_domain,
                        "severity": f.get("severity", "info"),
                    })

        # Sort subdomains: high first, then medium, then info
        _sev_order = {
            "high": 0,
            "medium": 1,
            "critical": 0,
            "low": 2,
            "info": 3}
        discovered_subdomains.sort(
            key=lambda x: _sev_order.get(
                x.get(
                    "severity",
                    "info"),
                3))

        # Check liveness of discovered subdomains
        unique_domains = list(_seen_subs)
        subdomain_liveness = {}
        if unique_domains:
            try:
                info(
                    f"Probing {
                        len(unique_domains)} subdomains for HTTP liveness...")
                subdomain_liveness = self.check_liveness(unique_domains)
            except Exception as e:
                self.log.debug(f"Subdomain liveness probe failed: {e}")

        is_behind = any(
            f.get("type") == "waf_detected" for f in self._findings)
        waf_info = next(
            (f.get("detail")
             for f in self._findings if f.get("type") == "waf_detected"),
            "None detected")
        root_ip = next((re.search(r'IP: ([\d.]+)', f.get("detail", "")).group(1)
                       for f in self._findings if f.get("type") == "subdomain" and f.get("target") == target
                       and re.search(r'IP: ([\d.]+)', f.get("detail", ""))), None)

        # ── W6.3: ORIGIN DISCOVERY (prefer origin over the CDN/WAF) ──────────
        # When the target sits behind a CDN/WAF, the highest-leverage bypass is
        # simply finding the origin server IP and talking to it directly — it
        # skips the edge entirely. Run discovery here in recon (not only inside
        # the WAF-block path) and, if a viable origin is found, set it as the
        # preferred bypass URL so exploitation retargets to it.
        origin_ip = None
        if is_behind and not results.get("waf_bypass_url"):
            try:
                from intelligence.waf_bypass.origin_discovery import OriginDiscovery
                clean_host = re.sub(r"^https?://", "", target).split("/")[0]
                od = OriginDiscovery()
                disc = od.discover_origin_ips(clean_host, aggressive=False)
                candidates = disc.get("origin_candidates", []) or []
                for cand in candidates[:5]:
                    cip = cand.get("ip") if isinstance(cand, dict) else cand
                    if not cip or cip == root_ip:
                        continue
                    try:
                        test = od.test_origin_connection(cip, clean_host)
                    except Exception as _te:
                        self.log.debug(f"origin test failed for {cip}: {_te}")
                        continue
                    if test.get("bypass_viable"):
                        origin_ip = cip
                        results["waf_bypass_url"] = f"https://{cip}/"
                        results["origin_ip"] = cip
                        # WS6.3: authorize the verified origin IP in scope, else the
                        # exploitation retarget (base_agent adopts waf_bypass_url and
                        # rewrites the command host -> origin IP) is BLOCKED by the
                        # scope enforcer and the whole origin-bypass path is dead. The
                        # origin is the same in-scope asset via a different network
                        # path (bypass_viable confirmed) and the retarget keeps the
                        # in-scope Host header, so scoping the request stays honest.
                        try:
                            if cip not in self.session.scope:
                                self.session.scope.append(cip)
                                self.log.info(
                                    f"[ORIGIN] Authorized verified origin {cip} in engagement scope "
                                    "so exploitation can retarget to it.")
                        except Exception as _se:
                            self.log.debug(f"origin scope-extend failed: {_se}")
                        self.add_finding(
                            "origin_ip_discovered", target,
                            f"Origin server IP {cip} reachable directly, bypassing the "
                            f"CDN/WAF edge (Host: {clean_host}). Preferred attack path.",
                            "high")
                        info(f"[ORIGIN] Discovered reachable origin {cip} behind the edge — "
                             "exploitation will retarget to it.")
                        break
                if not origin_ip and candidates:
                    self.log.info(
                        f"[ORIGIN] {len(candidates)} origin candidate(s) found but none "
                        "verified reachable; staying on the edge.")
            except Exception as _od_err:
                self.log.debug(f"Origin discovery failed (non-fatal): {_od_err}")

        # Check existing phase data to preserve already discovered
        # waf_bypass_url
        existing_data = self.store.get_phase_data(
            self.session.engagement_id, "recon") or {}
        if not results.get("waf_bypass_url") and existing_data.get(
                "waf_bypass_url"):
            results["waf_bypass_url"] = existing_data.get("waf_bypass_url")

        bundle = {
            "open_ports": sorted(list(set(open_ports))),
            "masscan_ports": sorted(list(set(masscan_ports))),
            "services": services,
            "base_paths": sorted(list(base_paths)),
            "ai_analysis": ai_summary,
            "waf_present": is_behind,
            "waf_type": waf_info,
            "waf_fingerprint": fingerprint or {},
            "waf_bypass_url": results.get("waf_bypass_url"),
            "origin_ip": results.get("origin_ip"),
            "is_cdn": is_behind,
            "baseline_size": baseline_size,
            "resolved_ip": root_ip,
            "subdomain_liveness": subdomain_liveness,
            # NEW: scored subdomains list for exploitation phase consumption
            "subdomains": discovered_subdomains,
            "subdomains_high": [s["domain"] for s in discovered_subdomains if s["severity"] in ("high", "critical")],
            "subdomains_medium": [s["domain"] for s in discovered_subdomains if s["severity"] == "medium"],
        }

        # ===== AI REASONING LAYER: Structure raw findings and create tactical
        # This is the key layer that transforms messy raw output into
        # structured tactical guidance
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
                    # First 1K chars to save tokens
                    "stdout": finding.get("detail", "")[:1000]
                })

            # Structure the findings through AI analysis
            if all_tool_outputs:
                structured_findings = self.analyzer.structure_recon_phase_output(
                    all_tool_outputs)
                info(
                    f"Structured {
                        len(
                            structured_findings.get(
                                'all_findings',
                                []))} findings from recon tools")

                # (Findings are registered into the awareness lobe universally in
                # base_agent.add_finding now — in EVERY phase, not just recon — so
                # the old recon-only loop here is gone to avoid double-counting.)

                # Get AI reasoning about what findings mean tactically
                tactical_reasoning = self.reasoning.reason_about_findings(
                    structured_findings,
                    target,
                    mode=self.session.mode if hasattr(
                        self.session, 'mode') else "pentest"
                )

                # Register tactical assumptions
                for tactic in tactical_reasoning.get(
                        "exploitation_tactics", []):
                    self.awareness.register_assumption(
                        f"Try {
                            tactic.get('tactic')} on {
                            tactic.get('target')}",
                        confidence=tactic.get("probability_of_success", 0.5)
                    )
                    info(
                        f"[REASONING] {
                            tactic.get('tactic')}: {
                            tactic.get(
                                'reasoning', '')[
                                :100]}")

                # Register knowledge gaps - guard against string entries from
                # fallback reasoning
                for gap in tactical_reasoning.get("knowledge_gaps", []):
                    if isinstance(gap, dict):
                        self.awareness.register_knowledge_gap(gap)
                    elif isinstance(gap, str) and gap:
                        self.awareness.register_knowledge_gap(
                            {"gap": gap, "why_it_matters": "unknown", "how_to_find_out": "manual"})

                # Add reasoning to bundle for exploitation phase
                bundle["structured_findings"] = structured_findings
                bundle["tactical_reasoning"] = tactical_reasoning
                # Close the assumption loop before snapshotting awareness: judge
                # earlier assumptions against the evidence gathered so the state
                # reflects reality (bounded by the existing _awareness_needed
                # throttle = loop 1 + every 5th loop).
                if getattr(self, "_awareness_needed", False):
                    self._validate_assumptions()
                bundle["system_awareness"] = self.awareness.get_current_knowledge_state()

                sys_aware = bundle.get("system_awareness")
                sys_conf = sys_aware.get(
                    "overall_confidence",
                    "unknown") if isinstance(
                    sys_aware,
                    dict) else "unknown"
                success(
                    f"AI reasoning complete. System confidence: {sys_conf}")
        except Exception as reasoning_err:
            self.log.warning(
                f"AI reasoning layer failed (non-fatal): {reasoning_err}")
            # Continue without reasoning layer

        # Snapshot current findings for cross-target analysis
        bundle["all_findings_snapshot"] = list(self._findings)

        # Capture homepage HTML for cross-reference detection
        try:
            _html_r = self.safe_run_tool(
                "curl", f"curl -sL --max-time 10 {target}", target, silent=True
            )
            bundle["homepage_html"] = _html_r.stdout[:50000] if _html_r.success else ""
        except Exception as e:
            import logging as __logging_tmp
            __logging_tmp.getLogger(__name__).debug(f"Silenced exception: {e}")
            bundle["homepage_html"] = ""

        # ── ATTACK SURFACE EXTRACTION (Track 2) ────────────────────────────
        # The hypothesis engine can only reason as well as the evidence it gets.
        # Pull concrete injection points (forms, input fields, parameterised
        # endpoints) out of the HTML/endpoints we already collected so recon
        # hands off an attack SURFACE, not just an inventory of subdomains.
        try:
            endpoint_details = [
                f.get("detail", "") for f in self._findings
                if f.get("type") in ("discovered_endpoint", "app_root",
                                      "discovered_path", "web_fingerprint")
            ]
            attack_surface = self._extract_attack_surface(
                bundle.get("homepage_html", ""), endpoint_details)
            bundle["attack_surface"] = attack_surface
            for _p in attack_surface.get("parameters", [])[:25]:
                self.add_finding("discovered_param", target,
                                 f"Parameter: {_p}", "info")
            for _frm in attack_surface.get("forms", [])[:15]:
                self.add_finding(
                    "discovered_form", target,
                    f"Form {_frm.get('method', 'GET')} {_frm.get('action', '?')} "
                    f"inputs=[{', '.join(_frm.get('inputs', [])[:8])}]", "info")
            if attack_surface.get("parameters") or attack_surface.get("forms"):
                info(f"[ATTACK SURFACE] {len(attack_surface.get('parameters', []))} params, "
                     f"{len(attack_surface.get('forms', []))} forms, "
                     f"{len(attack_surface.get('param_endpoints', []))} parameterised endpoints.")
        except Exception as _ase:
            self.log.debug(f"attack-surface extraction failed (non-fatal): {_ase}")

        # ── EVIDENCE GRAPH ─────────────────────────────────────────────────
        # Formalise recon output into a structured graph so ExploitationAgent
        # can query facts deterministically instead of guessing from freetext.
        try:
            graph_nodes = []
            services = bundle.get(
                "services",
                {}) if isinstance(
                bundle,
                dict) else {}
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
                self.store.store_evidence_graph(
                    self.session.engagement_id, graph_nodes)
                info(f"Evidence graph written: {len(graph_nodes)} nodes.")
        except Exception as _eg_err:
            self.log.warning(
                f"Evidence graph write failed (non-fatal): {_eg_err}")

        # ===== STEALTH: IP ROTATION (only if Tor is configured) =====
        if self._ip_rotator is not None:
            try:
                self.rotate_tor_ip()
            except Exception as _tor_err:
                self.log.warning(
                    f"Post-recon Tor rotation failed (non-fatal): {_tor_err}")

        success(
            f"[MULTI-SCOPE] Recon complete for {host} — {len(self._findings)} findings")
        return bundle

    # ═══════════════════════════════════════════════════════════════════════
    #  MAIN ENTRY POINT  — multi-target orchestrator
    # ═══════════════════════════════════════════════════════════════════════

    async def run(self) -> dict:
        section("PHASE 2 - Reconnaissance (Multi-Scope)")
        self.store.set_phase_status(
            self.session.engagement_id, "recon", "running")

        # ── Build the list of targets to recon ───────────────────────────
        scope_targets = self._build_scope_target_list()
        info(
            f"[MULTI-SCOPE] Scope contains {len(scope_targets)} target(s): {scope_targets}")

        # ── Initialize cross-target graph ────────────────────────────────
        target_graph = TargetGraph()

        # ── Per-target recon ─────────────────────────────────────────────
        per_target_bundles: dict[str, dict] = {}
        cidr_bundles: dict[str, dict] = {}

        for raw_target in scope_targets:
            # Detect CIDR ranges — run a sweep instead of full recon
            import ipaddress as _ipa
            try:
                _ipa.ip_network(raw_target, strict=False)
                # It's a CIDR — do a sweep, not a full recon
                cidr_result = self._scan_cidr_range(raw_target)
                cidr_bundles[raw_target] = cidr_result
                # Register each live host as a target node
                for live_ip in cidr_result.get("live_hosts", []):
                    target_graph.add_target(
                        host=live_ip,
                        ip=live_ip,
                        open_ports=cidr_result["host_ports"].get(live_ip, []),
                    )
                    self.add_finding(
                        "live_host", raw_target,
                        f"Live host in range {raw_target}: {live_ip} "
                        f"ports={cidr_result['host_ports'].get(live_ip, [])}",
                        "medium",
                    )
                continue
            except ValueError:
                pass  # Not a CIDR — treat as hostname/URL

            # Full recon for hostname/URL targets
            try:
                # Reset per-target finding accumulator so each target's
                # findings are captured separately in its snapshot.
                _pre_finding_count = len(self._findings)
                bundle = self._run_recon_for_target(raw_target)
                # Capture only findings from this target's recon run
                bundle["all_findings_snapshot"] = list(
                    self._findings[_pre_finding_count:]
                )
                # Derive the canonical host key for the bundle
                try:
                    _hkey = TargetContext.from_input(raw_target).host
                except Exception as e:
                    import logging as __logging_tmp
                    __logging_tmp.getLogger(__name__).debug(
                        f"Silenced exception: {e}")
                    _hkey = raw_target
                per_target_bundles[_hkey] = bundle
            except Exception as _target_err:
                self.log.error(
                    f"[MULTI-SCOPE] Recon failed for {raw_target}: {_target_err}",
                    exc_info=True,
                )
                warning(
                    f"[MULTI-SCOPE] Skipping {raw_target} due to error: {_target_err}")

        # ── Cross-target relationship analysis ───────────────────────────
        if len(per_target_bundles) > 1 or cidr_bundles:
            section("CROSS-TARGET ANALYSIS")
            info(
                f"Analysing relationships across {
                    len(per_target_bundles)} targets...")
            target_graph = self._analyze_cross_target_relationships(
                per_target_bundles, target_graph
            )
            clusters = target_graph.get_shared_infra_clusters()
            if clusters:
                for cluster in clusters:
                    self.add_finding(
                        "shared_infrastructure",
                        " | ".join(cluster),
                        f"Shared infrastructure cluster detected: {cluster}",
                        "high",
                    )
                    info(f"[CROSS-TARGET] Shared infra: {cluster}")

            intel_summary = target_graph.get_cross_target_intel_summary()
            if intel_summary:
                info(
                    "[CROSS-TARGET] Relationship map built:\n" +
                    intel_summary)

        # ── Build combined multi-target bundle ───────────────────────────
        # Use primary target's bundle as the base for backward-compat,
        # then augment with multi-target data.
        try:
            primary_host = TargetContext.from_input(self.session.target).host
        except Exception as e:
            import logging as __logging_tmp
            __logging_tmp.getLogger(__name__).debug(f"Silenced exception: {e}")
            primary_host = self.session.target

        primary_bundle = per_target_bundles.get(primary_host, {})

        multi_bundle = dict(primary_bundle)  # start with primary
        multi_bundle["per_target"] = per_target_bundles
        multi_bundle["cidr_results"] = cidr_bundles
        multi_bundle["target_graph"] = target_graph.to_dict()
        multi_bundle["all_scope_hosts"] = scope_targets
        multi_bundle["primary_target"] = primary_host

        # ── WS2: TARGET COMPREHENSION LAYER ──────────────────────────────
        # Synthesize a strategic Target Model (what is this target, where's the
        # value, which vuln classes are plausible vs impossible) so exploitation
        # stops attacking impossible surfaces. AI-driven; falls back safely.
        try:
            from intelligence.target_profiler import TargetProfiler

            def _js_fetch(url: str) -> str:
                try:
                    r = self.tools.run(
                        "curl", f"curl -s -L --max-time 15 {url}", "recon",
                        silent=True)
                    return getattr(r, "stdout", "") or ""
                except Exception:
                    return ""

            profiler = TargetProfiler(ai_backend=self.ai, fetch_fn=_js_fetch)
            target_model = profiler.build(
                primary_host, multi_bundle, list(self._findings))
            multi_bundle["target_model"] = target_model.to_dict()
            self.store.set(
                f"{self.session.engagement_id}:target_model",
                json.dumps(target_model.to_dict()))
            info(
                f"[TARGET MODEL] {primary_host} → {target_model.target_type} "
                f"(conf {target_model.confidence:.0%}); "
                f"impossible: {target_model.implausible_vuln_classes[:4]}")
            # Surface as a finding so the model is visible in the report.
            self.add_finding(
                "target_model", primary_host,
                f"Target type: {target_model.target_type}. "
                f"Strategy: {target_model.recommended_strategy[:300]}",
                "info")
        except Exception as _tm_err:
            self.log.warning(
                f"[TARGET MODEL] synthesis failed (non-fatal): {_tm_err}")

        # Persist unified bundle
        self.store.set_phase_data(
            self.session.engagement_id, "recon", multi_bundle)
        if primary_bundle.get("waf_fingerprint"):
            try:
                self.store.set(
                    f"{self.session.engagement_id}:waf_fingerprint",
                    json.dumps(primary_bundle["waf_fingerprint"]),
                )
            except Exception as _e:
                import logging
                logging.getLogger(__name__).debug(
                    f'Swallowed exception persisting waf fingerprint: {_e}'
                )

        # Verify persistence
        persisted = self.store.get_phase_data(
            self.session.engagement_id, "recon")
        if not persisted:
            self.log.warning(
                "Recon phase_data write verification failed; retrying persist.")
            self.store.set_phase_data(
                self.session.engagement_id, "recon", multi_bundle)

        # Publish event so other agents know recon is done
        self.bus.publish("recon", "exploitation", {
            "event": "recon_complete",
            **{k: v for k, v in multi_bundle.items()
               if k not in ("per_target", "target_graph", "cidr_results",
                            "all_findings_snapshot", "homepage_html")},
        })

        success(
            f"[MULTI-SCOPE] Recon complete. "
            f"{len(per_target_bundles)} host targets + {len(cidr_bundles)} CIDR ranges processed."
        )
        return self.finish_phase(multi_bundle)
