from abc import ABC, abstractmethod
from pathlib import Path
from utils.logger import get_logger
from utils.display import agent_msg
from tools.tool_registry import TOOL_REGISTRY
import re
import time as _time_module
import threading
from utils.sanitizer import clean_text
from utils.validator import is_valid_target
from core.safe_executor import should_retry
from config import (
    CURL_TLS_FLAGS, STEALTH_HEADERS,
    TLS_BREAKER_BACKOFF_SECS, TLS_BREAKER_MAX_RETRIES,
    POST_HEAVY_SCAN_COOLDOWN, NETWORK_UNFIXABLE_EXITS,
    MAX_RESPONSE_SIZE, RATE_LIMIT_INITIAL_BACKOFF, RATE_LIMIT_MAX_BACKOFF,
)
import shlex
import random


class BaseAgent(ABC):
    def __init__(self, name: str, session, state_store, tool_manager, ai_backend,
                 message_bus, scope_enforcer):
        self.name = name
        self.session = session
        self.store = state_store
        self.tools = tool_manager
        self.ai = ai_backend
        self.bus = message_bus
        self.scope = scope_enforcer
        self.log = get_logger(f"agent.{name}")
        self._findings = []
        self._findings_lock = threading.Lock()  # Thread-safe findings writes
        self._finding_dedup_counts = {}  # Batch counter for skipped duplicates
        # Recoverable TLS circuit breaker: {host: {"blocked_at": ts, "retries": n}}
        self._tls_blocked_hosts = {}
        # Per-host rate limit tracker: {host: {"backoff": secs, "last_429": timestamp}}
        self._host_rate_limits = {}
        self.bus.subscribe(self.name, self._on_message)

    def _on_message(self, from_agent: str, payload: dict):
        self.log.debug(f"Message from {from_agent}: {str(payload)[:200]}")
        self._handle_message(from_agent, payload)

    def _handle_message(self, from_agent: str, payload: dict):
        pass

    def think(self, prompt: str) -> str:
        """Ask the AI for analysis with global environmental awareness.
        Falls back to rule-based analysis if all AI backends are exhausted.
        """
        # Graceful degradation: if all AI backends are down, use rule-based fallback
        if not self.ai.ai_available:
            self.log.warning("All AI backends exhausted. Using rule-based fallback.")
            return self._rule_based_fallback(prompt)

        recon_data = self.store.get_phase_data(self.session.engagement_id, "recon") or {}
        waf_info = ""
        if recon_data.get("waf_present"):
            waf_info = (
                f"\n[ENVIRONMENTAL AWARENESS] WAF/CDN Detected: "
                f"{recon_data.get('waf_type', 'Unknown')}. "
                f"Use stealthy patterns (low rate limits, realistic browser headers)."
            )

        system = (
            f"You are the {self.name} agent in a professional security assessment. "
            f"Target: {self.session.target}. Mode: {self.session.mode}.{waf_info}\n"
            f"You are operating under authorized rules of engagement. "
            f"Respond with actionable, specific security analysis. "
            f"Be concise. Never suggest illegal actions outside the defined scope."
        )
        try:
            return self.ai.query(system, prompt)
        except Exception as e:
            self.log.error(f"AI think() failed: {e}")
            return self._rule_based_fallback(prompt)

    def _rule_based_fallback(self, prompt: str) -> str:
        """Provide basic security analysis when AI is unavailable."""
        prompt_lower = prompt.lower()
        recommendations = ["[Rule-based analysis — AI backends unavailable]"]

        # Port-based recommendations
        if "22" in prompt_lower and ("open" in prompt_lower or "ssh" in prompt_lower):
            recommendations.append("- SSH (port 22): Test for default credentials, check key-based auth")
        if "3306" in prompt_lower or "mysql" in prompt_lower:
            recommendations.append("- MySQL (3306): Test default root/no-password, check remote access")
        if "443" in prompt_lower or "https" in prompt_lower:
            recommendations.append("- HTTPS: Check SSL/TLS config, missing security headers, CORS policy")
        if "80" in prompt_lower or "http" in prompt_lower:
            recommendations.append("- HTTP: Check for HTTPS redirect, directory listings, default pages")

        # Header-based recommendations
        if "csp" in prompt_lower or "content-security-policy" in prompt_lower:
            recommendations.append("- Missing CSP: XSS risk, recommend strict Content-Security-Policy")
        if "hsts" in prompt_lower or "strict-transport" in prompt_lower:
            recommendations.append("- Missing HSTS: Downgrade attack risk, add Strict-Transport-Security")
        if "cors" in prompt_lower:
            recommendations.append("- CORS: Check for wildcard origins, credential reflection")

        # Technology-based recommendations
        if "next.js" in prompt_lower or "vercel" in prompt_lower:
            recommendations.append("- Next.js: Check /.env, /_next/data/, /api/ for exposure")
        if "react" in prompt_lower or "spa" in prompt_lower:
            recommendations.append("- SPA: Check client-side JS for API keys, source maps")

        if len(recommendations) == 1:
            recommendations.append("- Run standard vulnerability assessment with available tool outputs")
            recommendations.append("- Check for common misconfigurations manually")

        return "\n".join(recommendations)

    def _dynamic_waf_update(self, waf_type: str):
        """Update global WAF state so all future agents/tools are aware."""
        self.log.info(f"Ghost Protocol: Updating WAF state → {waf_type}")
        recon_data = self.store.get_phase_data(self.session.engagement_id, "recon") or {}
        recon_data["waf_present"] = True
        recon_data["waf_type"] = waf_type
        self.store.set_phase_data(self.session.engagement_id, "recon", recon_data)
        self.add_finding("waf_discovered", self.session.target,
                         f"Dynamic discovery of {waf_type} during {self.name}", "medium")

    def add_finding(self, finding_type: str, target: str, detail: str, severity: str = "info"):
        """Add a deduplicated finding to the state store (batch-logged, thread-safe)."""
        with self._findings_lock:
            # Deduplicate: check type + first 120 chars of detail
            detail_key = detail[:120]
            for f in self._findings:
                if f["type"] == finding_type and f["detail"][:120] == detail_key:
                    # Batch-count instead of logging every single duplicate
                    dedup_key = f"{finding_type}:{detail_key[:40]}"
                    self._finding_dedup_counts[dedup_key] = \
                        self._finding_dedup_counts.get(dedup_key, 0) + 1
                    return

            self.store.add_finding(
                engagement_id=self.session.engagement_id,
                phase=self.name,
                finding_type=finding_type,
                target=target,
                detail=detail,
                severity=severity
            )
            self._findings.append({"type": finding_type, "target": target,
                                    "detail": detail, "severity": severity})
        agent_msg(self.name, f"[{severity.upper()}] {finding_type}: {detail[:100]}")

    def validate_and_add_finding(self, finding_type: str, target: str,
                                  detail: str, severity: str = "info"):
        """
        'Prove It' Architecture: Only commit a finding if a non-destructive
        AI-generated PoC script confirms it on the VPS.
        Falls back to add_finding if PoC generation fails.
        """
        import json as _json

        # 1. Dedup check
        with self._findings_lock:
            detail_key = detail[:120]
            for f in self._findings:
                if f["type"] == finding_type and f["detail"][:120] == detail_key:
                    return

        # 2. VPS connectivity guard
        if not self.tools.remote or not self.tools.remote.is_active():
            self.log.warning("Prove It: VPS not connected. Falling back to standard add_finding.")
            self.add_finding(finding_type, target, detail, severity)
            return

        # 3. AI prompt for PoC script
        poc_prompt = (
            f"Write a Python3 script that NON-DESTRUCTIVELY verifies this finding:\n"
            f"Type: {finding_type}\nTarget: {target}\nDetail: {detail}\n\n"
            f"Rules:\n"
            f"- Must print exactly 'CONFIRMED' to stdout if the vulnerability is real\n"
            f"- Must print 'NOT_CONFIRMED' otherwise\n"
            f"- Must complete in under 10 seconds\n"
            f"- Must be read-only (no writes, no exploits, no modifications)\n"
            f"- Use only stdlib + requests (which is installed)\n"
            f"- Handle all exceptions gracefully\n\n"
            f"Return ONLY the raw Python script, no markdown fences."
        )

        try:
            poc_script = self.think(poc_prompt)
        except Exception as e:
            self.log.warning(f"Prove It: AI PoC generation failed: {e}")
            self.add_finding(finding_type, target, detail, severity)
            return

        # Strip markdown fences if present
        if "```" in poc_script:
            poc_script = re.sub(r'```python\n?', '', poc_script)
            poc_script = re.sub(r'```\n?', '', poc_script)
        poc_script = poc_script.strip()

        if not poc_script or len(poc_script) < 20:
            self.log.warning("Prove It: AI returned empty/too-short PoC. Falling back.")
            self.add_finding(finding_type, target, detail, severity)
            return

        # 4. Upload to VPS with collision-safe filename
        poc_filename = f"/tmp/poc_{finding_type}_{int(_time_module.time())}.py"
        upload_ok = self.tools.remote.upload_content(poc_script, poc_filename)
        if not upload_ok:
            self.log.warning("Prove It: Failed to upload PoC script. Falling back.")
            self.add_finding(finding_type, target, detail, severity)
            return

        # 5. Execute with timeout
        exit_code, stdout, stderr = self.tools.remote.execute(
            f"timeout 15 python3 {poc_filename}", timeout=20
        )

        # 6. Validate stdout for CONFIRMED token
        if "CONFIRMED" in stdout:
            self.log.info(f"Prove It: CONFIRMED — {finding_type} on {target}")
            self.add_finding(
                finding_type, target,
                f"[VERIFIED] {detail}", severity
            )
        else:
            self.log.info(
                f"Prove It: NOT confirmed — {finding_type} on {target}. "
                f"PoC output: {stdout[:200]}"
            )
            # Don't add unconfirmed findings for high/critical
            if severity in ("info", "medium"):
                self.add_finding(
                    finding_type, target,
                    f"[UNVERIFIED] {detail}", severity
                )

        # 8. Cleanup
        self.tools.remote.execute(f"rm -f {poc_filename}")

    def _preflight(self) -> tuple[bool, str]:
        """
        Pre-flight check before running this agent's phase.
        Override in subclasses to add dependency checks.
        Returns (can_proceed: bool, reason: str).
        """
        return True, ""

    def _playwright_bypass(self, original_command: str):
        """
        V2 Phase E: Headless Browser Automation.
        Attempts to bypass JS challenges/CAPTCHA by rendering the page in
        a real Chromium browser via Playwright on the VPS.
        Returns a ToolResult on success, or None on failure.
        """
        from tools.tool_manager import ToolResult

        if not self.tools.remote or not self.tools.remote.is_active():
            return None

        # Extract target URL from the original command
        url = None
        urls = re.findall(r'https?://[^\s\'"]+', original_command)
        if urls:
            url = urls[-1]  # Last URL is typically the target
        if not url:
            return None

        # Ensure Playwright is installed (lazy-install on first use)
        if not self.tools.ensure_installed("playwright"):
            self.log.warning("Playwright not available on VPS. Skipping headless bypass.")
            return None

        # Generate a minimal Playwright script
        pw_script = f'''
import sys
try:
    from playwright.sync_api import sync_playwright
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True, args=["--no-sandbox", "--disable-gpu"])
        page = browser.new_page()
        page.set_default_timeout(8000)
        page.goto("{url}", wait_until="networkidle", timeout=20000)
        # Wait extra for JS challenges to auto-resolve
        page.wait_for_timeout(3000)
        content = page.content()
        print("BYPASSED")
        print(content[:50000])
        browser.close()
except Exception as e:
    print(f"PLAYWRIGHT_ERROR: {{e}}", file=sys.stderr)
    sys.exit(1)
'''

        # Upload and execute on VPS
        script_path = f"/tmp/pw_bypass_{int(_time_module.time())}.py"
        upload_ok = self.tools.remote.upload_content(pw_script, script_path)
        if not upload_ok:
            return None

        exit_code, stdout, stderr = self.tools.remote.execute(
            f"timeout 30 python3 {script_path}", timeout=35
        )

        # Cleanup
        self.tools.remote.execute(f"rm -f {script_path}")

        if "BYPASSED" in stdout:
            # Extract the page content (everything after "BYPASSED\n")
            content = stdout.split("BYPASSED\n", 1)[-1] if "BYPASSED\n" in stdout else stdout
            return ToolResult(
                tool="playwright", command=f"playwright_bypass({url})",
                stdout=content, stderr=stderr,
                exit_code=0, duration=0, status="success"
            )

        self.log.debug(f"Playwright bypass failed: {stderr[:200]}")
        return None

    def flush_dedup_stats(self):
        """Log batch counts of skipped duplicates (call at end of phase)."""
        if self._finding_dedup_counts:
            total = sum(self._finding_dedup_counts.values())
            self.log.info(f"Dedup summary: {total} duplicate findings suppressed "
                          f"across {len(self._finding_dedup_counts)} categories.")
            self._finding_dedup_counts.clear()

    def _post_scan_cooldown(self, scan_name: str, seconds: int = None):
        """Wait after a heavy scan to let WAF rate-limit windows expire."""
        wait = seconds if seconds is not None else POST_HEAVY_SCAN_COOLDOWN
        if wait > 0:
            self.log.info(f"Post-{scan_name} cooldown: waiting {wait}s for WAF rate-limit recovery...")
            _time_module.sleep(wait)

    def _clean_command(self, cmd: str) -> str:
        """
        Prepare a command for VPS execution:
        1. Normalize Windows path separators
        2. Inject DNS server for dig (if not already present)
        3. Privacy Scrubber (Referer)
        4. Inject Stealth Flags (TLS)
        5. WHOIS Resiliency
        6. Strip non-ASCII characters
        7. Prepend PATH export
        """
        if not cmd:
            return cmd

        vps_paths = (
            "$HOME/.local/bin:/root/.local/bin:/usr/local/bin"
            ":/usr/sbin:/usr/bin:/sbin:/bin:/usr/games"
            ":/root/theHarvester"
        )

        # 1. Normalize Windows backslashes
        cmd = cmd.replace("\\", "/")

        # 2. Inject reliable DNS server for dig (only if not already specified)
        if cmd.strip().startswith("dig ") and "@" not in cmd:
            cmd = cmd.replace("dig ", "dig @1.1.1.1 ", 1)

        # 3. Privacy Scrubber: Poison the Referer to hide source origin
        if "--referer" not in cmd and "-e " not in cmd: # wget uses -e
             common_referers = ["https://www.google.com/", "https://duckduckgo.com/", "https://www.bing.com/"]
             ref = random.choice(common_referers)
             if "curl " in cmd:
                 cmd = cmd.replace("curl ", f"curl -e {shlex.quote(ref)} ", 1)

        # 4. Inject Stealth Flags for curl/wget to bypass WAF & Hide Identity
        #    Only for HTTPS — TLS flags are meaningless and can break HTTP requests
        if "curl " in cmd and CURL_TLS_FLAGS not in cmd and "https://" in cmd:
            # Prevent Double-Injection: do not append if agent manually supplied a User-Agent
            if "-H 'User-Agent:" not in cmd and "-A " not in cmd:
                # NOTE: Do NOT inject X-Forwarded-For / X-Originating-IP headers.
                # hcdn (Hostinger CDN) uses these as scanner fingerprints — their presence
                # in a non-browser TLS session triggers 'tls: internal error' RST drops.
                # Real browsers never send XFF headers. Removing them improves stealth.
                cmd = cmd.replace("curl ", f"curl {CURL_TLS_FLAGS} ", 1)
        
        # 5. WHOIS Resiliency: Universal 4-tier fallback for ANY TLD registry
        #    Key fix: use output-length checks, not just exit codes — whois can
        #    exit 0 with empty output for uncommon TLDs (.lk, .bd, .pk, etc.)
        if cmd.strip().startswith("whois ") and "timeout " not in cmd:
            target_domain = cmd.split()[-1]
            # Tier 1: Standard whois (20s, check output has content)
            # Tier 2: IANA referral → query discovered server directly
            # Tier 3: RDAP JSON API (modern replacement for whois)
            # Tier 4: Web scraping fallback
            cmd = (
                f"OUT=$(timeout 20 whois {target_domain} 2>/dev/null); "
                f"if [ $(echo \"$OUT\" | wc -c) -gt 50 ]; then echo \"$OUT\"; exit 0; fi; "
                f"REF=$(timeout 10 whois -h whois.iana.org {target_domain} 2>/dev/null "
                f"| grep -i refer | awk '{{print $2}}' | head -1); "
                f"if [ -n \"$REF\" ]; then "
                f"OUT2=$(timeout 20 whois -h \"$REF\" {target_domain} 2>/dev/null); "
                f"if [ $(echo \"$OUT2\" | wc -c) -gt 50 ]; then echo \"$OUT2\"; exit 0; fi; fi; "
                f"curl --max-filesize 5242880 -sL --max-time 15 "
                f"'https://rdap.org/domain/{target_domain}' 2>/dev/null "
                f"| python3 -c \"import sys,json; d=json.load(sys.stdin); "
                f"print('Domain:',d.get('ldhName','')); "
                f"[print('Nameserver:',n.get('ldhName','')) for n in d.get('nameservers',[])]; "
                f"[print(e.get('eventAction','')+':', e.get('eventDate','')) for e in d.get('events',[])]\" "
                f"2>/dev/null || "
                f"curl --max-filesize 5242880 -sL --max-time 15 "
                f"'https://whois.domaintools.com/{target_domain}' 2>/dev/null "
                f"| grep -oP '(?s)<div class=\"whois-data\">.*?</div>' | head -80"
            )

        # 6. Response Size Guard: prevent OOM on huge pages
        if "curl " in cmd and "--max-filesize" not in cmd:
            cmd = cmd.replace("curl ", f"curl --max-filesize {MAX_RESPONSE_SIZE} ", 1)

        # 7. AI Command Sanitizer & Ext WAF Evasion
        if "nmap " in cmd:
            cmd = re.sub(r'--script:', '--script=', cmd)  # AI often hallucinates colon

        # NOTE: Do NOT inject X-Forwarded-For into gobuster or ffuf.
        # hcdn and similar CDNs detect scanner traffic by the XFF header presence
        # in non-browser HTTP sessions — this was causing 'tls: internal error'.
        # The TLS block then cascaded to ALL subsequent curl probes in the phase.
            
        # 8. Strip non-ASCII / hidden characters
        clean = re.sub(r'[^\x20-\x7E]', '', cmd.strip())

        # 8. Prepend PATH export if not already present
        path_prefix = f"export PATH={vps_paths}:$PATH && "
        if path_prefix in clean:
            return clean

        return path_prefix + clean

    def _extract_host(self, command: str) -> str | None:
        """Extract the TARGET hostname from a URL in a command, ignoring referer URLs."""
        urls = re.findall(r'https?://([^\s/\'",:]+)', command)
        if not urls:
            return None
        # Filter out referer domains injected by _clean_command
        referer_domains = {"www.google.com", "www.bing.com", "duckduckgo.com"}
        targets = [h.split(':')[0] for h in urls if h.split(':')[0] not in referer_domains]
        return targets[-1] if targets else None

    def safe_run_tool(self, tool: str, command: str, target: str = None,
                       output_path: str | Path = None, silent: bool = False):
        """
        Run a tool with safety checks and autonomous self-repair (Ghost Protocol).
        Features:
        - Scope enforcement
        - Target validation
        - Universal PATH injection
        - AI-driven syntax repair (Ghost Protocol)
        - WAF adaptive recovery
        - Circuit breaker (loop prevention)
        - Network error detection (skip repair for unfixable errors)
        """
        from tools.tool_manager import ToolResult
        from core.scope_enforcer import ScopeViolation

        # ── Scope check ──────────────────────────────────────────────────────
        if target:
            try:
                self.scope.check_target(target)
            except ScopeViolation as e:
                self.log.warning(f"SCOPE BLOCK: {e}")
                return ToolResult(tool=tool, command=command, stdout="", stderr=str(e),
                                   exit_code=-1, duration=0, status="scope_blocked")

        # ── Input sanitization ───────────────────────────────────────────────
        current_command = self._clean_command(clean_text(command))
        if target:
            target = clean_text(target)
            if not is_valid_target(target):
                self.log.warning(f"VALIDATION BLOCK: '{target}' is not a valid domain or IP.")
                return ToolResult(tool=tool, command=current_command, stdout="",
                                   stderr="Invalid target format", exit_code=-1,
                                   duration=0, status="failed")

        # ── TLS circuit breaker: skip curl to hosts where TLS is dead ───────
        # Only applies to curl — nikto/nuclei/gobuster have their own TLS stacks
        # that can bypass CDN fingerprinting even when curl is blocked.
        # RECOVERABLE: After TLS_BREAKER_BACKOFF_SECS, we allow one retry.
        _VIRTUAL_TOOLS = {"ssh_cmd", "remote_exec", "ai_dynamic_recon", "react_payload", "python", "python3"}
        cmd_host = self._extract_host(command)
        tls_blocked = (
            (tool == "curl" or tool in _VIRTUAL_TOOLS)
            and cmd_host
            and cmd_host in self._tls_blocked_hosts
            and ("https://" in command or "http://" in command)
        )
        if tls_blocked:
            breaker_info = self._tls_blocked_hosts[cmd_host]
            elapsed = _time_module.time() - breaker_info["blocked_at"]
            if elapsed < TLS_BREAKER_BACKOFF_SECS:
                self.log.warning(
                    f"[TLS CIRCUIT BREAKER] Skipping curl → {cmd_host} "
                    f"(TLS dead, retry in {TLS_BREAKER_BACKOFF_SECS - elapsed:.0f}s)"
                )
                return ToolResult(tool=tool, command=command, stdout="",
                                   stderr="TLS blocked by circuit breaker",
                                   exit_code=35, duration=0, status="tls_blocked")
            elif breaker_info["retries"] >= TLS_BREAKER_MAX_RETRIES:
                self.log.warning(
                    f"[TLS CIRCUIT BREAKER] Permanently blocked: {cmd_host} "
                    f"({breaker_info['retries']}/{TLS_BREAKER_MAX_RETRIES} retries exhausted)"
                )
                return ToolResult(tool=tool, command=command, stdout="",
                                   stderr="TLS blocked permanently after max retries",
                                   exit_code=35, duration=0, status="tls_blocked")
            else:
                # Backoff expired AND retries remain — fully clear the block for a clean-slate attempt.
                # Do NOT just reset blocked_at; that would re-extend the block on every probe.
                self.log.info(
                    f"[TLS CIRCUIT BREAKER] Backoff expired for {cmd_host}. "
                    f"Clearing block for clean retry (attempt {breaker_info['retries'] + 1}/{TLS_BREAKER_MAX_RETRIES})..."
                )
                # Track that we used a retry slot, but allow the command to pass through
                self._tls_blocked_hosts[cmd_host]["retries"] += 1
                del self._tls_blocked_hosts[cmd_host]  # Remove block — let command run freely

        # ── Virtual tool routing (SSH commands, no registry lookup) ──────────

        repair_count = 0
        max_repairs = 3
        cmd_history = set()  # Circuit breaker

        while repair_count <= max_repairs:
            # ── Circuit breaker ───────────────────────────────────────────────
            # Strip PATH prefix before dedup check to avoid false mismatches
            normalized = " ".join(current_command.split())
            prefix_marker = "$PATH && "
            if prefix_marker in normalized:
                normalized = normalized.split(prefix_marker, 1)[-1].strip()
            if normalized in cmd_history:
                self.log.warning(
                    f"[CIRCUIT BREAKER] Dedup: '{tool}' — same command already attempted, skipping."
                )
                break
            cmd_history.add(normalized)

            if repair_count > 0:
                self.log.info(f"Ghost Protocol: Repair attempt {repair_count}/{max_repairs}")

            # ── Stability Guard ───────────────────────────────────────────────
            # Check binary presence AFTER stripping the PATH prefix
            if tool not in _VIRTUAL_TOOLS:
                cmd_without_prefix = normalized
                binary = TOOL_REGISTRY.get(tool, {}).get("binary", tool)
                import shlex
                tokens = []
                try:
                    tokens = shlex.split(cmd_without_prefix)
                except ValueError:
                    pass
                allowed_wrappers = {"timeout", "sudo", "stdbuf", "time", "env", "nohup"}
                # Detect compound shell scripts: variable assignments (VAR=...),
                # subshells ((...)), or conditionals (if/for/while).
                # These are valid multi-statement commands from _clean_command()
                # and should NOT have the binary re-injected.
                is_compound = (
                    tokens and (
                        '=' in tokens[0] or           # VAR=$(cmd) assignment
                        tokens[0].startswith('(') or  # Subshell
                        tokens[0].startswith('{') or  # Brace group
                        tokens[0] in ('if', 'for', 'while', 'case', 'bash')
                    )
                )
                if tokens and tokens[0] not in (tool, binary) and tokens[0] not in allowed_wrappers and not is_compound:
                    self.log.warning(
                        f"Stability Guard: Mangled command for '{tool}'. Re-injecting binary."
                    )
                    current_command = self._clean_command(f"{tool} {cmd_without_prefix}")

            # ── Execute ───────────────────────────────────────────────────────
            if tool in _VIRTUAL_TOOLS:
                if not self.tools.remote:
                    return ToolResult(tool=tool, command=current_command, stdout="",
                                       stderr="VPS not connected", exit_code=-1,
                                       duration=0, status="failed")
                import time as _time
                _start = _time.time()
                exit_code, out, err = self.tools.remote.execute(current_command)
                _dur = _time.time() - _start
                status = "success" if exit_code == 0 else "failed"
                result = ToolResult(tool=tool, command=current_command, stdout=out,
                                     stderr=err, exit_code=exit_code,
                                     duration=_dur, status=status)
                if status == "failed":
                    self.tools._print_vps_console(current_command, status, _dur, out, err)
            else:
                result = self.tools.run(tool, current_command, phase=self.name,
                                         output_path=output_path, silent=silent)

            combined_output = (result.stdout + result.stderr).lower()

            # ── HTTP 429 Rate Limit detection ──────────────────────────────
            if "429" in combined_output or "too many requests" in combined_output:
                host_429 = self._extract_host(command)
                if host_429:
                    rate_info = self._host_rate_limits.get(host_429, {
                        "backoff": RATE_LIMIT_INITIAL_BACKOFF, "last_429": 0
                    })
                    backoff = min(rate_info["backoff"], RATE_LIMIT_MAX_BACKOFF)
                    self.log.warning(
                        f"[RATE LIMIT] HTTP 429 from {host_429}. "
                        f"Backing off {backoff}s before continuing..."
                    )
                    _time_module.sleep(backoff)
                    self._host_rate_limits[host_429] = {
                        "backoff": backoff * 2,  # exponential
                        "last_429": _time_module.time()
                    }
                    self.add_finding(
                        "rate_limited", host_429 or self.session.target,
                        f"Target returned HTTP 429 — active rate limiting detected", "info"
                    )
                # Don't retry — the backoff alone may fix the next probe
                return result

            # ── CAPTCHA wall detection ───────────────────────────────────
            captcha_signals = [
                "captcha", "recaptcha", "hcaptcha", "turnstile",
                "verify you are human", "challenge-platform",
                "cf-turnstile", "g-recaptcha",
            ]
            if any(sig in combined_output for sig in captcha_signals):
                self.log.info("⚡ CAPTCHA/JS challenge detected. Attempting Playwright headless bypass...")

                # V2: Playwright headless bypass attempt
                bypass_result = self._playwright_bypass(command)
                if bypass_result and bypass_result.success:
                    self.log.info("✓ Playwright headless bypass successful!")
                    bypass_result.status = "fallback_success"
                    return bypass_result

                self.log.warning("Playwright bypass unavailable or failed. CAPTCHA blocks probe.")
                result.status = "captcha_blocked"
                self.add_finding(
                    "captcha_detected", self._extract_host(command) or self.session.target,
                    "Target requires CAPTCHA verification — automated probing blocked", "medium"
                )
                return result

            # ── TCP RST detection (exit 56) ─────────────────────────────
            if result.exit_code == 56 or "connection reset" in combined_output:
                self.log.warning("TCP RST from target. Pausing 5s before continuing...")
                _time_module.sleep(5)
                self.add_finding(
                    "network_defense",
                    self._extract_host(command) or self.session.target,
                    "Target sends TCP RST — active connection killing detected", "info"
                )
                # For non-curl tools, return immediately (no fallback chain)
                if "curl " not in current_command:
                    return result
                # For curl commands: fall through to the adaptive fallback chain below

            # ── Network block / TLS failure / TCP RST: adaptive fallback ─────────────────
            if result.exit_code in (28, 35, 56) and "curl " in current_command:
                self.log.info(f"⚡ Connection issue ({result.exit_code}) for '{tool}'. Engaging adaptive fallback chain...")
                # Step 1: Try forcing HTTP/1.1 (bypasses H2 fingerprinting)
                http11_cmd = current_command.replace("curl ", "curl --http1.1 ", 1)
                if tool in _VIRTUAL_TOOLS:
                    exit_code, out, err = self.tools.remote.execute(http11_cmd)
                    status = "success" if exit_code == 0 else "failed"
                    result = ToolResult(tool=tool, command=http11_cmd, stdout=out,
                                         stderr=err, exit_code=exit_code,
                                         duration=0, status=status)
                else:
                    # Run silently so intermediate failures don't spam the console
                    result = self.tools.run(tool, http11_cmd, phase=self.name, silent=True)

                if result.success:
                    self.log.info(f"✓ HTTP/1.1 fallback recovered '{tool}' successfully.")
                    result.status = "fallback_success"
                    if not silent:
                        self.tools._print_vps_console(http11_cmd, result.status, result.duration, result.stdout, result.stderr)
                    return result

                # Step 2: Naked Retry (strip all stealth headers)
                self.log.info(f"⚡ HTTP/1.1 insufficient. Attempting Naked Retry (no stealth headers)...")
                naked_cmd = current_command.replace(CURL_TLS_FLAGS, "").replace(STEALTH_HEADERS, "")
                if tool == "curl":
                    naked_cmd = naked_cmd.replace("-sI", "-s").replace("-I", "-s") # Switch to GET for better TLS compat
                
                # Perform the Naked Retry
                if tool in _VIRTUAL_TOOLS:
                    exit_code, out, err = self.tools.remote.execute(naked_cmd)
                    status = "success" if exit_code == 0 else "failed"
                    result = ToolResult(tool=tool, command=naked_cmd, stdout=out,
                                         stderr=err, exit_code=exit_code,
                                         duration=0, status=status)
                else:
                    result = self.tools.run(tool, naked_cmd, phase=self.name, silent=True)
                
                if result.success:
                    self.log.info(f"✓ Naked Retry recovered '{tool}' successfully.")
                    result.status = "fallback_success"
                    if not silent:
                        self.tools._print_vps_console(naked_cmd, result.status, result.duration, result.stdout, result.stderr)
                    return result
                else:
                    self.log.info(f"⚡ Naked Retry insufficient. Engaging WGET TLS-Bypass Fallback...")
                    if "curl " in naked_cmd:
                        # Translate curl to wget with robust flag mapping
                        wget_cmd = naked_cmd
                        # Inject wget with baseline bypass flags (regex ensures we only hit the binary, not URLs)
                        wget_cmd = re.sub(r'(^|\s|&&|\|\||;|\|)curl\b', r'\1wget -qO- --no-check-certificate --tries=1 --timeout=10', wget_cmd)
                        # Normalize common curl flags to wget equivalents using robust regex
                        # Note: curl flags starting with '-' or '--' don't work well with \b at the start
                        flag_map = {
                            r'--max-time\b\s*=?': '--timeout=',
                            r'-m\b\s*=?': '--timeout=',
                            r'--connect-timeout\b\s*=?': '--timeout=',
                            r'--location\b': '',
                            r'-L\b': '',
                            r'-sL\b': '',
                            r'-sI\b': '--spider -S',
                            r'-I\b': '--spider -S',
                            r'-so\b\s*\S+': '', # Strip -so /dev/null
                            r'-sS\b': '',
                            r'-s\b': '',
                            r'-k\b': '',
                            r'-w\b\s*\'[^\']*\'': '', # Strip -w '...'
                            r'-w\b\s*\"[^\"]*\"': '', # Strip -w "..."
                            r'-w\b\s*\S+': '',        # Strip -w %{...}
                            r'-o\b\s*\S+': '',        # Strip -o /dev/null
                            r'-D\b\s*\S+': '',        # Strip -D -
                            r'--header\b\s*=?': '--header=',
                            r'-H\b\s*=?': '--header=',
                            r'--referer\b\s*=?': '--referer=',
                            r'-e\b\s*=?': '--referer=',
                            r'--user-agent\b\s*=?': '--user-agent=',
                            r'-A\b\s*=?': '--user-agent=',
                        }
                        for pattern, replacement in flag_map.items():
                            # Use (?:^|\s) as an anchor instead of \b for the start of the flag
                            full_pattern = r'(^|\s)' + pattern
                            wget_cmd = re.sub(full_pattern, r'\1' + replacement, wget_cmd)
                        
                        # Strip any remaining curl-style short flags that might break wget
                        # (e.g., clustered flags we missed, or things like -v, -u, etc.)
                        # We only keep --header, --referer, --user-agent, --timeout, --spider
                        known_wget_flags = ['--header', '--referer', '--user-agent', '--timeout', '--spider', '--no-check-certificate', '--tries', '-qO-', '-S']
                        
                        # Final clean: remove any tokens starting with '-' that aren't in our whitelist
                        # and aren't obviously values for headers/referers
                        words = wget_cmd.split()
                        final_words = []
                        skip_next = False
                        for i, w in enumerate(words):
                            if skip_next:
                                skip_next = False
                                final_words.append(w)
                                continue
                            if w.startswith('-') and not any(w.startswith(k) for k in known_wget_flags) and not w.startswith('--no-check-certificate'):
                                # If it's a known curl flag that we want to ignore, skip it
                                continue
                            if any(w.startswith(k) for k in ['--header', '--referer', '--user-agent', '--timeout']):
                                if '=' not in w and i + 1 < len(words):
                                    skip_next = True
                            final_words.append(w)
                        
                        wget_cmd = " ".join(final_words)
                        # Ensure wget is still the binary
                        if not wget_cmd.startswith("wget") and "wget" in wget_cmd:
                            wget_cmd = "wget " + wget_cmd.split("wget", 1)[-1]
                        elif not wget_cmd.startswith("wget"):
                             # If something went horribly wrong, use a baseline
                             host = self._extract_host(current_command)
                             if host:
                                 wget_cmd = f"wget -qO- --no-check-certificate --tries=1 --timeout=10 https://{host}/"
                        
                        if tool in _VIRTUAL_TOOLS:
                            exit_code, out, err = self.tools.remote.execute(wget_cmd)
                            status = "success" if exit_code == 0 else "failed"
                            result = ToolResult(tool="wget", command=wget_cmd, stdout=out,
                                                 stderr=err, exit_code=exit_code,
                                                 duration=0, status=status)
                        else:
                            result = self.tools.run("wget", wget_cmd, phase=self.name, silent=True)
                    
                    if result.success:
                        self.log.info(f"✓ WGET Fallback recovered data bypassing TLS block.")
                        result.status = "fallback_success"
                        if not silent:
                            self.tools._print_vps_console(wget_cmd, result.status, result.duration, result.stdout, result.stderr)
                        return result
                        
                    self.log.error(f"WGET Fallback failed. Target actively blocking tools.")
                    host = self._extract_host(current_command)
                    if host:
                        if host in self._tls_blocked_hosts:
                            # Increment retry counter on existing breaker
                            self._tls_blocked_hosts[host]["retries"] += 1
                            self._tls_blocked_hosts[host]["blocked_at"] = _time_module.time()
                            self.log.warning(
                                f"[TLS CIRCUIT BREAKER] Retry failed for '{host}'. "
                                f"Attempt {self._tls_blocked_hosts[host]['retries']}/{TLS_BREAKER_MAX_RETRIES}."
                            )
                        else:
                            self._tls_blocked_hosts[host] = {
                                "blocked_at": _time_module.time(),
                                "retries": 0
                            }
                            self.log.warning(
                                f"[TLS CIRCUIT BREAKER] Marked '{host}' as TLS-blocked. "
                                f"Will retry after {TLS_BREAKER_BACKOFF_SECS}s cooldown."
                            )
                    result.status = "tls_blocked"
                    return result

            # ── WAF / Challenge detection ─────────────────────────────────────
            waf_signals = [
                "vercel security checkpoint", "x-vercel-mitigated",
                "attention required! | cloudflare", "cf-ray"
            ]
            if any(sig in combined_output for sig in waf_signals):
                waf_type = "Vercel Challenge" if "vercel" in combined_output else "Cloudflare Challenge"
                self.log.warning(f"Ghost Protocol: {waf_type} detected. Adaptive stealth recovery...")
                self._dynamic_waf_update(waf_type)
                repair_count += 1
                if repair_count > max_repairs:
                    result.status = "waf_blocked"
                    return result

                recovery_prompt = (
                    f"The command '{current_command}' was blocked by {waf_type}.\n"
                    f"Rewrite it to bypass: add realistic User-Agent, Referer header, "
                    f"and reduce rate limits. Return ONLY a JSON object:\n"
                    f'{{ "retry_cmd": "the corrected command" }}'
                )
                try:
                    import json as _json
                    resp = self.think(recovery_prompt)
                    m = re.search(r'\{[^{}]*"retry_cmd"[^{}]*\}', resp, re.DOTALL)
                    if m:
                        fix = _json.loads(m.group(0))
                        retry_cmd = fix.get("retry_cmd", "")
                        if retry_cmd and len(retry_cmd) < 500:
                            current_command = self._clean_command(retry_cmd)
                            continue
                except Exception as e:
                    self.log.error(f"Ghost Protocol WAF recovery failed: {e}")
                result.status = "waf_blocked"
                return result

            # ── Error keyword detection → force failed for repair ─────────────
            # Tight list — avoid broad terms like "not found" or "failed"
            hard_error_keywords = [
                "invalid source", "invalid engine", "access denied",
                "permission denied", "syntax error", "invalid option",
                "flag provided but not defined", "unrecognized",
                "fatal error", "no such file or directory",
                "[fatal]", "unknown flag", "unknown argument",
            ]
            # Nmap's binary probe fingerprint blocks (SF-Port80-TCP:V=...) can contain
            # ASCII substrings matching error keywords in raw hex data — strip them first
            # to prevent false-positive Ghost Protocol triggers on successful scans.
            check_output = combined_output
            if tool == "nmap":
                # Try to filter out the fingerprint blocks cleanly
                check_output = re.sub(r'SF-Port.*?\nSF:', '', check_output, flags=re.DOTALL)
                
            if result.success and any(k in check_output for k in hard_error_keywords):
                self.log.warning(f"Ghost Protocol: Hidden syntax error in '{tool}' output.")
                result.status = "failed"
                result.success = False

            # ── Return on success or non-retriable status ─────────────────────
            if result.success or result.status in ("timeout", "scope_blocked", "waf_blocked", "not_installed", "tls_blocked", "captcha_blocked"):
                return result

            # ── SSH failure: trigger reconnect and retry ──────────────────────
            ssh_errors = ["ssh session not active", "ssh not connected", "ssh connection failed", "channel closed"]
            if any(err in combined_output for err in ssh_errors) or result.exit_code == -1:
                self.log.warning("Ghost Protocol: SSH session dropped. Attempting infrastructure recovery...")
                if self.tools.remote.connect():
                    # Brief cooldown to let session stabilize
                    import time as _time
                    _time.sleep(2)
                    continue 

            # ── SSH timeout: no repair ────────────────────────────────────────
            if result.exit_code == -2:
                self.log.warning(f"SSH timeout for '{tool}'. Returning.")
                return result

            # ── Malformed input: no repair ────────────────────────────────────
            if not should_retry(result):
                self.log.warning(
                    f"Ghost Protocol: Exit {result.exit_code} for '{tool}' "
                    f"indicates malformed input. Skipping repair."
                )
                return result

            repair_count += 1
            if repair_count > max_repairs:
                break

            err_lower = (result.stderr + result.stdout).lower()

            # ── Step 1: Missing binary → auto-install ─────────────────────────
            if result.exit_code == 127 or "command not found" in err_lower:
                missing_bin = tool
                # Extract actual missing binary from error (e.g. "bash: sslscan: command not found")
                m = re.search(r'(?:bash:.*?:\s*|)([\w.-]+):\s*command not found', err_lower, re.IGNORECASE)
                if m:
                    missing_bin = m.group(1)
                
                tool_info = TOOL_REGISTRY.get(missing_bin)
                
                # If it's not in the registry, try AI discovery
                if not tool_info:
                    tool_info = self.tools.discover_tool(missing_bin)
                
                if tool_info and "install" in tool_info:
                    install_cmd = self._clean_command(tool_info["install"])
                    # PEP 668 bypass for pip
                    for pip in ["pip install", "pip3 install"]:
                        if pip in install_cmd and "--break-system-packages" not in install_cmd:
                            install_cmd = install_cmd.replace(
                                pip, f"{pip} --break-system-packages"
                            )
                    self.log.info(f"Ghost Protocol: Installing missing binary '{missing_bin}'...")
                    if self.tools.remote:
                        self.tools.remote.execute(install_cmd, timeout=300)
                    else:
                        import subprocess
                        subprocess.run(install_cmd, shell=True, timeout=180)
                    self.tools._failed_cache.pop(missing_bin, None)
                    self.tools._installed_cache.discard(missing_bin)
                    # Clear circuit breaker so the retry is not blocked by dedup
                    cmd_history.discard(normalized)
                    continue

            # ── Step 2: Syntax error → AI repair ─────────────────────────────
            syntax_patterns = [
                "flag provided but not defined", "syntax error", "incorrect usage",
                "invalid option", "unknown argument", "not supported", "invalid source",
                "unrecognized option", "unrecognized",
            ]
            network_error_patterns = [
                "could not resolve", "connection refused", "no route to host",
                "network unreachable", "timed out", "connection reset",
                "recv failure", "empty reply from server", "tcp rst",
                "429 too many requests", "rate limit",
            ]

            is_syntax_error = any(p in combined_output for p in syntax_patterns)
            is_network_error = any(p in combined_output for p in network_error_patterns)
            is_unfixable = result.exit_code in NETWORK_UNFIXABLE_EXITS or is_network_error

            if is_syntax_error and not is_unfixable:
                self.log.info(f"Ghost Protocol: Syntax error in '{tool}'. Invoking AI rewriter...")
                diag_prompt = (
                    f"Command failed on Linux VPS. Fix the syntax error only.\n"
                    f"COMMAND: {current_command}\n"
                    f"EXIT CODE: {result.exit_code}\n"
                    f"STDERR: {result.stderr[:400]}\n\n"
                    f"Do NOT add -v or --verbose if -silent is present. "
                    f"Return ONLY raw JSON:\n"
                    f'{{ "heal_cmd": "install command or null", '
                    f'"retry_cmd": "corrected command", '
                    f'"explanation": "reason" }}'
                )
                try:
                    import json as _json
                    resp = self.think(diag_prompt)
                    m = re.search(r'\{[^{}]*"retry_cmd"[^{}]*\}', resp, re.DOTALL)
                    if m:
                        fix = _json.loads(m.group(0))
                        heal_cmd = fix.get("heal_cmd", "")
                        retry_cmd = fix.get("retry_cmd", "")
                        if heal_cmd and str(heal_cmd).lower() not in ("null", "none", ""):
                            if self.tools.remote:
                                self.tools.remote.execute(self._clean_command(heal_cmd))
                        if retry_cmd and len(retry_cmd) < 500:
                            current_command = self._clean_command(retry_cmd)
                            continue
                except Exception as e:
                    self.log.error(f"Ghost Protocol AI repair failed: {e}")

            break  # No more repair strategies

        return result

    def _is_false_positive(self, detail: str, response_body: str = "",
                             baseline_size: int = 0) -> bool:
        """Heuristic filter for SPA / CDN false positives."""
        if baseline_size and len(response_body) == baseline_size:
            return True
        # Don't flag NEXT_PUBLIC_ env vars as secret exposures
        if "NEXT_PUBLIC_" in response_body and not re.search(
            r'(?:PASSWORD|SECRET|TOKEN|KEY|API_KEY)\s*=\s*\S+', response_body, re.IGNORECASE
        ):
            return True
        return False

    @abstractmethod
    def run(self) -> dict:
        """Execute this agent's phase. Returns summary dict."""
        pass
