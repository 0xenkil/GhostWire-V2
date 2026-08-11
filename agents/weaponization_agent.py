import re
import config_paths
from agents.base_agent import BaseAgent
from utils.display import section, info, warning, success
from utils.poc_customizer import PoCCustomizer


class WeaponizationAgent(BaseAgent):
    """
    Phase 3: Weaponization and Delivery (PoC Validation Engine)
    Generates dynamic proof-of-concept exploits for discovered vulnerabilities
    and executes them in a non-destructive manner to prove impact without false positives.
    """

    def _preflight(self) -> tuple[bool, str]:
        """Pre-flight: ensure exploitation completed and core tools available."""
        self.log.info("Performing weaponization pre-flight checks...")

        # Check core tools
        core_tools = ["gcc", "python3", "pip3", "git", "curl"]
        missing = []
        for tool in core_tools:
            if not self.tools.ensure_installed(tool):
                missing.append(tool)

        if missing:
            self.log.warning(
                f"Critical weaponization tools missing: {
                    ', '.join(missing)}")

        # Check phase_data first (primary), then fall back to phase status +
        # findings
        exploit_data = self.store.get_phase_data(
            self.session.engagement_id, "exploitation")
        if exploit_data is not None:
            return True, ""

        # Fallback: exploitation may have stored findings without phase_data
        exploit_status = self.store.get_phase_status(
            self.session.engagement_id, "exploitation")
        if exploit_status == "complete":
            return True, ""

        # Also check if there are ANY findings from the exploitation phase
        all_findings = self.store.get_all_findings(self.session.engagement_id)
        exploit_findings = [
            f for f in all_findings if f.get("phase") == "exploitation"]
        if exploit_findings:
            return True, ""

        return False, "Exploitation phase has no data. Cannot weaponize without findings."

    def _is_false_positive(self, finding_detail: str,
                           response_body: str, baseline_size: int = 0) -> bool:
        """Filter out common false positives from AI PoC execution."""
        body_lower = response_body.lower()

        # WAF block page patterns
        WAF_BLOCK_PATTERNS = [
            "access denied", "cloudflare ray", "request blocked", "mod_security",
            "403 forbidden", "you have been blocked", "sucuri", "incapsula",
            "web application firewall", "security violation", "blocked by", "mitigated"
        ]
        if any(w in body_lower for w in WAF_BLOCK_PATTERNS):
            return True

        # Common false positive networks/error patterns
        if "unable to connect" in body_lower or "timed out" in body_lower:
            return True
        if "host maximum execution time" in body_lower:
            return True

        # Non-WordPress FP guards (Laravel, Django, Express, etc.)
        for pattern in [
            "symfony\\component\\httpkernel\\exception", "methodnotallowedhttpexception",
            "django.http", "disallowedhost", "csrf verification failed", "cannot get /",
            "invalid request", "400 bad request", "404 not found", "cannot post /"
        ]:
            if pattern in body_lower:
                if any(k in finding_detail.lower()
                       for k in ["sql", "rce", "lfi", "xxe"]):
                    return True

        # Strict HTML drop for data/API vulnerabilities
        if "<!doctype html" in body_lower or "<html" in body_lower:
            if any(k in finding_detail.lower()
                   for k in ["sql", "rce", "lfi", "xxe", "ssrf"]):
                if not any(proof in body_lower for proof in [
                           "root:x:0", "uid=0", "syntax error", "mysql_fetch"]):
                    return True

        # Simple baseline check - if the proof response is exactly the baseline
        # size, it might be the homepage
        if baseline_size > 0 and abs(len(response_body) - baseline_size) < 10:
            return True
        return False

    async def run(self) -> dict:
        section("PHASE 4 - Weaponization & PoC Validation")
        self.store.set_phase_status(
            self.session.engagement_id,
            "weaponization",
            "running")

        roe = self.session.rules_of_engagement
        results = {"proven_exploits": []}

        if not roe.get("allow_exploitation", True):
            warning(
                "ROE does not permit active exploitation. Skipping PoC generation.")
            self.store.set_phase_status(
                self.session.engagement_id, "weaponization", "skipped",
                "ROE prohibits active exploitation"
            )
            return {"skipped": "Exploitation disabled by ROE"}

        # Gather all findings from previous phases
        all_findings = self.store.get_all_findings(self.session.engagement_id)

        # ── Load Dynamic Rules ───────────────────────────────────────────────
        rules = self._load_rules("weaponization")
        WEAPONIZABLE_TYPES = set(rules.get("weaponizable_types", [
            "sql_injection", "sqli", "xss", "lfi", "rfi", "rce", "ssrf", "ssti", "xxe",
            "sensitive_data", "directory_listing", "backup_file", "git_repo",
            "exposed_config", "env_file", "unauthorized_access",
            "idor", "broken_auth", "csrf", "open_redirect", "jwt_weakness",
            "cors_misconfig", "subdomain_takeover",
            "vulnerability", "web_vulnerability",
            "cve", "ai_dynamic_exploit"
        ]))

        # Nikto noise: informational Nikto lines that pass 'web_vulnerability' type
        # but contain no exploitable content - skip these regardless of type
        # match.
        DETAIL_NOISE_PATTERNS = rules.get("noise_patterns", [
            "uncommon header", "x-hcdn-request-id", "alt-svc", "maximum execution time",
            "items checked", "target ip", "target hostname", "1 host(s) tested",
            "<!doctype html", "<html", "<body",
            # Header-only findings are never weaponizable on their own
            "missing csp", "missing hsts", "missing x-frame", "missing x-content",
            "missing permissions-policy", "core security headers present",
        ])

        SEV_ORDER = {
            "critical": 0,
            "high": 1,
            "medium": 2,
            "low": 3,
            "info": 4}

        exploitable_findings = []
        for f in all_findings:
            sev = f.get("severity", "").lower()
            typ = f.get("type", "") or f.get("finding_type", "")
            typ_lower = typ.lower()
            detail = (f.get("detail", "") or "").lower()

            # Must match a weaponizable type
            if not any(wt in typ_lower for wt in WEAPONIZABLE_TYPES):
                continue

            # Skip Nikto informational noise even if it matches
            # web_vulnerability
            if any(pat in detail for pat in DETAIL_NOISE_PATTERNS):
                continue

            # web_vulnerability only gets PoC if it's actually high/critical,
            # OR it's medium but has real exploit keywords in the detail.
            MEDIUM_EXPLOIT_KEYWORDS = [
                "clickjack", "x-frame", "cors", "open redirect", "csrf",
                "injection", "traversal", "disclosure", "exposure", "header missing",
            ]
            if typ_lower == "web_vulnerability" and sev not in (
                    "high", "critical"):
                if sev != "medium" or not any(
                        kw in detail for kw in MEDIUM_EXPLOIT_KEYWORDS):
                    continue

            # ai_dynamic_exploit: skip if output is homepage HTML (pre-fix DB
            # records)
            if typ_lower == "ai_dynamic_exploit":
                if any(x in detail for x in [
                       "<!doctype", "wp-content", "litespeed", "<html"]):
                    continue

            # http_request_smuggling: skip pre-fix false positives (WP admin
            # keyword match)
            if typ_lower == "http_request_smuggling":
                if "wp-content" in detail or "<!doctype" in detail or "downgrade" in detail:
                    # "downgrade" was the old false-positive wording
                    continue

            exploitable_findings.append(f)

        # Sort by severity so the top-3 cap picks the most impactful findings
        # first
        exploitable_findings.sort(
            key=lambda x: SEV_ORDER.get(
                x.get(
                    "severity",
                    "info").lower(),
                4))

        if not exploitable_findings:
            info(
                "No confirmed exploitable vulnerabilities found. Generating standard payloads instead.")
            self._generate_standard_payloads(results)
        else:
            info(
                f"Found {
                    len(exploitable_findings)} confirmed exploitable findings. Synthesizing dynamic PoCs...")
            # Cap at top 3 highest-severity findings
            for finding in exploitable_findings[:3]:
                self._synthesize_and_execute_poc(finding, results)

        self.bus.publish("weaponization", "persistence", {
            "event": "weaponization_complete",
            "results": results
        })

        self.store.set_phase_status(
            self.session.engagement_id, "weaponization", "complete",
            f"Validated {len(results['proven_exploits'])} exploits."
        )
        success("Weaponization & Validation phase complete.")
        return results

    def _synthesize_and_execute_poc(self, finding: dict, results: dict):
        target = self.session.target
        vuln_type = finding.get("type", "Unknown")
        vuln_detail = finding.get("detail", "")
        # rules loaded but not needed here - logic is inline

        info(
            f"Synthesizing PoC for: {vuln_type} ({
                finding.get(
                    'severity',
                    '?').upper()})...")

        # ── Step 1: Try template-driven PoC (reliable, FP-guarded) ───────────
        from utils.poc_templates import get_poc_template
        template, defaults = get_poc_template(vuln_type, vuln_detail)

        if template:
            # ──── NEW: Customize template params based on recon data ────
            customizer = PoCCustomizer(
                self.session.engagement_id, self.store, self.log)
            try:
                custom_params = customizer.customize_poc_params(
                    target, vuln_type, vuln_detail)
            except Exception as customizer_err:
                warning(
                    f"PoC customization failed, falling back to template defaults: {customizer_err}")
                custom_params = {
                    "target": target,
                    "endpoints_to_test": ["/"],
                    "headers_to_check": [],
                    "framework": "unknown",
                    "hosting": "unknown",
                    "reason": f"Fallback after customization error: {customizer_err}",
                }

            # Merge: custom params from recon override defaults
            defaults.update(custom_params)

            info(
                f"PoC customized based on recon: {
                    custom_params.get(
                        'reason',
                        'target profiling')}")

            # Ask AI to fill in target-specific params (not write exploit code)
            param_prompt = (
                f"We're testing {target} for {vuln_type}.\n"
                f"Finding detail: {vuln_detail}\n"
                f"Target profile: {
                    custom_params.get(
                        'framework',
                        'unknown')} on {
                    custom_params.get(
                        'hosting',
                        'unknown')}\n\n"
                f"We need these parameters for our exploit template:\n"
                f"- path: The URL path most likely vulnerable (e.g. /search, /api/v1/users, /). Default: {
                    defaults.get(
                        'path',
                        '/')}\n"
                f"- param: The query parameter name most likely injectable. Default: {
                    defaults.get(
                        'param',
                        'id')}\n"
            )
            if "credential" in vuln_type.lower() or "valid_credential" in vuln_type.lower():
                # Extract creds from finding detail
                param_prompt += (
                    f"- username: extracted username. Default: {
                        defaults.get(
                            'username', 'admin')}\n"
                    f"- password: extracted password. Default: {
                        defaults.get(
                            'password', 'admin')}\n"
                    f"- login_path: login endpoint. Default: {
                        defaults.get(
                            'login_path',
                            '/wp-login.php')}\n"
                )
            param_prompt += (
                "\nReturn ONLY a JSON object with these keys. Nothing else. Example: "
                '{"path": "/search", "param": "q"}'
            )

            try:
                ai_params_raw = self.think(param_prompt).strip()
                from core.robust_parser import extract_json_object
                ai_params = extract_json_object(ai_params_raw)
            except Exception as e:
                import logging as __logging_tmp
                __logging_tmp.getLogger(__name__).debug(
                    f"Silenced exception: {e}")
                ai_params = {}

            # Merge: AI overrides defaults, but target always set
            params = {**defaults, **ai_params}
            target_url = f"https://{target}" if "://" not in target else target
            params["target"] = target_url

            # Safe substitution: replace only known {key} placeholders.
            # str.format(**params) crashes on any { or } in PoC code (dict literals,
            # JSON bodies, f-strings, etc.).
            script_code = template
            for key, val in params.items():
                script_code = script_code.replace(f"{{{key}}}", str(val))
            poc_source = "template"
        else:
            # ── Step 2: AI-generated fallback (no template match) ────────────
            # First, customize params from recon data to give AI better context
            customizer = PoCCustomizer(
                self.session.engagement_id, self.store, self.log)
            try:
                custom_params = customizer.customize_poc_params(
                    target, vuln_type, vuln_detail)
            except Exception as customizer_err:
                warning(
                    f"PoC customization failed, using minimal fallback context: {customizer_err}")
                custom_params = {
                    "target": target,
                    "endpoints_to_test": ["/"],
                    "framework": "unknown",
                    "hosting": "unknown",
                    "reason": f"Fallback after customization error: {customizer_err}",
                }

            framework = custom_params.get("framework", "unknown")
            hosting = custom_params.get("hosting", "unknown")
            endpoints = custom_params.get("endpoints_to_test", ["/"])

            # Build specific verification guidance based on vulnerability type
            verification_hints = {
                "disclosure": "Check response headers (Server, X-Powered-By, X-Version, etc) and HTTP error pages for leaked version/tech info",
                "information_disclosure": "Look for version numbers, software names, framework identifiers in headers and error responses",
                "header": "Parse response headers for any non-standard or sensitive headers like X-Internal-IP, X-Backend-IP, etc",
                "misconfiguration": "Test for debug endpoints, open admin paths, enabled debug modes in error pages",
                "debug": "Look for stack traces, verbose error messages, or debug information in responses",
                "xxe": "Check for XML parsing errors or entity expansion indicators (root:x:0 for XXE blind)",
                "ssrf": "Look for responses containing internal metadata (AWS, GCP, Azure metadata), localhost responses, or unusual headers",
                "open_redirect": "Check if redirects occur to unexpected locations; verify Location header changes",
                "traversal": "Test if file contents (like /etc/passwd or config files) are returned in responses",
            }

            # Find the most relevant hint
            verification_hint = ""
            for key, hint in verification_hints.items():
                if key in vuln_type.lower() or key in vuln_detail.lower():
                    verification_hint = f"\nVERIFICATION FOCUS: {hint}"
                    break

            if not verification_hint:
                # Default generic hint
                verification_hint = "\nVERIFICATION FOCUS: Look for specific indicators unique to this vulnerability (not generic 404/homepage responses)"

            prompt = (
                f"You are the GHOSTWIRE V5 PoC Engine. Generate a PRECISE exploit for this finding:\n\n"
                f"TARGET: {target}\n"
                f"VULNERABILITY TYPE: {vuln_type}\n"
                f"SEVERITY: {finding.get('severity', 'high').upper()}\n"
                f"FINDING DETAIL: {vuln_detail}\n"
                f"FRAMEWORK: {framework}\n"
                f"HOSTING: {hosting}\n"
                f"ENDPOINTS: {', '.join(endpoints[:10])}\n\n"
                f"YOUR TASK: Write ONLY Python 3 code that:\n"
                f"1. Uses the finding detail to target SPECIFIC endpoints/parameters (not random fuzzing)\n"
                f"2. Tests the exact vulnerability type discovered\n"
                f"3. Produces hardened proof with SPECIFIC indicators (not generic 404/homepage check)\n"
                f"4. Returns 'VULN_PROVEN: <proof>' on success or 'NOT_PROVEN: <reason>' on failure\n\n"
                f"MUST-HAVE VERIFICATION:\n"
                f"- IF SQLi: Look for 'SQL syntax error', 'mysql', 'mariadb', 'postgresql', 'ora-', or time-based delay (SLEEP(5))\n"
                f"- IF XSS: Check for reflected payload (not homepage/404/generic response)\n"
                f"- IF LFI: Verify /etc/passwd, /etc/hosts, or config file CONTENT (not 404)\n"
                f"- IF RCE: Look for command execution indicators (uid=, gid=, hostname output)\n"
                f"- IF SSRF: Check for metadata responses (169.254.169.254) or internal IP responses\n"
                f"- IF DISCLOSURE: Look for version numbers, API keys, secrets (not generic Server header)\n"
                f"- IF AUTH: Test actual credentials or auth bypass (not just 200 status)\n\n"
                f"RULES:\n"
                f"- Import only: requests, urllib3, socket, ssl, subprocess, re, json, base64\n"
                f"- Use: requests.get(url, verify=False, timeout=15, allow_redirects=False)\n"
                f"- Handle SSL: import urllib3; urllib3.disable_warnings()\n"
                f"- NEVER check for homepage HTML as proof (check '<!doctype', 'wp-content', etc as NEGATIVE)\n"
                f"- Compare against baseline responses - if normal target returns same, it's a FP\n"
                f"- CRITICAL: Use strict `assert` statements in your code to verify the proof (e.g. `assert 'root:x:0' in response.text`).\n"
                f"- IMPORTANT: Wrap your main logic in a try-except block. On exception, print 'NOT_PROVEN: ' followed by the exception.\n"
                f"- Return ONLY raw Python code, NO explanations, NO markdown"
            )
            script_code = self.think(prompt).strip()
            # Strip markdown code fences
            if script_code.startswith("```"):
                script_code = re.sub(
                    r"^```(?:python|py)?\s*\n?", "", script_code)
                script_code = re.sub(r"\n?```\s*$", "", script_code).strip()
            poc_source = "ai_generated"

        # ── Guardian Validation (Pre-Execution) ───────────────────
        if self.validation:
            is_ok, fixed_code, reason = self.validation.validate_python(
                script_code)
            if not is_ok:
                warning(
                    f"Guardian blocked sketchy PoC ({poc_source}): {reason}")
                return  # Skip this PoC
            if fixed_code != script_code:
                info(f"Guardian repaired PoC ({poc_source}): {reason}")
                script_code = fixed_code

        # ── Save & Execute ───────────────────────────────────────────────────
        safe_name = re.sub(r'[^a-zA-Z0-9]', '_', vuln_type).lower()[:20]
        script_name = f"poc_{safe_name}.py"
        local_script_path = self.session.results_dir / "raw" / script_name
        local_script_path.write_text(script_code, encoding="utf-8")

        info(f"Generated PoC ({poc_source}): {script_name}. Executing...")

        # Execute with timeout and stability fallbacks (Ghost Protocol)
        if self.tools.remote:
            remote_script_path = f"{config_paths.WSL_TEMP_DIR}/{script_name}"
            self.tools.remote.upload_content(script_code, remote_script_path)
            # Use python_payload virtual tool in safe_run_tool for VPS
            # stabilization
            r = self.safe_run_tool(
                "python_payload",
                f"python3 {remote_script_path}",
                target)
        else:
            r = self.safe_run_tool(
                "python3", f"python3 \"{local_script_path}\"", target)

        # BUG-17: Only check stdout for VULN_PROVEN - stderr is infrastructure noise
        # and must NOT cause rejection of a valid proof in stdout.
        proof_stdout = r.stdout
        combined_out = r.stdout + r.stderr  # kept for legacy checks only

        # ── Validate proof ───────────────────────────────────────────────────
        # AI driven validation will be used below
        vuln_proven = False
        proven_data = ""

        # Establish baseline for FP detection
        recon_data = self.store.get_phase_data(
            self.session.engagement_id, "recon") or {}
        baseline_size = recon_data.get("baseline_size", 0)

        if "VULN_PROVEN:" in proof_stdout:
            match = re.search(r"VULN_PROVEN:\s*(.+)", proof_stdout)
            if match:
                proof_text = match.group(1).strip()

                # Use AI-driven robust FP detector
                if self._is_false_positive(
                        vuln_detail, response_body=proof_stdout, baseline_size=baseline_size):
                    warning(
                        "AI evaluation determined PoC output is a false positive or failure. Rejecting.")
                    vuln_proven = False
                elif len(proof_text) < 5:
                    warning("PoC output too short to be credible. Rejecting.")
                    vuln_proven = False
                else:
                    vuln_proven = True
                    proven_data = proof_text
        # P0-6 (WEAPON-SUBSTR-PROOF): the `root:x:0` / `SQL syntax` substring
        # elifs that minted vuln_proven=True from a bare marker are DELETED — a
        # substring in output is not measured proof. A PoC must self-report the
        # structured VULN_PROVEN: marker (above, gated by AI FP detection); the
        # actual proof token below comes from a MEASURED artifact differential.

        if vuln_proven:
            success(f"[PROVEN] Exploit successful for {vuln_type}!")

            _sev = "medium"
            _vtype_lower = vuln_type.lower()
            if any(k in _vtype_lower for k in [
                   "rce", "remote_code", "cmd_injection"]):
                _sev = "critical"
            elif any(k in _vtype_lower for k in ["sqli", "sql_injection"]):
                _sev = "critical"
            elif any(k in _vtype_lower for k in ["lfi", "path_traversal", "file_inclusion", "xxe", "ssrf"]):
                _sev = "high"
            elif any(k in _vtype_lower for k in ["directory_listing", "dir_listing", "backup"]):
                _sev = "medium"
            elif any(k in _vtype_lower for k in ["cors"]):
                _sev = "medium"
            elif any(k in _vtype_lower for k in ["open_redirect"]):
                _sev = "low"
            elif any(k in _vtype_lower for k in ["missing_header"]):
                _sev = "info"

            # P0-6: stamp a MEASURED artifact proof — the leaked content must be
            # PRESENT in the PoC output and ABSENT from the recon baseline. The
            # VULN_PROVEN: marker + AI FP check only decide whether to ATTEMPT the
            # proof; the ledger token is what makes it count as proven downstream.
            # No baseline captured -> stamp returns '' -> the finding is a lead.
            from core.proof import ProofContext
            _baseline_body = str(self.store.get("waf_baseline_body") or "")
            _pctx = ProofContext(
                control_response=_baseline_body,
                test_response=proof_stdout,
                canary=str(proven_data)[:200],
                command=script_name,
                notes=str(proven_data)[:400])
            self.add_finding(f"proven_{vuln_type}", target,
                             f"VULN_PROVEN: PoC script: {script_name}\nProof: {proven_data[:400]}", _sev,
                             proof_method="artifact_reflection", proof_ctx=_pctx)
            results["proven_exploits"].append({
                "type": vuln_type,
                "proof": proven_data[:200],
                "source": poc_source,
                "script": script_name
            })
        else:
            # Log what the PoC actually returned for debugging
            not_proven_match = re.search(
                r"NOT_PROVEN:\s*(.+)",
                combined_out) if combined_out else None
            reason = not_proven_match.group(
                1).strip() if not_proven_match else "No output"
            warning(f"PoC not conclusive for {vuln_type}: {reason[:100]}")

            # P0-6 (WEAPON-NUCLEI-CONFIRM): a nuclei TEMPLATE MATCH whose active
            # PoC did NOT prove is a LEAD, not a confirmed vulnerability — a
            # template hit is a signal to validate, never measured proof. It is
            # retagged nuclei_lead/info (and NOT added to proven_exploits) so it
            # is chased/validated, never counted as proven in the report.
            if vuln_type.lower() in ("vulnerability",) and finding.get(
                    "severity", "").lower() in ("critical", "high", "medium"):
                nuclei_detail = finding.get("detail", vuln_type)
                self.add_finding(
                    "nuclei_lead", target,
                    f"[Nuclei Template Match — UNVERIFIED LEAD, active PoC did not prove] "
                    f"{nuclei_detail}",
                    "info")
                self.log.info(
                    f"[NUCLEI LEAD] {nuclei_detail[:80]} recorded as an unverified lead.")

    def _generate_standard_payloads(self, results: dict):
        # EICAR test file (industry-standard non-malicious AV test)
        rules = self._load_rules("weaponization")
        eicar = rules.get(
            "eicar_string",
            r'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*')
        eicar_path = self.session.results_dir / "raw" / "eicar_test.txt"
        eicar_path.write_text(eicar, encoding="utf-8")
        info(f"EICAR test file created at: {eicar_path}")
        results["eicar_path"] = str(eicar_path)
        self.add_finding("test_payload", self.session.target,
                         "EICAR test file prepared for AV detection testing", "info")

        # Probe the discovered paths from gobuster with python requests
        all_findings = self.store.get_all_findings(self.session.engagement_id)
        discovered_paths = [
            f.get("detail", "") for f in all_findings
            if f.get("type") == "discovered_path" or f.get("finding_type") == "discovered_path"
        ]
        target = self.session.target

        for path_detail in discovered_paths[:5]:  # e.g. "/wp-admin (HTTP 200)"
            if not path_detail or " " not in path_detail:
                continue
            path = path_detail.split(" ")[0]
            # Skip /~username CDN wildcards - these are Hostinger /~ redirect noise,
            # not real directories. Probing them just confirms a 301 CDN
            # response.
            if path.startswith("/~"):
                continue
            # Skip paths that returned 301 only (likely CDN redirects, not real
            # content)
            if "HTTP 301" in path_detail or "HTTP 302" in path_detail:
                continue

            # BUG-10: Build a proper temp script instead of a fragile inline -c '...' command.
            # Inline shell quoting breaks on paths with special characters and
            # is unreadable.
            p_timeout = rules.get("path_probe_timeout", 10)
            p_ua = rules.get(
                "path_probe_user_agent",
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
            probe_url = f"https://{target}{path}"
            probe_script = (
                "import urllib.request, ssl, sys\n"
                f"url = {probe_url!r}\n"
                f"ua  = {p_ua!r}\n"
                f"timeout = {p_timeout}\n"
                "try:\n"
                "    ctx = ssl.create_default_context()\n"
                "    ctx.check_hostname = False\n"
                "    ctx.verify_mode = ssl.CERT_NONE\n"
                "    req = urllib.request.Request(url, headers={'User-Agent': ua})\n"
                "    r = urllib.request.urlopen(req, timeout=timeout, context=ctx)\n"
                "    body = r.read(200).decode('utf-8', errors='ignore')\n"
                "    print(f'STATUS: {r.status} | BODY: {body}')\n"
                "except Exception as e:\n"
                "    print(f'NOT_PROVEN: {e}')\n"
            )
            probe_script_name = f"{
                config_paths.WSL_TEMP_DIR}/gw_probe_{
                abs(
                    hash(path)) %
                100000}.py"
            if self.tools.remote:
                self.tools.remote.upload_content(
                    probe_script, probe_script_name)
                r = self.safe_run_tool(
                    "python_payload", f"python3 {probe_script_name}", target)
                self.tools.remote.execute(f"rm -f {probe_script_name}")
            else:
                local_probe = self.session.results_dir / "raw" / \
                    f"probe_{path.lstrip('/').replace('/', '_')}.py"
                local_probe.write_text(probe_script, encoding="utf-8")
                r = self.safe_run_tool(
                    "python3", f"python3 \"{local_probe}\"", target)

            if r.stdout and ("STATUS:" in r.stdout or "ERROR:" in r.stdout):
                self.add_finding("path_probe", target,
                                 f"{path}: {r.stdout[:500]}", "low")
                results["path_probes"] = results.get("path_probes", [])
                results["path_probes"].append(path)
