import json
from agents.base_agent import BaseAgent
from utils.display import section, info, warning, success


class PersistenceAgent(BaseAgent):
    """
    Phase 5: Persistence and Lateral Movement
    In pentest mode: identifies and documents persistence mechanisms found
    In redteam mode: attempts non-destructive persistence verification
    """

    def _has_target_foothold(self) -> bool:
        """True only if we have evidence of actual command execution / login ON
        the target (a shell, valid creds, or a confirmed RCE). Host-level
        persistence probes are only meaningful with such a foothold."""
        try:
            findings = self.store.get_all_findings(self.session.engagement_id)
        except Exception as _e:
            self.log.debug(f"foothold check could not read findings: {_e}")
            return False
        foothold_types = {
            "valid_credential", "shell_access", "rce_confirmed", "initial_access"}
        rce_markers = (
            "rce", "remote code execution", "command execution",
            "reverse shell", "uid=", "/bin/sh", "/bin/bash")
        for f in findings:
            ftype = (f.get("type") or "").lower()
            if ftype in foothold_types:
                return True
            if ftype == "confirmed_vulnerability":
                detail = (f.get("detail") or "").lower()
                if any(k in detail for k in rce_markers):
                    return True
        return False

    def _test_persistence_vectors(self, target: str) -> list[dict]:
        """
        Actively checks and tests persistence mechanisms in a non-destructive way.
        """
        tested_vectors = []

        # GATE: crontab -l, `test -w ~/.ssh/authorized_keys`, `test -w
        # /var/www/html` etc. execute on the LOCAL execution node (our
        # WSL/VPS box) — NOT on the target. Without a confirmed code-execution
        # foothold on the target they describe OUR OWN machine and produce
        # dangerously misleading "User has crontab access / web root writable"
        # findings. Skip them entirely until a foothold exists.
        if not self._has_target_foothold():
            info("[PERSISTENCE] No confirmed code-execution foothold on the target — "
                 "skipping host-level persistence probes (they would only describe the "
                 "local scanner box). Recording as theoretical.")
            self.add_finding(
                "persistence_info",
                target,
                "No target foothold (shell/credentials/RCE) was obtained, so host-level "
                "persistence (cron, SSH keys, web-root) is theoretical only and was NOT tested "
                "on the target.",
                "info")
            return tested_vectors

        # 1. Check for writable cron directories or crontab access
        info("[PERSISTENCE] Checking crontab and cron directories write access...")
        cron_check = self.safe_run_tool("bash", "crontab -l 2>&1", target)
        if cron_check.success:
            self.add_finding(
                "persistence_info",
                target,
                "User has crontab access.",
                "info")
            tested_vectors.append({"type": "cron", "status": "accessible"})
            # Test write access to crontab safely (adds test comment, checks,
            # and cleans up)
            cron_write_test = self.safe_run_tool(
                "bash",
                "(crontab -l 2>/dev/null; echo '# test_persistence') | crontab - && crontab -l | grep '# test_persistence' && (crontab -l | grep -v '# test_persistence' | crontab -)",
                target)
            if cron_write_test.success:
                self.add_finding(
                    "persistence_vector",
                    target,
                    "Verified write access to crontab (non-destructive test succeeded).",
                    "high")
                tested_vectors.append({"type": "cron", "status": "writable"})

        # 2. Check if .ssh directory and authorized_keys is writable
        info("[PERSISTENCE] Checking SSH authorized_keys write access...")
        ssh_check = self.safe_run_tool(
            "bash",
            "test -w ~/.ssh/authorized_keys && echo WRITABLE || echo NOT_WRITABLE",
            target)
        if ssh_check.success and "WRITABLE" in ssh_check.stdout:
            self.add_finding(
                "persistence_vector",
                target,
                "SSH authorized_keys file is writable.",
                "high")
            tested_vectors.append(
                {"type": "ssh_authorized_keys", "status": "writable"})

        # 3. Check for writable web root or upload paths (if we can find where
        # web application is)
        info("[PERSISTENCE] Checking web root and upload directory write access...")
        web_roots = ["/var/www/html", "/var/www", "/usr/share/nginx/html"]
        for root in web_roots:
            write_test = self.safe_run_tool(
                "bash", f"test -w {root} && echo WRITABLE || echo NOT_WRITABLE", target)
            if write_test.success and "WRITABLE" in write_test.stdout:
                self.add_finding(
                    "persistence_vector",
                    target,
                    f"Web root directory '{root}' is writable.",
                    "high")
                tested_vectors.append(
                    {"type": "web_root", "path": root, "status": "writable"})
                break

        # 4. Check for active file upload endpoints in existing findings
        findings = self.store.get_all_findings(self.session.engagement_id)
        upload_endpoints = [
            f for f in findings if "upload" in f.get(
                "detail", "").lower()]
        for ep in upload_endpoints:
            self.add_finding(
                "persistence_opportunity",
                target,
                f"Web file upload endpoint detected: {
                    ep.get('detail')}",
                "medium")
            tested_vectors.append(
                {"type": "file_upload_endpoint", "detail": ep.get("detail")})

        return tested_vectors

    async def run(self) -> dict:
        section("PHASE 5 - Persistence & Lateral Movement")
        self.store.set_phase_status(
            self.session.engagement_id,
            "persistence",
            "running")

        roe = self.session.rules_of_engagement
        target = self.session.target

        # SMB lateral movement check
        findings = self.store.get_all_findings(self.session.engagement_id)

        # AI analysis of persistence opportunities
        info("Asking AI to identify persistence and lateral movement opportunities...")
        persist_prompt = (
            f"Target: {target}. Mode: {self.session.mode}.\n"
            f"Findings so far: {json.dumps(findings[:15],
                                           default=str)[:2000]}\n"
            f"What persistence mechanisms should be checked? "
            f"What lateral movement paths are possible? "
            f"Provide at most 3 commands to verify these (e.g. crontab -l). "
            f"CRITICAL: Do NOT use bash pipes (|), &&, or ; to chain commands. Execute one tool per command. "
            f"Return ONLY a valid JSON array of strings. "
            f"Example: [\"crontab -l\", \"ls -la /etc/cron.d\"]"
        )
        ai_analysis_raw = self.think(persist_prompt)
        ai_analysis = ai_analysis_raw

        # Parse commands from AI response
        from core.robust_parser import extract_json_list
        try:
            # Use robust_parser to safely extract JSON arrays
            commands = extract_json_list(ai_analysis_raw)
        except Exception as e:
            self.log.error(f"Failed to parse AI persistence plan: {e}")
            self.log.debug(f"Raw AI response: {ai_analysis_raw}")
            commands = []

        # Architectural 4: Run actual validation commands
        if roe.get("allow_exploitation"):
            # Actively test persistence mechanisms
            tested_vectors = self._test_persistence_vectors(target)
            if tested_vectors:
                info(
                    f"[PERSISTENCE] Successfully tested {
                        len(tested_vectors)} persistence vectors.")

            # Architectural check: 'ssh_cmd' currently only runs on the scanner box.
            # We must explicitly separate this from target-bound execution.
            creds = [f for f in findings if f["type"] == "valid_credential"]
            if creds:
                # FUTURE: Implement TargetWSLExecutor for real target interaction.
                # For now, we block this to prevent scanner-box pollution.
                warning("System credentials found, but direct target SSH execution is not yet isolated from scanner box. Skipping automated validation to prevent self-infection.")
            if commands:
                info(
                    f"Executing {
                        len(commands)} persistence verification commands...")
                for cmd in commands:
                    info(f"Running: {cmd}")
                    primary_tool = self._extract_primary_tool(cmd)
                    if not primary_tool:
                        primary_tool = "unknown"
                    r = self.safe_run_tool(primary_tool, cmd, target)
                    if r.success:
                        self.add_finding(
                            "persistence_verified", target, f"Verified: {cmd}", "info")
                        success(f"Successfully verified: {cmd}")
                    else:
                        self.log.debug(f"Command failed: {cmd} - {r.stderr}")
            elif not tested_vectors:
                info(
                    "No specific persistence commands suggested by AI. Passive analysis only.")

        self.bus.publish("persistence", "objectives", {
            "event": "persistence_complete",
            "findings": findings,
            "ai_analysis": ai_analysis
        })

        self.store.set_phase_status(
            self.session.engagement_id, "persistence", "complete",
            (ai_analysis or "")[:200]
        )

        success("Persistence phase complete.")
        return self.finish_phase({
            "ai_analysis": ai_analysis,
            "findings": findings
        })
