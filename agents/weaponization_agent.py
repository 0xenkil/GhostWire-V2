import json
import re
from pathlib import Path
from agents.base_agent import BaseAgent
from utils.display import section, info, warning, success
from config import USE_REMOTE_VPS

class WeaponizationAgent(BaseAgent):
    """
    Phase 3: Weaponization and Delivery (PoC Validation Engine)
    Generates dynamic proof-of-concept exploits for discovered vulnerabilities
    and executes them in a non-destructive manner to prove impact without false positives.
    """

    def _preflight(self) -> tuple[bool, str]:
        """Pre-flight: ensure exploitation completed."""
        # Check phase_data first (primary), then fall back to phase status + findings
        exploit_data = self.store.get_phase_data(self.session.engagement_id, "exploitation")
        if exploit_data is not None:
            return True, ""

        # Fallback: exploitation may have stored findings without phase_data
        exploit_status = self.store.get_phase_status(self.session.engagement_id, "exploitation")
        if exploit_status == "complete":
            return True, ""

        # Also check if there are ANY findings from the exploitation phase
        all_findings = self.store.get_all_findings(self.session.engagement_id)
        exploit_findings = [f for f in all_findings if f.get("phase") == "exploitation"]
        if exploit_findings:
            return True, ""

        return False, "Exploitation phase has no data. Cannot weaponize without findings."

    def run(self) -> dict:
        section("PHASE 4 — Weaponization & PoC Validation")
        self.store.set_phase_status(self.session.engagement_id, "weaponization", "running")

        roe = self.session.rules_of_engagement
        results = {"proven_exploits": []}

        if not roe.get("allow_exploitation", True):
            warning("ROE does not permit active exploitation. Skipping PoC generation.")
            self.store.set_phase_status(
                self.session.engagement_id, "weaponization", "skipped",
                "ROE prohibits active exploitation"
            )
            return {"skipped": "Exploitation disabled by ROE"}

        # Gather all findings from previous phases
        all_findings = self.store.get_all_findings(self.session.engagement_id)
        
        # ── Exploitable finding filter ─────────────────────────────────────────
        # Only pick findings that represent REAL attack surface, not recon noise.
        # These type prefixes are informational/recon metadata — NOT exploits:
        NOISE_TYPES = {
            "ai_dynamic_recon",   # whatweb/nikto/sslscan stdout dumps
            "tech_stack",         # "SPA Framework: React" — not a vuln
            "rate_limited",       # HTTP 429 detection — defensive, not offensive
            "open_port",          # Port listing from nmap — not a vuln
            "dns_record",         # DNS recon output
            "whois",              # WHOIS data
            "engagement_plan",    # Setup metadata
            "objectives_assessment",  # AI narrative assessment
            "security_header_present",  # Good security header found
            "network_defense",    # TCP RST detection
        }
        # Only weaponize if finding type looks like an actual exploitable class
        EXPLOIT_TYPE_KEYWORDS = [
            "sql", "xss", "lfi", "rfi", "rce", "ssrf", "ssti", "xxe",
            "injection", "traversal", "path", "exposure", "disclosure",
            "upload", "deserialization", "misconfig", "cors_misconfig",
            "vulnerability", "missing_security_header", "ssl_weakness",
            "discovered_path", "waf_discovered", "captcha_detected",
            "web_vulnerability", "proven_", "nuclei", "credential",
        ]
        exploitable_findings = []
        for f in all_findings:
            sev = f.get("severity", "").lower()
            typ = f.get("type", "").lower()
            if not typ:
                typ = f.get("finding_type", "").lower()

            # Skip noise types entirely regardless of severity
            if any(typ == noise or typ.startswith(noise) for noise in NOISE_TYPES):
                continue

            # Must be high/critical, OR a recognized exploitable type keyword
            is_high_sev = sev in ["high", "critical"]
            is_exploitable_type = any(kw in typ for kw in EXPLOIT_TYPE_KEYWORDS)

            if is_high_sev or is_exploitable_type:
                exploitable_findings.append(f)

        if not exploitable_findings:
            info("No high/critical vulnerabilities found to weaponize. Generating standard payloads instead.")
            self._generate_standard_payloads(results)
        else:
            info(f"Found {len(exploitable_findings)} exploitable vulnerabilities. Synthesizing dynamic PoCs...")
            # Cap at top 3 to save time and API tokens during execution
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
        
        info(f"Synthesizing dynamic PoC for: {vuln_type}...")
        
        prompt = (
            f"You are the GHOSTWIRE V3 Engine. We found a vulnerability on {target}:\n"
            f"Type: {vuln_type}\nDetails: {vuln_detail}\n\n"
            f"Write a standalone Python 3 script to non-destructively exploit this vulnerability. "
            f"The script must attempt to extract benign proof (e.g., /etc/passwd, database version, or a callback). "
            f"Return ONLY the raw Python code. Do not include markdown blocks, explanations, or backticks. "
            f"Ensure it uses standard libraries (requests, socket, urllib) and prints 'VULN_PROVEN: <data>' on success."
        )
        
        script_code = self.think(prompt).strip()
        # Clean up any markdown formatting if the AI hallucinated it
        if script_code.startswith("```"):
            script_code = re.sub(r"^```python\n?", "", script_code)
            script_code = re.sub(r"^```\n?", "", script_code)
            script_code = re.sub(r"```$", "", script_code).strip()

        # Save script locally
        safe_name = re.sub(r'[^a-zA-Z0-9]', '_', vuln_type).lower()[:20]
        script_name = f"poc_{safe_name}.py"
        local_script_path = self.session.results_dir / "raw" / script_name
        local_script_path.write_text(script_code, encoding="utf-8")
        
        info(f"Generated PoC script: {script_name}. Executing...")

        # Execute script securely
        if USE_REMOTE_VPS and self.tools.remote:
            remote_script_path = f"/tmp/{script_name}"
            self.tools.remote.upload_content(script_code, remote_script_path)
            exit_code, out, err = self.tools.remote.execute(f"python3 {remote_script_path}", timeout=45)
            combined_out = out + err
        else:
            r = self.safe_run_tool("python", f"python {local_script_path}", target)
            combined_out = r.stdout + r.stderr

        # Check for proof of successful exploitation
        if "VULN_PROVEN" in combined_out or "root:x:0" in combined_out or "SQL syntax" in combined_out:
            success(f"[PROVEN] Exploit successful for {vuln_type}!")
            self.add_finding(f"proven_{vuln_type}", target, f"PoC Execution Output: {combined_out[:500]}", "critical")
            results["proven_exploits"].append(vuln_type)
        else:
            warning(f"PoC execution failed or was not conclusive for {vuln_type}.")

    def _generate_standard_payloads(self, results: dict):
        # EICAR test file (industry-standard non-malicious AV test)
        eicar = r'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*'
        eicar_path = self.session.results_dir / "raw" / "eicar_test.txt"
        eicar_path.write_text(encoding="utf-8", data=eicar)
        info(f"EICAR test file created at: {eicar_path}")
        results["eicar_path"] = str(eicar_path)
        self.add_finding("test_payload", self.session.target,
                         "EICAR test file prepared for AV detection testing", "info")

        # NEW: probe the discovered paths from gobuster with python requests
        all_findings = self.store.get_all_findings(self.session.engagement_id)
        discovered_paths = [f["detail"] for f in all_findings if f.get("type") == "discovered_path" or f.get("finding_type") == "discovered_path"]
        target = self.session.target

        for path_detail in discovered_paths[:5]:  # e.g. "/~admin (HTTP 301)"
            path = path_detail.split(" ")[0]
            probe_cmd = (
                f"python3 -c \"import urllib.request; "
                f"try: "
                f"req = urllib.request.Request('https://{target}{path}', headers={{'User-Agent': 'Mozilla/5.0'}}); "
                f"r = urllib.request.urlopen(req, timeout=10); "
                f"print(f'STATUS: {{r.status}} | BODY: {{r.read(200).decode(\\'utf-8\\', errors=\\'ignore\\')}}'); "
                f"except Exception as e: print(f'ERROR: {{e}}')\""
            )
            r = self.safe_run_tool("python3", probe_cmd, target)
            if r.stdout and ("STATUS:" in r.stdout or "ERROR:" in r.stdout):
                self.add_finding("path_probe", target, 
                                 f"{path}: {r.stdout[:500]}", "medium")
                results["path_probes"] = results.get("path_probes", [])
                results["path_probes"].append(path)
