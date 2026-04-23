import json
import re
from agents.base_agent import BaseAgent
from utils.display import section, info, warning, success
from utils.validator import is_valid_target
from config import USE_REMOTE_VPS, HONEYPOT_PORT_THRESHOLD
import os


class ReconAgent(BaseAgent):

    def _verify_subdomain(self, subdomain: str, wildcard_ips: set,
                           is_cdn: bool = False, silent: bool = False) -> tuple[bool, str | None]:
        """
        Post-enumeration filter to eliminate wildcard DNS / CDN noise.
        Uses the parent TARGET for scope enforcement, not the subdomain itself.
        """
        # Scope check uses parent domain so sub.target.com passes correctly
        # Use silent=True on the tool calls if requested to avoid flooding terminal
        r_dig = self.safe_run_tool(
            "dig", f"dig @1.1.1.1 +short {subdomain}", self.session.target,
            silent=silent
        )
        out = r_dig.stdout
        resolved_ips = set(
            line.strip() for line in out.strip().splitlines()
            if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', line.strip())
        )

        if not resolved_ips:
            return False, None

        # If it resolves to the same IPs as the wildcard canary → it's fake
        if wildcard_ips and (resolved_ips == wildcard_ips or
                              resolved_ips.issubset(wildcard_ips)):
            return False, None

        # Clean subdomain string just in case it contains scheme or leading dots
        clean_sub = re.sub(r'^https?://', '', subdomain).strip('/').lstrip('.')
        
        # HTTP verification — check for CDN-specific error pages
        r = self.safe_run_tool(
            "curl",
            f"curl -sI --max-time 5 http://{clean_sub}",
            self.session.target,
            silent=silent
        )
        combined = (r.stdout + r.stderr).upper()
        
        # Vercel / Cloudflare CDN 404-equivalents
        if any(x in combined for x in ["DEPLOYMENT_NOT_FOUND", "DEPLOYMENT_NOT_READY",
                                         "ERR_NGROK_3200", "NO_RESPONSE", "DIRECT_ACCESS_FORBIDDEN"]):
            return False, None

        if not r.success:
            return False, None

        return True, list(resolved_ips)[0]

    def run(self) -> dict:
        section("PHASE 2 — Reconnaissance")
        self.store.set_phase_status(self.session.engagement_id, "recon", "running")

        target = self.session.target
        results = {}

        # 1. WHOIS (with RDAP fallback for ccTLDs like .lk that block standard WHOIS)
        info("Running WHOIS...")
        r = self.safe_run_tool("whois", f"whois {target}", target)
        results["whois"] = r.parsed
        whois_text = json.dumps(r.parsed)[:500]
        if r.success and r.parsed and whois_text != "{}":
            self.add_finding("whois", target, whois_text, "info")
        else:
            # RDAP fallback — works for .lk and other restricted ccTLDs
            info(f"WHOIS returned empty for {target}. Trying RDAP fallback...")
            rdap_domain = target.replace(".", "/", 1) if target.count(".") == 1 else target
            r_rdap = self.safe_run_tool(
                "curl",
                f"curl -sL --max-time 15 'https://rdap.org/domain/{target}'",
                target, silent=True
            )
            if r_rdap.success and r_rdap.stdout.strip().startswith("{"):
                try:
                    rdap = json.loads(r_rdap.stdout)
                    registrar = rdap.get("entities", [{}])
                    rdap_info = f"RDAP: registrar={rdap.get('handle', 'unknown')} status={rdap.get('status', [])}"
                    results["whois"] = {"rdap": rdap_info}
                    self.add_finding("whois", target, rdap_info[:300], "info")
                    info(f"RDAP result: {rdap_info[:120]}")
                except Exception:
                    pass
            else:
                warning(f"WHOIS + RDAP both returned empty for {target} — registry may block lookups.")

        # 2. DNS enumeration
        info("Running DNS enumeration...")
        dns_results = {}
        for record in ["A", "MX", "NS", "TXT", "CNAME"]:
            # Always use @1.1.1.1 — VPS default resolver may be slow or filtered
            r = self.safe_run_tool("dig", f"dig @1.1.1.1 {record} {target} +short", target)
            if r.success and r.stdout.strip():
                dns_results[f"dns_{record}"] = r.stdout.strip().splitlines()
                self.add_finding("dns_record", target,
                                  f"{record}: {r.stdout.strip()[:200]}", "info")
        results.update(dns_results)

        # Early CDN detection from NS records
        ns_records = dns_results.get("dns_NS", [])
        ns_str = str(ns_records).lower()
        is_cdn_early = any(
            x in ns_str
            for x in ["vercel", "cloudflare", "fastly", "akamai", "dns-parking", "hostinger"]
        )
        if is_cdn_early:
            info(f"Early CDN detection via NS: {target} uses Hostinger/CDN nameservers.")
            # dns-parking.com = Hostinger's DNS — flag as infrastructure intelligence
            if "dns-parking" in ns_str or "hostinger" in ns_str:
                self.add_finding("infra_intel", target,
                                  f"NS records point to Hostinger DNS parking: {ns_records}", "info")

        # Bug 1 Fix: Wildcard Canary Fingerprinting
        # Resolve a guaranteed-fake subdomain to get the wildcard IP set
        canary = f"xzq99canary99xzq.{target}"
        info(f"Fingerprinting wildcard DNS with canary: {canary}")
        r_canary = self.safe_run_tool("dig", f"dig @1.1.1.1 +short {canary}", target)
        wildcard_ips = set(re.findall(r'\d+\.\d+\.\d+\.\d+', r_canary.stdout))
        if wildcard_ips:
            info(f"Wildcard fingerprint: {wildcard_ips} — will filter subdomain results")


        # ── Passive Recon (theHarvester) ─────────────────────────────────────
        info(f"Running passive discovery on {target} (theHarvester)...")
        passive_subs = set()
        # Use only sources reliably confirmed to work without API keys in theHarvester v4.10.1.
        # Removed: baidu, dnsdumpster, threatcrowd, urlscan, yahoo, crtsh (all fail silently
        # or require API keys, wasting 20+ seconds with zero results).
        # crt.sh is queried directly below via curl for better reliability.
        sources = "duckduckgo,hackertarget,otx,rapiddns"
        r_harv = self.safe_run_tool(
            "theharvester",
            f"theHarvester -d {target} -b {sources} -f /tmp/harvester_{target}.json",
            target
        )
        if r_harv.success:
            p_subs = re.findall(rf'([a-zA-Z0-9.-]+\.{re.escape(target)})', r_harv.stdout)
            passive_subs.update(s.lower() for s in p_subs if s.lower() != target)

        # Read back the JSON output file from VPS (theHarvester writes results to file, not stdout)
        if USE_REMOTE_VPS and self.tools.remote:
            harv_json_path = f"/tmp/harvester_{target}.json"
            exit_c, harv_json, _ = self.tools.remote.execute(f"cat {harv_json_path} 2>/dev/null")
            if exit_c == 0 and harv_json.strip():
                try:
                    import json as _hjson
                    hdata = _hjson.loads(harv_json)
                    # theHarvester JSON structure: {"hosts": [...], "ips": [...], "emails": [...]}
                    for host in hdata.get("hosts", []):
                        h = str(host).split(":")[0].lower().strip()
                        if h.endswith(target) and h != target:
                            passive_subs.add(h)
                    for email in hdata.get("emails", []):
                        self.add_finding("email", target, str(email), "medium")
                except Exception as _e:
                    # Fallback: parse as plain text for hostnames
                    for line in harv_json.splitlines():
                        line = line.strip()
                        if line.endswith(target) and line != target:
                            passive_subs.add(line.lower())

        if passive_subs:
            info(f"Passive discovery found {len(passive_subs)} potential subdomains.")

        # ── Elite Recon: Certificate Transparency (crt.sh) ───────────────────
        info(f"Querying Certificate Transparency logs for {target}...")
        r_crt = self.safe_run_tool(
            "curl",
            f"curl -sL --max-time 30 \"https://crt.sh/?q=%.{target}&output=json\"",
            target,
            silent=True
        )
        if r_crt.success and r_crt.stdout.strip().startswith("["):
            try:
                crt_data = json.loads(r_crt.stdout)
                for entry in crt_data:
                    name_value = entry.get("name_value", "").lower()
                    for sub in name_value.split('\n'):
                        if sub.endswith(target) and sub != target and "*" not in sub:
                            passive_subs.add(sub.strip())
            except Exception:
                pass
        info(f"CT Logs merged. Total passive subdomains: {len(passive_subs)}")

        # ── Elite Recon: Wayback Machine Historical Endpoints ────────────────
        info(f"Scraping historical API endpoints from Internet Archive...")
        r_wayback = self.safe_run_tool(
            "curl",
            f"curl -sL --max-time 30 \"http://web.archive.org/cdx/search/cdx?url=*.{target}/*&output=txt&fl=original&collapse=urlkey\"",
            target,
            silent=True
        )
        archived_urls = []
        if r_wayback.success:
            for line in r_wayback.stdout.splitlines():
                if "api" in line.lower() or "?" in line:
                    archived_urls.append(line.strip())
            if archived_urls:
                info(f"Found {len(archived_urls)} historical endpoints/parameters via Wayback.")
                results["archived_endpoints"] = archived_urls[:50]  # Store top 50
                self.add_finding("historical_endpoints", target, f"Wayback found {len(archived_urls)} past endpoints.", "low")

        # ── Elite Recon: Cloud Asset Enumeration (Heuristics) ────────────────
        cloud_prefixes = ["api-", "dev-", "staging-", "test-", "s3-", "assets-"]
        for pref in cloud_prefixes:
            passive_subs.add(f"{pref}{target}")
        info(f"Added {len(cloud_prefixes)} heuristic cloud prefixes for verification.")

        # ── Active Enumeration (gobuster) ────────────────────────────────────
        sub_list = "/tmp/subdomains.txt" if USE_REMOTE_VPS else str(self.session.results_dir / "raw" / "subdomains.txt")
        sub_url = "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/subdomains-top1million-5000.txt"
        
        r_sub = type("R", (), {"success": False, "stdout": "", "parsed": {}})()
        
        if USE_REMOTE_VPS:
            if self.tools.remote:
                # Check if file exists and has enough lines on VPS
                exit_code, out, _ = self.tools.remote.execute(f"[ -s {sub_list} ] && wc -l < {sub_list}")
                if exit_code != 0 or not out.strip().isdigit() or int(out.strip()) < 100:
                    self.log.info("Downloading DNS wordlist to VPS...")
                    self.tools.remote.execute(f"curl -sL --max-time 60 {sub_url} -o {sub_list}")

                # Verify wordlist AFTER download (curl may have timed out leaving 0-byte file)
                exit_code2, out2, _ = self.tools.remote.execute(f"wc -l < {sub_list} 2>/dev/null || echo 0")
                wordlist_lines = int(out2.strip()) if out2.strip().isdigit() else 0
                if wordlist_lines < 100:
                    warning(f"Wordlist download failed or too small ({wordlist_lines} lines). Using built-in fallback.")
                    # Write a minimal hardcoded fallback wordlist to VPS
                    fallback_subs = "www\nmail\nftp\nadmin\napi\ndev\nstaging\ntest\nshop\nblog\napp\nm\ncdn\nstatic\nassets\nvpn\nremote\nwebmail\nportal\nauth\nlogin\naccounts\ndash\ndashboard\npanel"
                    self.tools.remote.execute(f"printf '{fallback_subs}' > {sub_list}")

                # Use --resolver 1.1.1.1 to bypass OS resolver overload with high thread counts
                # Reduce threads from 40→20 to avoid SERVFAIL storm on single resolver
                r_sub = self.safe_run_tool(
                    "gobuster",
                    f"gobuster dns -d {target} -w {sub_list} -t 20 --timeout 15s --wildcard --resolver 1.1.1.1",
                    target
                )
        else:
            if not os.path.exists(sub_list):
                 try:
                    import requests as req
                    resp = req.get(sub_url, timeout=20)
                    if resp.status_code == 200:
                        open(sub_list, "w", encoding="utf-8").write(resp.text)
                 except: pass
            r_sub = self.safe_run_tool(
                "gobuster",
                f"gobuster dns -d {target} -w {sub_list} -t 20 --timeout 15s --wildcard",
                target
            )

        active_lines = r_sub.stdout.strip().splitlines() if r_sub.success else []
        found_subs = set()
        for line in active_lines:
             if "Found:" in line:
                 s = line.replace("Found:", "").strip().lower()
                 if s.endswith(target): found_subs.add(s)

        # Merge passive and active results
        all_potential = found_subs.union(passive_subs)
        total_found = len(all_potential)
        info(f"Filtering {total_found} potential subdomains for wildcard/CDN noise...")
        
        valid_count = 0
        processed = 0
        for sub in sorted(list(all_potential)):
            if valid_count >= 100: # Cap at 100 real subdomains for broad coverage
                info("Reached cap of 100 valid subdomains. Stopping deeper verification.")
                break

            processed += 1
            if processed % 25 == 0:
                info(f"Verification progress: {processed}/{total_found} processed...")
            
            # FAST DROP: If it resolves only to wildcard IPs, it's garbage
            is_valid, ip = self._verify_subdomain(sub, wildcard_ips, silent=True)
            if is_valid:
                valid_count += 1
                self.add_finding("subdomain", sub, f"IP: {ip}", "medium")
                self.session.scope.append(sub)  # Add to session for next phases

        # 3. Port Discovery (using unique IPs found above)
        unique_ips = set()
        for finding in self._findings:
            if finding["type"] == "subdomain":
                ip_match = re.search(r'IP: ([\d.]+)', finding["detail"])
                if ip_match: unique_ips.add(ip_match.group(1))

        # 4. Fast port discovery with masscan
        info("Resolving root target IPs for masscan...")
        resolve_result = self.safe_run_tool("dig", f"dig @1.1.1.1 A {target} +short", target)
        root_ips = []
        if resolve_result.success and resolve_result.stdout.strip():
            for line in resolve_result.stdout.strip().splitlines():
                if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', line.strip()):
                    root_ips.append(line.strip())
        
        # Combine root IPs with discovered unique IPs
        for ip in root_ips:
            unique_ips.add(ip)
            
        root_ip = root_ips[0] if root_ips else None
        
        # Select targets for masscan (cap at 10 for performance)
        masscan_targets = list(unique_ips)[:10]
        if masscan_targets:
            info(f"Sweeping discovered infrastructure IPs: {masscan_targets}")
            targets_str = " ".join(masscan_targets)
        else:
            targets_str = target

        info(f"Running masscan against {targets_str}...")
        r = self.safe_run_tool(
            "masscan",
            f"masscan {targets_str} -p 1-65535 --rate=200 --wait 5 "
            f"--exclude 255.255.255.255",
            target
        )
        fast_ports = r.parsed.get("open_ports", [])
        results["masscan_ports"] = fast_ports

        # 5. Detailed nmap on discovered ports
        local_nmap_out = self.session.results_dir / "raw" / "nmap_output.txt"
        vps_nmap_out = self.tools.vps_path(local_nmap_out)

        if fast_ports:
            port_str = ",".join(map(str, sorted(fast_ports[:50])))
            # Scan the SAME IPs masscan used — not the hostname.
            # hcdn rotates DNS between scans; re-resolving gives a DIFFERENT CDN server.
            # If masscan found ports on specific IPs, nmap those IPs directly.
            if masscan_targets and masscan_targets[0] != target:
                # Use first resolved IP and add --resolve-all suppressed by using IP directly
                nmap_ip_targets = " ".join(masscan_targets[:3])  # cap at 3 IPs
                nmap_cmd = (f'nmap -sV -sC -O -p {port_str} {nmap_ip_targets} '
                            f'--script-args newtargets '
                            f'-oN "{vps_nmap_out}"')
            else:
                nmap_cmd = f'nmap -sV -sC -O -p {port_str} {target} -oN "{vps_nmap_out}"'
        else:
            info("Masscan found no ports. Running nmap top-1000 scan.")
            nmap_cmd = f'nmap -sV -sC -O --top-ports 1000 {target} -oN "{vps_nmap_out}"'

        info("Running nmap service detection...")
        r = self.safe_run_tool("nmap", nmap_cmd, target, output_path=local_nmap_out)
        results["nmap"] = r.parsed

        if r.parsed.get("open_ports"):
            for port, svc in r.parsed.get("services", {}).items():
                self.add_finding(
                    "open_port", target,
                    f"Port {port}/{svc.get('protocol', 'tcp')}: "
                    f"{svc.get('service', '?')} {svc.get('version', '')}",
                    "medium" if int(port) not in [80, 443] else "info"
                )

        # ── Honeypot Detection Heuristics ─────────────────────────────────
        all_open_ports = r.parsed.get("open_ports", []) or fast_ports
        if len(all_open_ports) > HONEYPOT_PORT_THRESHOLD:
            warning(
                f"HONEYPOT INDICATOR: {len(all_open_ports)} ports open on {target} "
                f"(threshold: {HONEYPOT_PORT_THRESHOLD}). This is abnormally high."
            )
            self.add_finding(
                "honeypot_indicator", target,
                f"{len(all_open_ports)} ports open — possible honeypot or misconfigured host. "
                f"Results may be unreliable. Manual verification recommended.",
                "high"
            )

        # ── GeoIP Block Detection ─────────────────────────────────────────
        # If DNS resolves but ALL ports are unreachable, suspect GeoIP blocking
        if root_ip and not all_open_ports:
            warning(
                f"Target {target} resolves to {root_ip} but no ports are reachable. "
                f"Possible GeoIP blocking from VPS region."
            )
            self.add_finding(
                "geo_block_suspected", target,
                f"DNS resolves to {root_ip} but all connections fail — "
                f"may require local proxy or VPS in target's region",
                "high"
            )

        # 6. SMB enumeration if port 445 open
        if 445 in r.parsed.get("open_ports", []):
            info("SMB port open. Running enum4linux...")
            r2 = self.safe_run_tool("enum4linux", f"enum4linux -a {target}", target)
            results["smb"] = r2.parsed
            if r2.parsed.get("users"):
                self.add_finding("smb_users", target,
                                  f"SMB users: {', '.join(r2.parsed['users'])}", "high")

        # 7. WAF Detection
        info("Checking for WAF/Firewall...")
        r_waf = self.safe_run_tool("wafw00f", f"wafw00f {target}", target)
        waf_info = "None detected"
        out_lower = r_waf.stdout.lower()
        is_behind = False

        if r_waf.success:
            is_behind = (
                "is behind" in r_waf.stdout or
                "x-vercel-mitigated" in out_lower or
                "vercel security checkpoint" in out_lower or
                "cloudflare" in out_lower
            )
            if is_behind:
                waf_parsed = r_waf.parsed
                waf_info = waf_parsed.get("waf_name") or "CDN/WAF"
                if "vercel" in out_lower:
                    waf_info = "Vercel"
                elif "cloudflare" in out_lower:
                    waf_info = "Cloudflare"
                info(f"WAF Detected: {waf_info}")
                self.add_finding("waf_detected", target,
                                  f"Target is behind {waf_info}", "medium")

        # ── hcdn / Hostinger CDN fingerprinting (wafw00f has no signature for it) ──
        # hcdn injects 'x-hcdn-request-id' and 'x-hcdn-cache-status' response headers.
        # wafw00f returns false negative — we do a direct header probe to catch it.
        if not is_behind:
            info("wafw00f found no WAF. Running hcdn/Hostinger CDN header probe...")
            r_hcdn = self.safe_run_tool(
                "curl",
                f"curl -sI --max-time 10 https://{target}",
                target, silent=True
            )
            hcdn_lower = r_hcdn.stdout.lower()
            if any(h in hcdn_lower for h in [
                "x-hcdn-request-id", "x-hcdn-cache-status",
                "x-hostinger", "hostinger"
            ]):
                is_behind = True
                waf_info = "hcdn (Hostinger CDN)"
                info(f"hcdn CDN detected via response headers!")
                self.add_finding("waf_detected", target,
                                  f"Target is behind hcdn (Hostinger CDN) — wafw00f blind spot", "medium")

        is_cdn = any(
            x in r_waf.stdout.lower()
            for x in ["vercel", "cloudflare", "fastly", "akamai", "varnish", "hcdn", "hostinger"]
        ) or is_cdn_early or is_behind

        # AI recon analysis
        info("Asking AI to analyze recon findings and generate dynamic commands...")
        summary_prompt = (
            f"You are the GHOSTWIRE V5 Autonomous Pentest Engine. Analyze these recon results for {target}:\n"
            f"{json.dumps(results, default=str)[:3000]}\n\n"
            f"Provide a highly technical, offensive-security focused attack plan. Identify specific CVE potential, misconfigurations, and deeper enumeration steps.\n"
            f"Respond exactly in the following JSON format:\n"
            f"{{\n"
            f"  \"analysis\": \"Your detailed textual analysis and attack plan\",\n"
            f"  \"commands\": [\"sslscan {target}\", \"nmap -p 3306 --script=mysql-enum {target}\"]\n"
            f"}}\n"
            f"CRITICAL COMMAND SYNTAX RULES:\n"
            f"- nmap scripts use EQUALS sign: --script=SCRIPT_NAME (NOT --script:SCRIPT_NAME)\n"
            f"- All commands must be valid Linux bash, executable directly on a Debian VPS\n"
            f"- Only use tools that exist in standard repos: nmap, sslscan, whatweb, nikto, dig, curl, wget, enum4linux, sqlmap, gobuster, ffuf\n"
            f"- Do NOT use pipes or semicolons, keep each command simple and standalone\n"
            f"- Target must always be the last argument\n"
            f"Ensure the 'commands' array contains up to 3 specific bash commands for further deep reconnaissance. Return ONLY valid JSON."
        )
        ai_response = self.think(summary_prompt)
        try:
            cleaned_response = ai_response.strip()
            if cleaned_response.startswith("```json"):
                cleaned_response = cleaned_response[7:-3]
            elif cleaned_response.startswith("```"):
                cleaned_response = cleaned_response[3:-3]
                
            parsed_ai = json.loads(cleaned_response)
            ai_analysis = parsed_ai.get("analysis", "No textual analysis provided.")
            ai_commands = parsed_ai.get("commands", [])
            
            results["ai_analysis"] = ai_analysis
            info(f"AI Recon Analysis:\n{ai_analysis}")
            
            if ai_commands:
                info(f"Executing {len(ai_commands)} AI-generated dynamic recon commands...")
                for cmd in ai_commands[:3]:
                    # Pre-execution sanitizer: fix common AI hallucinations
                    cmd = re.sub(r'--script:', '--script=', cmd)  # nmap colon→equals
                    cmd = re.sub(r'\s+', ' ', cmd).strip()  # collapse whitespace
                    if cmd.startswith("nikto") and "-maxtime" not in cmd:
                        cmd += " -maxtime 60"
                    if not cmd or len(cmd) > 300:
                        continue
                    info(f"Running dynamic command: {cmd}")
                    r_cmd = self.safe_run_tool("ai_dynamic_recon", cmd, target)
                    results[f"dynamic_cmd_{cmd[:10]}"] = r_cmd.stdout[:500]
                    if r_cmd.success and r_cmd.stdout.strip():
                        # ai_dynamic_recon = informational recon output, not a vulnerability
                        self.add_finding("ai_dynamic_recon", target, f"Cmd: {cmd[:50]}\nOutput: {r_cmd.stdout[:300]}", "info")
        except Exception as e:
            warning(f"Failed to parse AI recon JSON: {e}")
            ai_analysis = ai_response
            results["ai_analysis"] = ai_analysis
            info(f"AI Recon Analysis (Raw):\n{ai_analysis}")

        # Persist to state store for cross-phase access
        # Merge masscan and nmap ports for maximum breadth
        open_ports = r.parsed.get("open_ports", [])
        if not open_ports and results.get("masscan_ports"):
            open_ports = results["masscan_ports"]
            info(f"Using masscan ports for Phase Data: {open_ports}")

        bundle = {
            "open_ports": open_ports,
            "services": r.parsed.get("services", {}),
            "osint": results.get("osint", {}),
            "ai_analysis": ai_analysis,
            "waf_present": is_behind if r_waf.success else False,
            "waf_type": waf_info,
            "is_cdn": is_cdn,
            "subdomains": results.get("subdomains", []),
            "resolved_ip": root_ip,
        }
        self.store.set_phase_data(self.session.engagement_id, "recon", bundle)

        self.bus.publish("recon", "exploitation", {
            "event": "recon_complete",
            **bundle
        })


        self.store.set_phase_status(
            self.session.engagement_id, "recon", "complete",
            f"Open ports: {r.parsed.get('open_ports', [])}. AI: {ai_analysis[:200]}"
        )
        success("Recon phase complete.")
        return results
