import re
import json
from utils.logger import get_logger

log = get_logger("output_parser")


class OutputParser:
    def parse(self, tool: str, stdout: str, stderr: str) -> dict:
        """
        Dispatch to per-tool parser. Always returns a dict, never raises.
        """
        try:
            parsers = {
                "nmap": self._nmap,
                "masscan": self._masscan,
                "nikto": self._nikto,
                "whois": self._whois,
                "theharvester": self._theharvester,
                "subfinder": self._subfinder,
                "gobuster": self._gobuster,
                "dirb": self._dirb,
                "ffuf": self._ffuf,
                "enum4linux": self._enum4linux,
                "hydra": self._hydra,
                "sqlmap": self._sqlmap,
                "nuclei": self._nuclei,
                "wafw00f": self._wafw00f,
            }
            parser_fn = parsers.get(tool, self._generic)
            return parser_fn(stdout, stderr)
        except Exception as e:
            log.warning(f"Parser error for {tool}: {e}")
            return {"raw": stdout[:5000], "parse_error": str(e)}

    def _nmap(self, stdout, stderr) -> dict:
        open_ports = []
        services = {}

        # Use finditer to tolerate fused lines
        for m in re.finditer(
                r'(\d+)/(tcp|udp)\s+(open|filtered|closed)\s+([\w.-]+)(?:\s+([^/\n]+))?', stdout):
            port_info = {
                "port": int(m.group(1)),
                "protocol": m.group(2),
                "state": m.group(3),
                "service": m.group(4),
                "version": m.group(5).strip() if m.group(5) else ""
            }
            if m.group(3) == "open":
                open_ports.append(port_info["port"])
                services[str(m.group(1))] = port_info

        os_match = re.search(r'(?:OS details|Running):\s*([^\n\r]+)', stdout)
        os_guess = os_match.group(1).strip() if os_match else ""

        return {
            "open_ports": list(set(open_ports)),
            "services": services,
            "os_guess": os_guess,
            "total_open": len(set(open_ports))
        }

    def _masscan(self, stdout, stderr) -> dict:
        """Returns open_ports as list of ints for consistency with nmap."""
        ports = []
        port_details = []
        # Use finditer to handle fused lines (masscan results can arrive
        # without newlines)
        pattern = r'Discovered open port (\d+)/(\w+) on ([\d.]+)'
        for match in re.finditer(pattern, stdout):
            port_num = int(match.group(1))
            if port_num not in ports:
                ports.append(port_num)
            port_details.append({
                "port": port_num,
                "proto": match.group(2),
                "host": match.group(3)
            })
        return {"open_ports": ports, "port_details": port_details}

    def _nikto(self, stdout, stderr) -> dict:
        findings = []
        skip_prefixes = [
            "target host:", "target port:", "target ip:",
            "start time:", "end time:", "0 host(s) tested",
            "nikto v", "+ no web server found", "multiple ips",
            "ssl info:", "+ server:"
        ]
        for line in stdout.splitlines():
            # Support + prefix (standard), - prefix, and * prefix (some
            # versions)
            stripped = None
            if line.startswith("+ "):
                stripped = line[2:].strip()
            elif line.startswith("- "):
                stripped = line[2:].strip()
            elif line.startswith("* "):
                stripped = line[2:].strip()

            if stripped and ":" in stripped:
                if not any(stripped.lower().startswith(s)
                           for s in skip_prefixes):
                    findings.append(stripped)

        return {"findings": findings, "count": len(findings)}

    def _whois(self, stdout, stderr) -> dict:
        result = {}
        for line in stdout.splitlines():
            if ":" in line and not line.startswith(
                    "%") and not line.startswith("#"):
                parts = line.split(":", 1)
                key = parts[0].strip().lower().replace(" ", "_")
                val = parts[1].strip()
                if key and val and key not in result:
                    result[key] = val
        return result

    def _theharvester(self, stdout, stderr) -> dict:
        emails, hosts, ips = [], [], []
        for line in stdout.splitlines():
            line = line.strip()
            if re.match(r'^[\w.+-]+@[\w.-]+\.\w+$', line):
                emails.append(line)
            elif re.match(r'^[\d.]+$', line) and len(line.split('.')) == 4:
                ips.append(line)
            elif re.match(r'^[\w.-]+\.\w{2,}$', line) and '@' not in line:
                hosts.append(line)
        return {
            "emails": list(set(emails)),
            "hosts": list(set(hosts)),
            "ips": list(set(ips))
        }

    def _subfinder(self, stdout, stderr) -> dict:
        domains = []
        for line in stdout.splitlines():
            line = line.strip()
            if line and not line.startswith("[") and not line.startswith(" "):
                domains.append(line)
        return {"subdomains": list(set(domains)), "count": len(set(domains))}

    def _gobuster(self, stdout, stderr) -> dict:
        paths = []
        for m in re.finditer(r'(/\S*)\s+\(Status:\s*(\d+)\)', stdout):
            paths.append({"path": m.group(1), "status": int(m.group(2))})

        for m in re.finditer(r'Found:\s*(\S+)', stdout):
            paths.append({"subdomain": m.group(1), "status": 0})

        return {"discovered_paths": paths, "count": len(paths)}

    def _dirb(self, stdout, stderr) -> dict:
        paths = []
        for m in re.finditer(r'\+\s+(https?://\S+)', stdout):
            paths.append(m.group(1))
        return {"discovered_paths": list(set(paths)), "count": len(set(paths))}

    def _ffuf(self, stdout, stderr) -> dict:
        paths = []
        for m in re.finditer(r'(\S*)\s+\[Status:\s*(\d+)', stdout):
            path = m.group(1) if m.group(1) else "/"
            if path.startswith('http'):
                try:
                    from urllib.parse import urlparse
                    path = urlparse(path).path
                except Exception as _e:
                    import logging
                    logging.getLogger(__name__).debug(
                        f'Swallowed exception in output_parser.py: {_e}')
            paths.append({"path": path, "status": int(m.group(2))})

        return {"discovered_paths": paths, "count": len(paths)}

    def _enum4linux(self, stdout, stderr) -> dict:
        users, shares = [], []
        for line in stdout.splitlines():
            um = re.search(r'user:\[(\w+)\]', line)
            if um:
                users.append(um.group(1))
            sm = re.search(r'Sharename\s+Type.*$', line, re.IGNORECASE)
            if sm:
                shares.append(line.strip())
        return {"users": list(set(users)), "shares": shares}

    def _hydra(self, stdout, stderr) -> dict:
        creds = []
        for line in stdout.splitlines():
            m = re.search(
                r'\[(\d+)\]\[(\w+)\] host: (\S+)\s+login: (\S+)\s+password: (\S+)', line)
            if m:
                creds.append({
                    "port": m.group(1), "service": m.group(2),
                    "host": m.group(3), "user": m.group(4), "pass": m.group(5)
                })
        return {"credentials": creds, "found": len(creds) > 0}

    def _sqlmap(self, stdout, stderr) -> dict:
        vulns = []
        for line in stdout.splitlines():
            if "is vulnerable" in line.lower() or "sql injection" in line.lower():
                vulns.append(line.strip())
        return {"vulnerabilities": vulns, "vulnerable": len(vulns) > 0}

    def _nuclei(self, stdout, stderr) -> dict:
        """Parse nuclei JSONL output, tolerating fused/noisy lines."""
        findings = []

        def _append_finding(data: dict):
            findings.append({
                "template_id": data.get("template-id", ""),
                "name": data.get("info", {}).get("name", ""),
                "severity": data.get("info", {}).get("severity", "info"),
                "matched": data.get("matched-at", ""),
                "type": data.get("type", ""),
            })

        decoder = json.JSONDecoder()
        for line in stdout.splitlines():
            line = line.strip()
            if not line:
                continue

            # Fast path for clean JSONL
            if line.startswith("{") and line.endswith("}"):
                try:
                    data = json.loads(line)
                    _append_finding(data)
                    continue
                except Exception as _e:
                    import logging
                    logging.getLogger(__name__).debug(
                        f'Swallowed exception in output_parser.py: {_e}')

            # Recovery path: walk line and decode all JSON objects found
            idx = 0
            decoded_any = False
            while idx < len(line):
                start = line.find("{", idx)
                if start == -1:
                    break
                try:
                    data, end = decoder.raw_decode(line[start:])
                    if isinstance(data, dict):
                        _append_finding(data)
                        decoded_any = True
                    idx = start + end
                except Exception as e:
                    import logging as __logging_tmp
                    __logging_tmp.getLogger(__name__).error(
                        f"Unhandled exception: {e}", exc_info=True)
                    idx = start + 1

            if not decoded_any:
                # Ignore known nuclei status/noise lines without spamming logs.
                noise_markers = [
                    "[", "duration", "hosts", "templates", "progress", "matched\":\"0"]
                if not any(x in line.lower() for x in noise_markers):
                    log.debug(
                        f"Nuclei parser skipped non-JSON line: {line[:120]}")
        return {"findings": findings, "count": len(findings)}

    def _wafw00f(self, stdout, stderr) -> dict:
        waf_name = None
        is_behind_waf = False
        for line in stdout.splitlines():
            if "is behind" in line.lower():
                is_behind_waf = True
                # Extract WAF name
                m = re.search(
                    r'is behind (.+?)(?:\s*\(|$)', line, re.IGNORECASE)
                if m:
                    waf_name = m.group(1).strip()
        return {"is_behind_waf": is_behind_waf, "waf_name": waf_name}

    def _generic(self, stdout, stderr) -> dict:
        # Extract URLs and parameter names so crawler / param-discovery tools
        # (katana, gau, hakrawler, waybackurls, arjun, paramspider, …) — which
        # have no dedicated parser — still contribute endpoints and parameters
        # to the attack surface instead of being discarded as raw text.
        text = stdout or ""
        urls = []
        seen = set()
        for m in re.finditer(r'https?://[^\s\'"<>\]\),]+', text):
            u = m.group(0).rstrip('.,);')
            if u not in seen:
                seen.add(u)
                urls.append(u)
            if len(urls) >= 300:
                break
        params = sorted({
            q.group(1) for q in re.finditer(r'[?&]([a-zA-Z0-9_\-\[\]]{1,40})=', text)
        })
        discovered_paths = [{"path": u, "status": 0} for u in urls[:200]]
        return {
            "raw_lines": text.splitlines()[:200],
            "line_count": len(text.splitlines()),
            "discovered_paths": discovered_paths,
            "discovered_urls": urls[:200],
            "parameters": params[:80],
            "has_errors": bool(stderr and len(stderr.strip()) > 0)
        }
