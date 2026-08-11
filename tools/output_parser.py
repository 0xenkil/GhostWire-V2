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
                "httpx": self._httpx,
                "whatweb": self._whatweb,
            }
            parser_fn = parsers.get(tool, self._generic)
            return parser_fn(stdout, stderr)
        except Exception as e:
            log.warning(f"Parser error for {tool}: {e}")
            return {"raw": stdout[:5000], "parse_error": str(e)}

    def _nmap(self, stdout, stderr) -> dict:
        open_ports = []
        services = {}

        # Use finditer to tolerate fused lines.
        # PARSER-3: the service field is now OPTIONAL — a port line with no
        # service column (`22/tcp open`) is no longer silently dropped — and
        # the service token allows `/` so a slashed service (`ssl/http`) is
        # captured whole instead of truncated to `ssl`. `\b` after the state
        # keeps it from matching `open` inside a fused word.
        # Intra-line separators are horizontal-only ([ \t]+, never \s+): a
        # \s+ would match the newline and let one port's optional version field
        # swallow the *next* line's port entry, dropping it from the scan.
        for m in re.finditer(
                r'(\d+)/(tcp|udp)[ \t]+(open|filtered|closed)\b(?:[ \t]+([\w./+-]+))?(?:[ \t]+([^\n\r]+))?', stdout):
            port_info = {
                "port": int(m.group(1)),
                "protocol": m.group(2),
                "state": m.group(3),
                "service": m.group(4) or "",
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

    def _httpx(self, stdout, stderr) -> dict:
        """PARSER-1: httpx says WHICH hosts are live and with what status/title/
        tech. `_generic` kept only URLs and threw away the live/dead verdict —
        the exact signal that separates a real web server from a dead name.

        Handles both httpx `-json` output and the default bracketed line format
        (`https://host [200] [Title] [nginx,PHP]`). ANSI colour has already been
        stripped by clean_text upstream."""
        live_hosts = []
        probes = []
        technologies = []
        seen = set()
        decoder = json.JSONDecoder()

        for raw in (stdout or "").splitlines():
            line = raw.strip()
            if not line:
                continue

            data = None
            if line.startswith("{"):
                try:
                    data, _ = decoder.raw_decode(line)
                except Exception:
                    data = None

            if isinstance(data, dict):
                url = data.get("url") or data.get("input") or data.get("host") or ""
                status = data.get("status_code") or data.get("status-code")
                title = data.get("title", "")
                tech = data.get("tech") or data.get("technologies") or []
                if isinstance(tech, str):
                    tech = [tech]
            else:
                # Bracketed text format: URL followed by [ ... ] groups.
                um = re.match(r'(https?://\S+)', line)
                if not um:
                    continue
                url = um.group(1)
                brackets = re.findall(r'\[([^\]]*)\]', line)
                status = None
                title = ""
                tech = []
                if brackets:
                    # First bracket is the status code(s), e.g. [200] or [301,200]
                    sm = re.search(r'\d{3}', brackets[0])
                    if sm:
                        status = int(sm.group(0))
                    # Remaining brackets: title / tech tags (order tool-dependent)
                    for b in brackets[1:]:
                        b = b.strip()
                        if not b:
                            continue
                        if ',' in b or re.search(r'[A-Za-z]', b):
                            tech.extend(t.strip() for t in b.split(',') if t.strip())
                    if tech and not title:
                        title = ""

            if not url or url in seen:
                continue
            seen.add(url)
            live_hosts.append(url)
            probes.append({
                "url": url,
                "status": status,
                "title": title,
                "tech": tech,
            })
            for t in tech:
                if t and t not in technologies:
                    technologies.append(t)

        return {
            "live_hosts": live_hosts,
            "http_probes": probes,
            "technologies": technologies,
            "count": len(live_hosts),
        }

    def _whatweb(self, stdout, stderr) -> dict:
        """PARSER-1: whatweb emits tech-stack tags (`HTTPServer[nginx]`,
        `Title[...]`), not URLs, so `_generic` extracted essentially nothing and
        the fingerprint that drives wordlist/tech-aware decisions was dropped.

        Each `Name[value]` becomes a technology; HTTPServer/Title/IP are also
        surfaced explicitly."""
        technologies = []
        http_server = None
        title = None
        ip = None
        targets = []

        for raw in (stdout or "").splitlines():
            line = raw.strip()
            if not line:
                continue
            tm = re.match(r'(https?://\S+)', line)
            if tm:
                targets.append(tm.group(1))
            for m in re.finditer(r'([A-Za-z][\w\-]*)\[([^\]]*)\]', line):
                name = m.group(1).strip()
                val = m.group(2).strip()
                tag = f"{name}[{val}]" if val else name
                if tag not in technologies:
                    technologies.append(tag)
                low = name.lower()
                if low == "httpserver" and not http_server:
                    http_server = val
                elif low == "title" and not title:
                    title = val
                elif low == "ip" and not ip:
                    ip = val

        return {
            "technologies": technologies,
            "http_server": http_server,
            "title": title,
            "ip": ip,
            "targets": targets,
            "count": len(technologies),
        }

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
