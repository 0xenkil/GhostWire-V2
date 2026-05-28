"""
Active WAF ghost engine for traffic mutation.

This module transforms tool commands to inject stealth headers, spoof IPs,
and use other evasion techniques to bypass WAF and rate-limiting.
"""

from pathlib import Path
import json
import random
import re

from utils.logger import get_logger

log = get_logger("waf_ghost_engine")


class WafGhostEngine:
    """Transforms commands to evade WAF detection using multi-tier mutations."""

    def __init__(self, ssh_executor=None, rules: dict | None = None):
        self._ssh = ssh_executor
        self._rules = rules or self._load_rules()
        self._request_counts: dict[str, int] = {}
        
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
        except Exception:
            return {}

    def transform(self, command: str, tool: str, level: int = 1, blocked_chars: list | None = None) -> str:
        """
        Inject stealth headers and mutation into the command.
        
        Levels:
        1: Stealth Headers + Random UA
        2: Encoding (Double URL, Unicode) + Payload Mutation
        3: Protocol Obfuscation (Chunked, HTTP/2) + Heavy Mutation + Keyword Breaking
        """
        if not self._rules.get("waf_ghost_use_parasitism", True):
            return command

        transformed = command
        headers = self._generate_stealth_headers()

        # Origin IP Swapping (WafBypassOrchestrator Integration)
        try:
            from intelligence.waf_bypass_orchestrator import WafBypassOrchestrator
            orchestrator = WafBypassOrchestrator()
            
            # Extract target from command for active strategy lookup
            target_match = re.search(r'https?://([^/\"\'\s]+)', command)
            if target_match:
                target_domain = target_match.group(1)
                active_strategy = orchestrator.get_active_strategy(target_domain)
                
                if active_strategy.get("vector") == "origin" and "origin_ip" in active_strategy:
                    origin_ip = active_strategy["origin_ip"]
                    # Inject Host header for Origin Bypass
                    headers["Host"] = active_strategy.get("host_header", target_domain)
                    # Swap URL domain with IP
                    transformed = re.sub(rf'https?://{re.escape(target_domain)}', f'http://{origin_ip}', transformed)
                    log.info(f"Ghost Protocol: Origin Swapping active. Targeting {origin_ip} for {target_domain}")
        except Exception as e:
            log.error(f"Ghost Protocol: Failed to lookup active bypass strategy: {e}")
        
        # Phase 1: Header & Protocol Injection
        if "curl" in command:
            h_args = " ".join([f'-H "{k}: {v}"' for k, v in headers.items()])
            if level >= 3:
                h_args += " --http2 --compressed -k -H \"Transfer-Encoding: chunked\"" # Protocol obfuscation
                if "--limit-rate" not in transformed:
                    h_args += " --limit-rate 50k" # Slow and steady Level 3
            transformed = transformed.replace("curl ", f"curl {h_args} ")
            
        elif "wget" in command:
            h_args = " ".join([f'--header="{k}: {v}"' for k, v in headers.items()])
            transformed = transformed.replace("wget ", f"wget {h_args} ")
            
        elif "sqlmap" in command:
            if "--random-agent" not in transformed:
                transformed += " --random-agent"
            h_str = ",".join([f"{k}:{v}" for k, v in headers.items()])
            transformed += f' --headers="{h_str}"'
            if level >= 2:
                transformed += " --tamper=between,randomcase,space2comment,charencode"
            if level >= 3:
                transformed += " --tamper=apostrophemask,unionalltounion,versionedkeywords"

        elif "nuclei" in command:
            h_args = " ".join([f'-H "{k}: {v}"' for k, v in headers.items()])
            if level >= 3:
                h_args += ' -H "Transfer-Encoding: chunked"'
            transformed = transformed.replace("nuclei ", f"nuclei {h_args} ")
            if level >= 2:
                transformed += " -rate-limit 5 -bulk-size 1 -concurrency 1"
            if level >= 3:
                # Nuclei specific advanced evasion
                transformed += " -header-filter 'User-Agent: .*' -silent -v -no-interactsh"
                if "-u" in transformed:
                    transformed = transformed.replace("-u ", "-u https://") if "http" not in transformed else transformed

        elif "ffuf" in command or "gobuster" in command:
            h_args = " ".join([f'-H "{k}: {v}"' for k, v in headers.items()])
            if level >= 3:
                h_args += ' -H "X-HTTP-Method-Override: GET"' # Method tunneling
            transformed = transformed.replace("ffuf ", f"ffuf {h_args} ")
            if "gobuster dir " in transformed:
                transformed = transformed.replace("gobuster dir ", f"gobuster dir {h_args} ")
            elif "gobuster vhost " in transformed:
                transformed = transformed.replace("gobuster vhost ", f"gobuster vhost {h_args} ")
            else:
                transformed = transformed.replace("gobuster ", f"gobuster {h_args} ")
            if level >= 3:
                if "ffuf" in command: transformed += " -p 1.5-3.0 -t 2 -H \"Connection: close\" -H \"Cache-Control: no-cache\""
                if "gobuster" in command: transformed += " --delay 5s --threads 1"
            elif level >= 2:
                # Add jitter and delay for fuzzing
                if "ffuf" in command: transformed += " -p 0.5-1.5 -t 5"
                if "gobuster" in command: transformed += " --delay 2s --threads 2"

        elif "httpx" in command:
            h_args = " ".join([f'-H "{k}: {v}"' for k, v in headers.items()])
            transformed = transformed.replace("httpx ", f"httpx {h_args} ")
            if level >= 2:
                transformed += " -rl 10 -c 5 -timeout 15 -retries 3"  # slow down and retry
            if level >= 3:
                transformed += " -random-agent"

        elif "katana" in command:
            h_args = " ".join([f'-H "{k}: {v}"' for k, v in headers.items()])
            transformed = transformed.replace("katana ", f"katana {h_args} ")
            if level >= 2:
                transformed += " -rl 10 -c 5"
            if level >= 3:
                transformed += " -random-agent"

        elif "dirsearch" in command:
            h_args = " ".join([f'--header "{k}: {v}"' for k, v in headers.items()])
            transformed = transformed.replace("dirsearch ", f"dirsearch {h_args} ")
            if level >= 2:
                transformed += " --random-agent -t 5 --delay 1"
            if level >= 3:
                transformed += " --random-agent -t 2 --delay 3"

        elif "dalfox" in command:
            h_args = " ".join([f'-H "{k}: {v}"' for k, v in headers.items()])
            transformed = transformed.replace("dalfox ", f"dalfox {h_args} ")
            if level >= 2:
                transformed += " --delay 1000 -w 5"

        elif "naabu" in command:
            if level >= 2:
                transformed += " -rate-limit 10 -c 5"
            if level >= 3:
                transformed += " -rate-limit 5 -c 2"

        elif "nikto" in command:
            # -evasion 1234 is heavily signatured and triggers instant WAF drops/tarpits.
            # Using -evasion A (random string/agent) is much stealthier.
            ua = headers.get("User-Agent", self._user_agents[0])
            transformed = transformed.replace("nikto ", f"nikto -useragent '{ua}' ")
            if level >= 2:
                transformed += " -evasion A -Tuning 123a"
            if level >= 3:
                # Nikto needs more time when running through WAFs
                if "-maxtime 60" in transformed:
                    transformed = transformed.replace("-maxtime 60", "-maxtime 180")

        elif "whatweb" in command:
            h_args = " ".join([f'--header "{k}: {v}"' for k, v in headers.items()])
            transformed = transformed.replace("whatweb ", f"whatweb {h_args} ")
            if level >= 2:
                transformed += " --no-errors"

        # Phase 2: Payload Mutation (Level 2+)
        if level >= 2:
            transformed = self._mutate_payloads(transformed, blocked_chars, level)

        # Phase 3: Proxychains Injection (Level 2+)
        if level >= 2 and not transformed.startswith("proxychains"):
            transformed = f"proxychains4 -q {transformed}"

        if transformed != command:
            log.info(f"Ghost Protocol: Transformed {tool} command (Evasion Level {level}).")
            
        return transformed

    def _mutate_payloads(self, command: str, blocked_chars: list | None = None, level: int = 2) -> str:
        """Apply advanced mutations to payloads within the command string."""
        blocked = blocked_chars or []
        
        # 1. SQLi Space Mutation (only if spaces are explicitly blocked)
        if " " in blocked:
            command = command.replace(" ", "/**/")
        
        # 2. SQLi Equality Mutation (only if equality operator is explicitly blocked)
        if "=" in blocked:
            # Safely replace only in queries (or target payloads) rather than headers
            # To be simple and robust: only replace outside of header definitions or just the whole command if requested
            command = command.replace("=", " LIKE ")
            
        # 3. Path Traversal Mutation
        if "../" in command and "/" in blocked:
            command = command.replace("../", "..\\")
            
        # 4. Keyword Breaking (Level 3+)
        if level >= 3:
            # Break common keywords that WAFs look for
            keywords = ["SELECT", "UNION", "ETC/PASSWD", "SCRIPT", "ALERT", "EVAL"]
            for kw in keywords:
                if kw in command.upper():
                    scrambled = "".join([c.upper() if i % 2 == 0 else c.lower() for i, c in enumerate(kw)])
                    if level >= 3:
                        scrambled = scrambled[0] + "%00" + scrambled[1:]
                    command = re.sub(re.escape(kw), scrambled, command, flags=re.IGNORECASE)

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
                    
        return " ".join(parts)

    def _generate_stealth_headers(self) -> dict:
        """Generate a set of spoofed headers."""
        fake_ip = ".".join(map(str, (random.randint(1, 254) for _ in range(4))))
        
        # Use UA from rules if available
        ua_list = self._rules.get("waf_evasion_user_agents", self._user_agents)
        headers = {
            "User-Agent": random.choice(ua_list),
            "X-Forwarded-For": fake_ip,
            "X-Real-IP": fake_ip,
            "Accept-Language": "en-US,en;q=0.9",
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
                        # Try to use a domain name if we have one, otherwise use fake_ip or localhost
                        headers[k] = "localhost" 
                    else:
                        headers[k] = v
        
        return headers

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
            log.warning("Ghost Protocol: No SSH executor available for remote challenge solving.")
            return command

        solver_script = f"""
import time
import json
try:
    from playwright.sync_api import sync_playwright
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        context = browser.new_context(
            user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
        )
        page = context.new_page()
        page.goto('{target_url}', wait_until='networkidle', timeout=20000)
        time.sleep(5)  # Allow JS challenges to execute
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
        script_path = f"/tmp/waf_solver_{random.randint(1000,9999)}.py"
        self._ssh.upload_content(solver_script.strip(), script_path)
        
        exit_code, stdout, stderr = self._ssh.execute(f"python3 {script_path}", timeout=30)
        self._ssh.execute(f"rm -f {script_path}")
        
        # Safely extract cookies with safe_marker_extraction (never crashes with IndexError)
        from core.result_contracts import FragileParseFixer
        
        cookie_str = FragileParseFixer.safe_marker_extraction(
            stdout, 
            marker_start="__SOLVED_COOKIES__=",
            marker_end="\n",
            default=""
        )
        
        if cookie_str:
            log.info(f"Ghost Protocol: Challenge solved successfully. Injected cookies: {cookie_str[:30]}...")
            # Inject cookie into command
            if "curl " in command:
                return command.replace("curl ", f"curl -b '{cookie_str}' ", 1)
            elif "wget " in command:
                return command.replace("wget ", f"wget --header='Cookie: {cookie_str}' ", 1)
            elif "sqlmap " in command:
                return command + f" --cookie='{cookie_str}'"
            elif "ffuf " in command or "gobuster " in command:
                tool_bin = command.split()[0]
                return command.replace(tool_bin, f"{tool_bin} -H 'Cookie: {cookie_str}' ", 1)
        
        log.warning("Ghost Protocol: Challenge solver failed or timed out.")
        return command
