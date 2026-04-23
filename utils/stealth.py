import random

USER_AGENTS = [
    # Chrome Windows
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    # Chrome Mac
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    # Chrome Linux
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    # Firefox Windows
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:123.0) Gecko/20100101 Firefox/123.0",
    # Safari Mac
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.3 Safari/605.1.15",
    # Edge Windows
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36 Edg/122.0.0.0",
    # Mobile iOS
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_3 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.3 Mobile/15E148 Safari/604.1",
    # Mobile Android
    "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Mobile Safari/537.36"
]

def get_random_ua() -> str:
    """Return a highly realistic, randomized User-Agent."""
    return random.choice(USER_AGENTS)

def get_sniper_headers(for_curl: bool = False) -> str:
    """Generate dynamic stealth headers to bypass CDN/WAF rules.
    If multiple headers are needed for curl, it returns `-H '...' -H '...'`.
    """
    ua = get_random_ua()
    
    # Fake origin IPs to bypass basic rate-limits
    fake_ips = [
        f"192.168.{random.randint(1,254)}.{random.randint(1,254)}",
        f"10.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}",
        f"172.{random.randint(16,31)}.{random.randint(0,255)}.{random.randint(1,254)}"
    ]
    fake_ip = random.choice(fake_ips)
    
    headers = {
        "User-Agent": ua,
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
        "Connection": "keep-alive",
        "Upgrade-Insecure-Requests": "1",
        "X-Forwarded-For": fake_ip,
        "X-Real-IP": fake_ip
    }
    
    if for_curl:
        return " ".join([f"-H '{k}: {v}'" for k, v in headers.items()])
    
    return headers

def apply_sniper_delays(waf_present: bool, base_cmd: str) -> str:
    """Injects low-and-slow delays into commands if WAF is detected."""
    if not waf_present:
        return base_cmd

    # Gobuster throttling
    if "gobuster dir" in base_cmd and "--delay" not in base_cmd:
        # Instead of max speed, enforce a polite 1500ms delay and limit threads
        import re
        cmd = re.sub(r'-t\s+\d+', '-t 5', base_cmd)  # Cap threads to 5
        cmd += " --delay 1500ms"
        return cmd
        
    # FFUF throttling
    if "ffuf" in base_cmd and "-p " not in base_cmd:
        import re
        cmd = re.sub(r'-t\s+\d+', '-t 5', base_cmd)
        cmd += " -p 1.5" # 1.5 second delay
        return cmd
        
    # Nmap throttling (if T4 or T5 is used)
    if "nmap" in base_cmd:
        cmd = base_cmd.replace("-T4", "-T2").replace("-T5", "-T2")
        # Ensure we don't scan too deeply if WAF is active
        cmd += " --max-retries 1 --host-timeout 5m"
        return cmd

    return base_cmd


def apply_nuclei_stealth(waf_present: bool, nuclei_cmd: str) -> str:
    """Inject stealth rate-limiting into Nuclei commands based on WAF state.
    
    WAF targets get heavily throttled to avoid triggering rate limits
    that would cascade-block subsequent curl-based probes.
    """
    import re
    from config import NUCLEI_RATE_LIMIT_WAF, NUCLEI_RATE_LIMIT_DEFAULT
    
    rate = NUCLEI_RATE_LIMIT_WAF if waf_present else NUCLEI_RATE_LIMIT_DEFAULT
    
    # Override existing rate-limit if present
    if '-rate-limit' in nuclei_cmd:
        nuclei_cmd = re.sub(r'-rate-limit\s+\d+', f'-rate-limit {rate}', nuclei_cmd)
    else:
        nuclei_cmd += f' -rate-limit {rate}'
    
    # Cap bulk-size for WAF targets
    if waf_present:
        if '-bulk-size' in nuclei_cmd:
            nuclei_cmd = re.sub(r'-bulk-size\s+\d+', '-bulk-size 10', nuclei_cmd)
        else:
            nuclei_cmd += ' -bulk-size 10'
    
    return nuclei_cmd
