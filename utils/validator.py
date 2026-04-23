import re
import ipaddress
from utils.sanitizer import clean_target

def is_valid_ip(ip: str) -> bool:
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False

def is_valid_cidr(cidr: str) -> bool:
    try:
        ipaddress.ip_network(cidr, strict=False)
        return True
    except ValueError:
        return False

def is_valid_domain(domain: str) -> bool:
    # Aggressive pattern to catch domains and subdomains
    pattern = r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
    return bool(re.match(pattern, domain))

def is_valid_target(target: str) -> bool:
    """Universal validator for domains, IPs, and URLs."""
    if not target:
        return False
        
    # Basic domain/IP check (User specified pattern)
    pattern = r"^(https?:\/\/)?([a-zA-Z0-9.-]+)(:[0-9]+)?(\/.*)?$"
    if re.match(pattern, target) is None:
        return False
        
    normalized = normalize_target(target)
    return is_valid_ip(normalized) or is_valid_cidr(normalized) or is_valid_domain(normalized)

def normalize_target(target: str) -> str:
    """Strip protocol, trailing slashes, and whitespace from any target input."""
    target = target.strip().lower()
    # Remove protocol prefixes
    for prefix in ["https://", "http://", "ftp://"]:
        if target.startswith(prefix):
            target = target[len(prefix):]
    # Remove trailing slashes and paths — keep only host
    target = target.split("/")[0]
    # Remove port if present
    if ":" in target:
        parts = target.split(":")
        if is_valid_ip(parts[0]) or is_valid_domain(parts[0]):
            target = parts[0]
    return target

def sanitize_target(target):
    """Clean and optionally upgrade protocol for a target URL."""
    target = clean_target(target)
    # Force https if missing or if it looks like a domain without a protocol
    if not target.startswith(("http://", "https://")):
        # If it's a sub/domain like static.xx, upgrade to https
        target = "https://" + target
    return target
