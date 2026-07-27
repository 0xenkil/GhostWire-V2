import re
import ipaddress


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

    normalized = normalize_target(target)
    return is_valid_ip(normalized) or is_valid_cidr(
        normalized) or is_valid_domain(normalized)


def normalize_target(target: str) -> str:
    """Strip protocol, trailing slashes, and whitespace from any target input."""
    target = target.strip().lower()
    # Remove any protocol prefix
    if "://" in target:
        target = target.split("://", 1)[1]
    # Remove trailing slashes and paths - keep only host
    target = target.split("/")[0]
    # Remove port if present
    if ":" in target:
        target = target.split(":")[0]
    return target
