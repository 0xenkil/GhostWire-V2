import re
from core.config_loader import load_yaml_config
from urllib.parse import urlparse


def extract_host(target: str) -> str:
    """Robust host extraction that handles:
    - URLs with schemes
    - bare host:port strings
    - IPv6 addresses like [::1]:8080
    - nested schemes
    Returns lowercase hostname or IP with no port or userinfo.
    """
    if not target:
        return ""
    t = str(target).strip()
    # Collapse repeated schemes like https://http://example.com
    t = re.sub(
        r'^(?:[a-zA-Z][a-zA-Z0-9+.-]*://)+',
        lambda m: m.group(0).split('://')[0] +
        '://',
        t,
        flags=re.IGNORECASE)

    # urlparse requires a scheme to populate netloc; if missing, prepend '//'
    # to parse as network location
    parsed = urlparse(t if '://' in t else '//' + t)
    hostport = parsed.netloc or parsed.path

    # Remove userinfo if present
    if '@' in hostport:
        hostport = hostport.split('@')[-1]

    host = hostport
    # IPv6 in [::1]:8080 form
    if host.startswith('['):
        end = host.find(']')
        if end != -1:
            host = host[1:end]
    else:
        # Split out port if present
        if ':' in host:
            host = host.split(':')[0]

    return host.lower().strip()


def normalize_url(raw: str) -> str:
    """Normalize a URL by collapsing duplicated schemes and ensuring a scheme.

    Settings are loaded from config/url_normalizer.yaml.
    """
    config = load_yaml_config("url_normalizer")
    default_scheme = config.get("default_scheme", "http")
    scheme_pattern = config.get(
        "scheme_pattern",
        r"^([a-zA-Z][a-zA-Z0-9+.-]*)://(.+)$")
    nested_pattern = config.get(
        "nested_scheme_check",
        r"^[a-zA-Z][a-zA-Z0-9+.-]*://")

    text = str(raw).strip()
    if not text:
        return text

    # Remove stacked schemes
    _scheme_re = re.compile(scheme_pattern, re.DOTALL)
    while True:
        m = _scheme_re.match(text)
        if not m:
            break
        scheme = m.group(1)
        rest = m.group(2)

        # Check if the remaining part still starts with a scheme
        m_inner = re.match(nested_pattern, rest)
        if m_inner:
            # Found nested scheme, e.g., https://http://example.com
            # We want to keep the outer scheme (https) and strip the inner one (http)
            # To do this, we need to find the content after the inner scheme
            inner_m = _scheme_re.match(rest)
            if inner_m:
                text = f"{scheme}://{inner_m.group(2)}"
            else:
                # Should not happen if nested_pattern matched, but for safety:
                break
        else:
            # No more nested schemes
            break

    # Add default scheme if missing
    if not re.match(nested_pattern, text):
        text = f"{default_scheme}://{text}"
    return text
