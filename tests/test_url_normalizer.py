from core.url_utils import normalize_url, extract_host
import sys
from pathlib import Path
# Add project root to path
sys.path.append(str(Path(__file__).parent.parent))


def test_normalize_url():
    print("Testing normalize_url...")
    # Test cases: (input, expected)
    cases = [
        ("example.com", "http://example.com"),
        ("http://http://example.com", "http://example.com"),
        ("https://http://example.com", "https://example.com"),
        ("http://https://http://example.com", "http://example.com"),
        ("https://example.com:8080/path?q=1", "https://example.com:8080/path?q=1"),
    ]
    for inp, exp in cases:
        res = normalize_url(inp)
        assert res == exp, f"Failed: {inp} -> {res} (expected {exp})"
    print("normalize_url passed!")


def test_extract_host():
    print("Testing extract_host...")
    cases = [
        ("http://example.com/path", "example.com"),
        ("https://sub.example.com:8080", "sub.example.com"),
        ("http://http://example.com", "example.com"),
        ("example.com/foo?bar=1#baz", "example.com"),
        ("127.0.0.1", "127.0.0.1"),
    ]
    for inp, exp in cases:
        res = extract_host(inp)
        assert res == exp, f"Failed: {inp} -> {res} (expected {exp})"
    print("extract_host passed!")


if __name__ == "__main__":
    test_normalize_url()
    test_extract_host()
