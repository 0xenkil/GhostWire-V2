import sys
import os
import re
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core.session import EngagementSession
from core.target_context import TargetContext
from agents.base_agent import BaseAgent
from unittest.mock import MagicMock

def test_canonicalize_fixes():
    print("=== Testing Command Canonicalization Fixes ===")
    
    # Setup dummy agent
    class TestAgent(BaseAgent):
        async def run(self):
            return {}
            
    session = EngagementSession(mode="pentest", target_context=TargetContext.from_input("novalink.lk"))
    store = MagicMock()
    tool_mgr = MagicMock()
    ai = MagicMock()
    bus = MagicMock()
    scope = MagicMock()
    
    agent = TestAgent("test_agent", session, store, tool_mgr, ai, bus, scope)
    
    # Test cases for canonicalization
    test_cases = [
        # 1. gobuster missing subcommand
        {
            "tool": "gobuster",
            "cmd": "proxychains4 -q gobuster --useragent \"Mozilla/5.0\" -H \"X-Forwarded-For: 1.1.1.1\"",
            "expected_contains": ["gobuster dir", "-w {WORDLIST}", "-a"],
            "expected_not_contains": ["--useragent"]
        },
        # 2. sqlmap --crawl-depth & --batch
        {
            "tool": "sqlmap",
            "cmd": "sqlmap -u http://novalink.lk/tiki/ --crawl-depth=2",
            "expected_contains": ["--crawl=2", "--batch"],
            "expected_not_contains": ["--crawl-depth"]
        },
        # 3. whatweb custom headers
        {
            "tool": "whatweb",
            "cmd": "whatweb --header \"User-Agent: Mozilla/5.0\" http://novalink.lk",
            "expected_contains": ["--custom-header=\"User-Agent: Mozilla/5.0\""],
            "expected_not_contains": ["--header"]
        },
        # 4. ffuf missing FUZZ
        {
            "tool": "ffuf",
            "cmd": "ffuf -u http://novalink.lk -w common.txt",
            "expected_contains": ["/FUZZ", "-w"],
            "expected_not_contains": []
        },
        # 5. ffuf missing wordlist flag
        {
            "tool": "ffuf",
            "cmd": "ffuf -u http://novalink.lk/FUZZ",
            "expected_contains": ["-w {WORDLIST}"],
            "expected_not_contains": []
        },
        # 6. bare host tools URL and path stripping
        {
            "tool": "nmap",
            "cmd": "nmap -sV http://novalink.lk/tiki/index.php",
            "expected_contains": ["nmap -sV novalink.lk"],
            "expected_not_contains": ["http://", "/tiki", "index.php"]
        },
        # 7. bare host tools CIDR range protection
        {
            "tool": "nmap",
            "cmd": "nmap -sV 192.168.1.1/24",
            "expected_contains": ["nmap -sV 192.168.1.1/24"],
            "expected_not_contains": []
        },
        # 8. bare host tools IP with path stripping
        {
            "tool": "nmap",
            "cmd": "nmap -sV 192.168.1.1/tiki/index.php",
            "expected_contains": ["nmap -sV 192.168.1.1"],
            "expected_not_contains": ["/tiki", "index.php"]
        },
        # 9. stdout parsability (stripping -o filename and > redirection)
        {
            "tool": "subfinder",
            "cmd": "subfinder -d novalink.lk -o subdomains.txt -silent",
            "expected_contains": ["subfinder -d novalink.lk -silent"],
            "expected_not_contains": ["-o subdomains.txt"]
        },
        {
            "tool": "gobuster",
            "cmd": "gobuster dir -u http://novalink.lk -w common.txt > output.txt",
            "expected_contains": ["gobuster dir -u http://novalink.lk -w common.txt"],
            "expected_not_contains": ["> output.txt"]
        }
    ]
    
    all_passed = True
    for i, tc in enumerate(test_cases):
        tool = tc["tool"]
        cmd = tc["cmd"]
        canonical = agent._canonicalize_tool_command(tool, cmd, target="novalink.lk")
        print(f"\n[Case {i+1}] Tool: {tool}")
        print(f"  Input command: {cmd}")
        print(f"  Output command: {canonical}")
        
        # Verify contains
        for exp in tc["expected_contains"]:
            if exp not in canonical:
                print(f"  [FAIL] Expected string '{exp}' not found in canonical command!")
                all_passed = False
                
        # Verify not contains
        for exp in tc["expected_not_contains"]:
            if exp in canonical:
                print(f"  [FAIL] Unexpected string '{exp}' found in canonical command!")
                all_passed = False
                
    if all_passed:
        print("\n[SUCCESS] All command canonicalization fix tests passed!")
        sys.exit(0)
    else:
        print("\n[FAILURE] Some tests failed!")
        sys.exit(1)

if __name__ == "__main__":
    test_canonicalize_fixes()
