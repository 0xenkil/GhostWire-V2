import sys
import os
import re

sys.path.append(r"C:\Users\ASUS\Desktop\red team")

from agents.base_agent import BaseAgent
from core.session import EngagementSession
from core.state_store import StateStore
from tools.tool_manager import ToolManager
from core.target_context import TargetContext

class DummySession:
    def __init__(self):
        self.engagement_id = "test_eng_all_tools"
        self.target = "http://novalink.lk/"
        self.target_context = TargetContext.from_input("http://novalink.lk/")
        self.rules_of_engagement = {"allow_exploitation": True}
        self.results_dir = "results"
        self.session_dir = "results"
        self.db_path = "tests/results/test_v7.db"
        self.stealth_config = {}

class DummyStateStore:
    def set_phase_status(self, *args, **kwargs): pass
    def log_tool_run(self, *args, **kwargs): pass
    def get_all_findings(self, *args): return []
    def get_phase_data(self, *args): return {}

class TestAgent(BaseAgent):
    def __init__(self, tm):
        session = DummySession()
        store = DummyStateStore()
        super().__init__(
            name="test_agent",
            session=session,
            state_store=store,
            tool_manager=tm,
            ai_backend=None,
            message_bus=None,
            scope_enforcer=None
        )
    def run(self):
        return {}

def test_comprehensive_generation():
    session = DummySession()
    store = DummyStateStore()
    tm = ToolManager(session, store, ai_backend=None)
    agent = TestAgent(tm)
    
    # Let's mock the valid flags for tools so we don't depend on WSL help menus taking time or failing
    # We will just inject some mock valid flags into the cache so the corrector works predictably.
    mock_flags = {
        "nmap": {"-p", "-sS", "-sV", "-O", "-T4", "-oN", "-v", "--open"},
        "masscan": {"-p", "--rate", "--adapter-ip"},
        "sslscan": {"--no-failed", "--tlsall"},
        "curl": {"-s", "-L", "-I", "-X", "-H", "-d", "-u"},
        "wget": {"-q", "-O", "--no-check-certificate"},
        "nikto": {"-h", "-Tuning", "-Format", "-o"},
        "gobuster": {"dir", "dns", "-u", "-w", "-t", "-x"},
        "ffuf": {"-u", "-w", "-t", "-mc", "-H"},
        "sqlmap": {"-u", "--batch", "--dbs", "--level", "--risk"},
        "nuclei": {"-u", "-t", "-severity", "-o"},
        "hydra": {"-l", "-p", "-L", "-P", "-s", "-t"},
        "whatweb": {"-v", "-a"},
        "wafw00f": {"-v", "-a"},
        "dirsearch": {"-u", "-w", "-e"},
        "subfinder": {"-d", "-all"},
        "theharvester": {"-d", "-b", "-l"},
        "assetfinder": {"--subs-only"},
        "ping": {"-c", "-W"},
        "traceroute": {"-m", "-q"},
        "dnsenum": {"--enum", "--noreverse"},
        "whois": {"-H"},
        "dig": {"+short", "+noall", "+answer", "ANY", "A", "TXT", "MX"},
        "host": {"-t", "-a"},
        "nslookup": {"-type"}
    }
    
    for k, v in mock_flags.items():
        tm._valid_flags_cache[k] = v
        # Also mock subcommands for gobuster
        if k == "gobuster":
            tm._valid_flags_cache["gobuster_dir"] = v

    print("=== TESTING ALL TOOLS COMMAND GENERATION ===")
    
    test_cases = [
        {
            "tool": "nmap",
            "cmd": "nmap -p 80,443 -sS --hallucinated=123 --open -T4 http://novalink.lk",
            "desc": "Strip hallucinated flags and bare-host normalization"
        },
        {
            "tool": "masscan",
            "cmd": "masscan -p 1-65535 --rate 1000 --fake-param https://novalink.lk",
            "desc": "Masscan scheme stripping and flag filtering"
        },
        {
            "tool": "sslscan",
            "cmd": "sslscan --no-failed --tlsall --bogus-flag http://novalink.lk:443",
            "desc": "SSLScan target format and flag filtering"
        },
        {
            "tool": "curl",
            "cmd": "curl -s -L -H 'User-Agent: test' --made-up-flag http://novalink.lk/api",
            "desc": "Curl preserves headers and strips fake flags"
        },
        {
            "tool": "wget",
            "cmd": "wget -q -O output.txt --not-real http://novalink.lk/file.zip",
            "desc": "Wget strips invalid flags"
        },
        {
            "tool": "nikto",
            "cmd": "nikto -h http://novalink.lk -Tuning 123 --fake",
            "desc": "Nikto flag filtering"
        },
        {
            "tool": "gobuster",
            "cmd": "gobuster dir -u http://novalink.lk -w /tmp/wordlist.txt -t 50 --not-real",
            "desc": "Gobuster dir flag filtering"
        },
        {
            "tool": "ffuf",
            "cmd": "ffuf -u http://novalink.lk/FUZZ -w /tmp/wordlist.txt -mc 200 --bogus",
            "desc": "FFUF flag filtering"
        },
        {
            "tool": "whatweb",
            "cmd": "whatweb -v -a 3 --hallucinated https://novalink.lk",
            "desc": "WhatWeb flag filtering"
        },
        {
            "tool": "wafw00f",
            "cmd": "wafw00f -v -a --bogus http://novalink.lk",
            "desc": "Wafw00f flag filtering"
        },
        {
            "tool": "dirsearch",
            "cmd": "dirsearch -u http://novalink.lk -w /tmp/wordlist.txt -e php --fake",
            "desc": "Dirsearch flag filtering"
        },
        {
            "tool": "subfinder",
            "cmd": "subfinder -d novalink.lk -all --hallucinated",
            "desc": "Subfinder flag filtering"
        },
        {
            "tool": "theharvester",
            "cmd": "theharvester -d novalink.lk -b all -l 500 --fake",
            "desc": "TheHarvester flag filtering"
        },
        {
            "tool": "assetfinder",
            "cmd": "assetfinder --subs-only novalink.lk --hallucinated",
            "desc": "Assetfinder flag filtering"
        },
        {
            "tool": "ping",
            "cmd": "ping -c 4 -W 2 --bogus http://novalink.lk",
            "desc": "Ping scheme stripping"
        },
        {
            "tool": "traceroute",
            "cmd": "traceroute -m 30 -q 1 --fake https://novalink.lk",
            "desc": "Traceroute scheme stripping"
        },
        {
            "tool": "dnsenum",
            "cmd": "dnsenum --enum --noreverse --fake novalink.lk",
            "desc": "Dnsenum flag filtering"
        },
        {
            "tool": "whois",
            "cmd": "whois -H --fake novalink.lk",
            "desc": "Whois flag filtering"
        },
        {
            "tool": "dig",
            "cmd": "dig +short ANY novalink.lk --hallucinated",
            "desc": "Dig flag filtering"
        },
        {
            "tool": "host",
            "cmd": "host -t A novalink.lk --fake",
            "desc": "Host flag filtering"
        },
        {
            "tool": "nslookup",
            "cmd": "nslookup -type=TXT novalink.lk --bogus",
            "desc": "Nslookup flag filtering"
        }
    ]

    for tc in test_cases:
        tool = tc["tool"]
        cmd_in = tc["cmd"]
        
        print(f"\n--- Testing {tool} ---")
        print(f"Original: {cmd_in}")
        
        # 1. Proactive valid flag filter
        cmd_filtered = tm.validate_and_filter_flags(cmd_in, tool)
        
        # 2. BaseAgent Canonicalizer
        cmd_out = agent._canonicalize_tool_command(tool, cmd_filtered, "novalink.lk")
        
        print(f"Result  : {cmd_out}")
        
        # Assertions
        assert "--hallucinated" not in cmd_out, f"[{tool}] Failed to strip --hallucinated flag!"
        assert "--fake" not in cmd_out, f"[{tool}] Failed to strip --fake flag!"
        assert "--bogus" not in cmd_out, f"[{tool}] Failed to strip --bogus flag!"
        assert "--not-real" not in cmd_out, f"[{tool}] Failed to strip --not-real flag!"
        assert "--made-up-flag" not in cmd_out, f"[{tool}] Failed to strip --made-up-flag flag!"
        
        if tool in {"nmap", "masscan", "sslscan", "ping", "traceroute"}:
            assert "http://" not in cmd_out and "https://" not in cmd_out, f"[{tool}] Failed to strip HTTP scheme!"

    print("\n[+] All generation tests passed successfully for all 21 tools!")

if __name__ == "__main__":
    test_comprehensive_generation()
