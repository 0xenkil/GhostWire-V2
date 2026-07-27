import sys
import os
import re
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import config_paths
from core.session import EngagementSession
from core.target_context import TargetContext
from core.ai_backend import AIBackend
from agents.base_agent import BaseAgent

def test_path_segregation():
    print("=== Testing Path Segregation ===")
    original_temp = config_paths.WSL_TEMP_DIR
    original_results = config_paths.WSL_RESULTS_DIR
    print(f"Original Temp: {original_temp}")
    print(f"Original Results: {original_results}")
    
    ctx = TargetContext.from_input("novalink.lk")
    session = EngagementSession(mode="pentest", target_context=ctx)
    print(f"Engagement ID: {session.engagement_id}")
    print(f"New WSL Temp: {config_paths.WSL_TEMP_DIR}")
    print(f"New WSL Results: {config_paths.WSL_RESULTS_DIR}")
    
    assert session.engagement_id in config_paths.WSL_TEMP_DIR
    assert session.engagement_id in config_paths.WSL_RESULTS_DIR
    assert config_paths.WSL_RESULTS_DIR == f"{config_paths.WSL_TEMP_DIR}/results"
    print("[SUCCESS] Path segregation test passed!\n")

def test_tag_cleaning():
    print("=== Testing Tag Cleaning ===")
    ai = AIBackend()
    test_str = "<|start_header_id|>assistant\nHere is the command:\n<|start_header_id|>user\nnmap -p 80 novalink.lk<|eot_id|>"
    cleaned = ai._clean_llama_tags(test_str)
    print(f"Raw string:\n{test_str}")
    print(f"Cleaned string:\n{cleaned}")
    assert "<|" not in cleaned
    assert "|>" not in cleaned
    assert "start_header_id" not in cleaned
    print("[SUCCESS] Llama-3 tag cleaning test passed!\n")

def test_target_validation():
    print("=== Testing Target Validation & Nuclei Wordlist Correction ===")
    # Dummy subclass of BaseAgent to test safe_run_tool behavior
    class TestAgent(BaseAgent):
        async def run(self):
            return {}
            
    # Mock objects for instantiation
    from unittest.mock import MagicMock
    session = EngagementSession(mode="pentest", target_context=TargetContext.from_input("novalink.lk"))
    store = MagicMock()
    tool_mgr = MagicMock()
    ai = MagicMock()
    bus = MagicMock()
    scope = MagicMock()
    
    agent = TestAgent("test_agent", session, store, tool_mgr, ai, bus, scope)
    
    # 1. Test nuclei wordlist path correction in _canonicalize_tool_command
    raw_nuclei = "nuclei -u https://novalink.lk -t ~/redteam-workspace/ai_wordlist.txt"
    canonical = agent._canonicalize_tool_command("nuclei", raw_nuclei)
    print(f"Original Nuclei cmd: {raw_nuclei}")
    print(f"Canonicalized cmd: {canonical}")
    assert "ai_wordlist.txt" not in canonical
    assert "-t" not in canonical
    
    # 2. Test target validation helper check
    # command with target
    host = agent._extract_host("nmap -p 80 novalink.lk")
    print(f"Extracted host: {host}")
    assert host == "novalink.lk"
    
    # command without target but exempt (help command)
    help_cmd = "nmap --help"
    host_help = agent._extract_host(help_cmd)
    is_exempt_help = bool(re.search(r'(?<!\S)(?:-h|--help|-version|--version|-iL|-l|-dL|-list|--list|--input-file)\b', help_cmd))
    print(f"Help command: {help_cmd}, host: {host_help}, is_exempt: {is_exempt_help}")
    assert host_help is None
    assert is_exempt_help is True
    
    # command without target but exempt (list targets)
    list_cmd = "nmap -iL /tmp/list.txt"
    host_list = agent._extract_host(list_cmd)
    is_exempt_list = bool(re.search(r'(?<!\S)(?:-h|--help|-version|--version|-iL|-l|-dL|-list|--list|--input-file)\b', list_cmd))
    print(f"List command: {list_cmd}, host: {host_list}, is_exempt: {is_exempt_list}")
    assert is_exempt_list is True
    
    print("[SUCCESS] Target validation and nuclei parsing tests passed!\n")

if __name__ == "__main__":
    test_path_segregation()
    test_tag_cleaning()
    test_target_validation()
