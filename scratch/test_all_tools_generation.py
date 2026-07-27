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

def test_all_tools():
    session = DummySession()
    store = DummyStateStore()
    
    # 1. Initialize ToolManager with WSL remote enabled (respecting get_config())
    tm = ToolManager(session, store, ai_backend=None)
    agent = TestAgent(tm)
    
    print("=== DYNAMIC FLAG RESOLUTION (HELP MENUS) ===")
    
    # List of offensive tools to test dynamic help parsing
    tools_to_test = [
        "nmap", "masscan", "dig", "curl", "wget", "sslscan", 
        "nikto", "gobuster", "ffuf", "sqlmap", "nuclei", "hydra"
    ]
    
    installed_tools = []
    for tool in tools_to_test:
        # Check if installed on WSL
        if tm.remote:
            ec, _, _ = tm.remote.execute(f"which {tool}", timeout=3)
            is_installed = (ec == 0)
        else:
            import shutil
            is_installed = bool(shutil.which(tool))
            
        print(f"Tool '{tool}': {'INSTALLED' if is_installed else 'NOT INSTALLED'}")
        if is_installed:
            installed_tools.append(tool)
            
            # Fetch valid flags dynamically via help menu
            flags = tm.get_tool_valid_flags(tool)
            print(f"  -> Extracted {len(flags)} valid flags from --help")
            if len(flags) > 0:
                print(f"  -> Sample flags: {list(flags)[:5]}")
            else:
                print("  -> Warning: No flags extracted (might be in unreliable_help_tools or safety guard triggered)")
                
    print("\n=== VERIFYING PROACTIVE CORRECTION & DYNAMIC normalizations ===")
    
    # Test 1: Sqlmap invalid option stripping (proactive correction)
    if "sqlmap" in installed_tools:
        cmd_in = "sqlmap -u http://novalink.lk --crawl-depth=2 --threads=5 --batch"
        cmd_out = tm._validate_and_fix_command(cmd_in, "sqlmap")
        print(f"Sqlmap original: {cmd_in}")
        print(f"Sqlmap corrected: {cmd_out}")
        assert "--crawl-depth" not in cmd_out, "Failed to strip --crawl-depth from sqlmap"
        assert "--batch" in cmd_out, "Stripped valid flag --batch from sqlmap"
        print("Sqlmap proactive stripping: PASS")
        
    # Test 2: Hydra URL normalization (no hardcoded stripping or translation)
    if "hydra" in installed_tools:
        cmd_in = "hydra -l admin -P /tmp/wordlist.txt http://novalink.lk/tiki/"
        cmd_out = agent._canonicalize_tool_command("hydra", cmd_in, "novalink.lk")
        print(f"Hydra original: {cmd_in}")
        print(f"Hydra corrected: {cmd_out}")
        assert "http-get://" in cmd_out, "Hydra failed to normalize http to http-get!"
        
        # Test 3: Hydra POST form normalization
        cmd_in_post = "hydra -l admin -P /tmp/wordlist.txt http://novalink.lk/login.php:user=^USER^&pass=^PASS^:failed"
        cmd_out_post = agent._canonicalize_tool_command("hydra", cmd_in_post, "novalink.lk")
        print(f"Hydra POST original: {cmd_in_post}")
        print(f"Hydra POST corrected: {cmd_out_post}")
        assert "http-post-form://" in cmd_out_post, "Hydra failed to normalize http to http-post-form!"
        print("Hydra URL normalization: PASS")
        
    # Test 4: Nuclei template directory correction
    if "nuclei" in installed_tools:
        # Mock _is_remote_path_valid for non-existent path
        old_is_valid = agent._is_remote_path_valid
        agent._is_remote_path_valid = lambda path: False if "/tmp/antigravity/" in path else True
        
        cmd_in = "nuclei -u http://novalink.lk -t /tmp/antigravity/nuclei-templates/cves/2023/ -ni"
        cmd_out = agent._canonicalize_tool_command("nuclei", cmd_in, "novalink.lk")
        print(f"Nuclei original: {cmd_in}")
        print(f"Nuclei corrected: {cmd_out}")
        assert "/tmp/antigravity/" not in cmd_out, "Failed to correct invalid template prefix!"
        assert "cves/2023/" in cmd_out, "Lost template folder suffix!"
        
        agent._is_remote_path_valid = old_is_valid
        print("Nuclei template path correction: PASS")
        
    # Test 5: Gobuster header splits avoidance (from our previous fix)
    if "gobuster" in installed_tools:
        # Mock WafGhostEngine to run transform
        from core.waf_ghost_engine import WafGhostEngine
        ghost = WafGhostEngine()
        cmd_in = "gobuster dir -u http://novalink.lk/ -w /tmp/wordlist.txt"
        cmd_out = ghost.transform(cmd_in, "gobuster", level=2)
        print(f"Gobuster original: {cmd_in}")
        print(f"Gobuster transformed: {cmd_out}")
        # Make sure no comma-based languages exist in headers
        assert "en;q=0.9" not in cmd_out, "Gobuster contains comma-separated header value!"
        print("Gobuster header evasion format: PASS")

if __name__ == "__main__":
    test_all_tools()
