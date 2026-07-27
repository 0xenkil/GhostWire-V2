import sys
import os
import re

sys.path.append(r"C:\Users\ASUS\Desktop\red team")

from agents.base_agent import BaseAgent
from core.target_context import TargetContext

class DummySession:
    def __init__(self):
        self.engagement_id = "test_eng"
        self.target = "https://novalink.lk/"
        self.target_context = None
        self.rules_of_engagement = {"allow_exploitation": True}
        self.results_dir = "results"
        self.session_dir = "results"

class DummyStateStore:
    def set_phase_status(self, *args, **kwargs): pass
    def log_tool_run(self, *args, **kwargs): pass
    def get_all_findings(self, *args): return []
    def get_phase_data(self, *args): return {}

class TestAgent(BaseAgent):
    def __init__(self):
        session = DummySession()
        store = DummyStateStore()
        super().__init__(
            name="test_agent",
            session=session,
            state_store=store,
            tool_manager=None,
            ai_backend=None,
            message_bus=None,
            scope_enforcer=None
        )
        
    def run(self):
        return {}

agent = TestAgent()

print("=== TESTING HYDRA SYNTAX REPAIR & URL TRANSLATION ===")
cmd_hydra1 = "hydra -l admin -P /tmp/antigravity/ai_wordlist.txt http://novalink.lk/tiki/"
repaired_hydra1 = agent._canonicalize_tool_command("hydra", cmd_hydra1, "novalink.lk")
print("Original:", cmd_hydra1)
print("Repaired:", repaired_hydra1)
assert "http-get://novalink.lk/tiki/" in repaired_hydra1, "Hydra HTTP GET URL translation failed!"
print("Hydra GET URL translation: PASS")

cmd_hydra2 = "hydra -l admin -P /tmp/antigravity/ai_wordlist.txt http://novalink.lk/tiki/tiki-login.php:user=^USER^&pass=^PASS^:login_failed"
repaired_hydra2 = agent._canonicalize_tool_command("hydra", cmd_hydra2, "novalink.lk")
print("Original:", cmd_hydra2)
print("Repaired:", repaired_hydra2)
assert "http-post-form://novalink.lk/tiki/tiki-login.php:user=^USER^&pass=^PASS^:login_failed" in repaired_hydra2, "Hydra HTTP POST URL translation failed!"
print("Hydra POST URL translation: PASS")

print("\n=== TESTING NUCLEI DYNAMIC TEMPLATE PATH CORRECTION ===")
# Mock _is_remote_path_valid to return False for /tmp/antigravity/ paths
def mock_is_remote_path_valid(path):
    if "/tmp/antigravity/" in path:
        return False
    return True
agent._is_remote_path_valid = mock_is_remote_path_valid

cmd_nuclei1 = "nuclei -u http://novalink.lk/tiki/ -t /tmp/antigravity/nuclei-templates/ -ni"
repaired_nuclei1 = agent._canonicalize_tool_command("nuclei", cmd_nuclei1, "novalink.lk")
print("Original:", cmd_nuclei1)
print("Repaired:", repaired_nuclei1)
assert "nuclei-templates" not in repaired_nuclei1 or "~/nuclei-templates" in repaired_nuclei1, "Nuclei templates base fallback failed!"
assert "/tmp/antigravity/" not in repaired_nuclei1, "Nuclei templates failed to strip invalid prefix!"
print("Nuclei Base fallback: PASS")

cmd_nuclei2 = "nuclei -u http://novalink.lk/tiki/ -t /tmp/antigravity/nuclei-templates/cves/2023/CVE-2023-xxxx.yaml -ni"
repaired_nuclei2 = agent._canonicalize_tool_command("nuclei", cmd_nuclei2, "novalink.lk")
print("Original:", cmd_nuclei2)
print("Repaired:", repaired_nuclei2)
assert "cves/2023/CVE-2023-xxxx.yaml" in repaired_nuclei2, "Nuclei suffix path got lost!"
assert "/tmp/antigravity/" not in repaired_nuclei2, "Nuclei prefix replacement failed!"
print("Nuclei Suffix preservation: PASS")

cmd_nuclei3 = "nuclei -u http://novalink.lk/tiki/ -t /tmp/antigravity/nuclei-templates/cves/,/tmp/antigravity/nuclei-templates/exposures/ -ni"
repaired_nuclei3 = agent._canonicalize_tool_command("nuclei", cmd_nuclei3, "novalink.lk")
print("Original:", cmd_nuclei3)
print("Repaired:", repaired_nuclei3)
assert "/tmp/antigravity/" not in repaired_nuclei3, "Nuclei comma-separated path replacement failed!"
assert "exposures/" in repaired_nuclei3, "Nuclei exposures path got lost!"
print("Nuclei Comma-separated parsing: PASS")

print("\n=== TESTING PROACTIVE FLAG CORRECTOR FOR SQLMAP ===")
class DummyRemote:
    def execute(self, cmd, timeout=15):
        if "sqlmap" in cmd:
            # mock help output containing valid flags
            return 0, "--crawl=CRAWL          Crawl website starting from target URL\n-u URL, --url=URL      Target URL\n--dump                 Dump DBMS database table entries\n-v VERBOSE             Verbosity level\n--batch                Never ask for user input\n--forms                Parse and test forms", ""
        return 1, "", ""

from tools.tool_manager import ToolManager
tm = ToolManager(session=DummySession(), state_store=DummyStateStore(), ai_backend=None)
tm.remote = DummyRemote()

sqlmap_cmd = "sqlmap -u http://novalink.lk --crawl-depth=2 --dump"
corrected = tm.validate_and_filter_flags(sqlmap_cmd, "sqlmap")
print("Original:", sqlmap_cmd)
print("Corrected:", corrected)
assert "--crawl-depth" not in corrected, "Proactive Flag Corrector failed to strip --crawl-depth!"
assert "--dump" in corrected, "Proactive Flag Corrector stripped valid flag --dump!"
print("Sqlmap flag correction: PASS")
