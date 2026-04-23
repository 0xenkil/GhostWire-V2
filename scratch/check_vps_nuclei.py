import os
import sys
from pathlib import Path
from core.session import EngagementSession
from tools.tool_manager import ToolManager
from core.state_store import StateStore
from core.ai_backend import AIBackend

# Add current dir to path
sys.path.append(os.getcwd())

eng_id = "eng_656b4e50"
db_path = Path("results") / eng_id / "state.db"
store = StateStore(db_path)

# Initialize session with dummy values
session = EngagementSession(
    target="kandyx.lk",
    mode="redteam",
    scope=["kandyx.lk"],
    rules_of_engagement={"allow_exploitation": True}
)
session.engagement_id = eng_id

ai = AIBackend()
tools = ToolManager(session, store, ai_backend=ai)

if tools.remote:
    print("Checking VPS nuclei status...")
    # Get last 5 lines of the log
    exit_code, out, err = tools.remote.execute("tail -n 5 /tmp/antigravity/buffers/1b22871c.log")
    print(f"LATEST NUCLEI LOGS:\n{out}")
    
    # Check if process is still running
    exit_code, out, err = tools.remote.execute("ps aux | grep nuclei | grep -v grep")
    print(f"PROCESS LIST:\n{out}")
else:
    print("Remote VPS not configured/active.")
