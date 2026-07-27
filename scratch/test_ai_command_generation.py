from agents.specialists import ReconSpecialist, ExploitSpecialist
from tools.tool_manager import ToolManager
from core.session import EngagementSession
from core.ai_backend import AIBackend
from core.state_store import StateStore
import sys
import json
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))


def extract_action(response: str):
    """Simple parser to extract tool and command from the AI's ReAct response"""
    try:
        import re
        match = re.search(r'```json(.*?)```', response, re.DOTALL)
        if match:
            data = json.loads(match.group(1).strip())
            return data.get("tool"), data.get("command")

        match = re.search(r'\{.*\}', response, re.DOTALL)
        if match:
            data = json.loads(match.group(0).strip())
            return data.get("tool"), data.get("command")
    except Exception as _e:
        import logging
        logging.getLogger(__name__).warning(f"Swallowed exception: {_e}")
    return None, None


def test_command_generation():
    print("[*] Initializing mock components for testing...")
    store = StateStore('test_campaign')
    ai = AIBackend(store)
    session = EngagementSession(
        target='example.com',
        engagement_id='test_campaign',
        mode='pentest')
    tools = ToolManager(session, store, ai)

    print("[*] Learning tool syntaxes dynamically (this may take a moment)...")
    # Pre-learn the syntaxes to populate the cache
    for tool in ['hydra', 'sqlmap', 'ffuf', 'gobuster', 'masscan', 'nuclei']:
        tools.learn_tool_syntax(tool)

    print("[*] Initializing specialists...")
    recon = ReconSpecialist(
        session=session,
        state_store=store,
        tool_manager=tools,
        ai_backend=ai,
        message_bus=None,
        scope_enforcer=None)
    exploit = ExploitSpecialist(
        session=session,
        state_store=store,
        tool_manager=tools,
        ai_backend=ai,
        message_bus=None,
        scope_enforcer=None)

    scenarios = [
        {
            "agent": exploit,
            "scenario": "We found an API endpoint at http://api.target.com/v1/users. It requires an 'Authorization: Bearer <token>' header and accepts POST requests with JSON data. We need to fuzz the 'id' field in the JSON payload `{\"id\": \"FUZZ\"}` using the wordlist 'ids.txt'.",
            "expected_tool": "ffuf"
        },
        {
            "agent": exploit,
            "scenario": "We are testing a blind SQL injection on http://example.com/login. The injection point is inside the 'User-Agent' header. The request is a GET request. Use sqlmap to dump the database 'users' while routing traffic through a proxy at http://127.0.0.1:8080.",
            "expected_tool": "sqlmap"
        },
        {
            "agent": exploit,
            "scenario": "We discovered an SSH service running on a non-standard port 2222 at 10.0.0.5. We have a combined credentials file 'creds.txt' formatted as 'user:pass'. Use hydra to brute force the service.",
            "expected_tool": "hydra"
        },
        {
            "agent": recon,
            "scenario": "Perform a comprehensive nmap scan against 192.168.1.100. We need to scan all 65535 TCP ports, perform service and OS detection, use timing template 4, and do not ping the host before scanning.",
            "expected_tool": "nmap"
        },
        {
            "agent": recon,
            "scenario": "We need to discover virtual hosts on the target domain target.com. The web server is at 10.0.0.10. Use gobuster to enumerate vhosts using 'vhosts.txt', and hide all 400 and 404 status codes from the output.",
            "expected_tool": "gobuster"
        },
        {
            "agent": recon,
            "scenario": "Run a targeted nuclei scan against https://example.com to check ONLY for known CVEs and misconfigurations (using tags). Rate limit the scan to 50 requests per second to avoid triggering the WAF.",
            "expected_tool": "nuclei"
        },
        {
            "agent": recon,
            "scenario": "We suspect example.com is running WordPress. Enumerate all vulnerable plugins, vulnerable themes, and users.",
            "expected_tool": "wpscan"
        },
        {
            "agent": exploit,
            "scenario": "We need to quickly test if a JWT endpoint at https://api.example.com/auth is vulnerable to the 'None' algorithm. Send a crafted POST request with JSON payload `{\"token\": \"eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJ1c2VyIjoiYWRtaW4ifQ.\"}`.",
            "expected_tool": "curl"
        },
        {
            "agent": recon,
            "scenario": "Perform deep active intelligence gathering on 'target.com' using amass. Include whois lookups and active certificate grabbing.",
            "expected_tool": "amass"
        },
        {
            "agent": exploit,
            "scenario": "We have an SMB share at //10.0.0.5/IPC$ that allows anonymous login (no password). We need to list the contents of the share.",
            "expected_tool": "smbclient"
        },
        {
            "agent": recon,
            "scenario": "Find emails and subdomains for target.com using theharvester with google and bing data sources.",
            "expected_tool": "theharvester"
        },
        {
            "agent": recon,
            "scenario": "Enumerate the Windows host at 10.0.0.10 using enum4linux.",
            "expected_tool": "enum4linux"
        },
        {
            "agent": recon,
            "scenario": "Query the TXT records for example.com using dig.",
            "expected_tool": "dig"
        },
        {
            "agent": recon,
            "scenario": "Perform a whois lookup on example.com.",
            "expected_tool": "whois"
        },
        {
            "agent": recon,
            "scenario": "Find subdomains for target.com using subfinder.",
            "expected_tool": "subfinder"
        },
        {
            "agent": recon,
            "scenario": "Check if http://example.com is behind a Web Application Firewall.",
            "expected_tool": "wafw00f"
        },
        {
            "agent": recon,
            "scenario": "Scan the SSL/TLS configuration of https://example.com.",
            "expected_tool": "sslscan"
        },
        {
            "agent": recon,
            "scenario": "Identify the web technologies used on http://example.com.",
            "expected_tool": "whatweb"
        },
        {
            "agent": recon,
            "scenario": "Fuzz directories on http://example.com/ using dirsearch and extensions php,txt,html.",
            "expected_tool": "dirsearch"
        },
        {
            "agent": exploit,
            "scenario": "Connect to a reverse shell listener at 10.0.0.2 port 4444 using netcat.",
            "expected_tool": "nc"
        }
    ]

    print("\n" + "=" * 50)
    print("STARTING SCENARIO TESTS")
    print("=" * 50 + "\n")

    for i, s in enumerate(scenarios):
        agent = s["agent"]
        scenario_text = s["scenario"]
        print(f"--- SCENARIO {i + 1} ---")
        print(f"Goal: {scenario_text}")

        # Build prompt
        system_prompt, _ = agent._build_initial_prompt()
        user_prompt = f"Target: example.com\n\nTask: {scenario_text}\nDecide the next action.\nYou must respond ONLY with a JSON object containing 'tool' and 'command' keys, for example:\n```json\n{{\"tool\": \"nmap\", \"command\": \"nmap -p- example.com\"}}\n```"

        # Query AI
        print("Querying AI...")
        response = agent._query_ai(system_prompt, user_prompt)

        # Extract command
        tool, command = extract_action(response)

        print(f"Expected Tool: {s['expected_tool']}")
        print(f"AI Selected Tool: {tool}")
        print(f"AI Generated Command: {command}")
        print("-" * 50 + "\n")


if __name__ == "__main__":
    test_command_generation()
