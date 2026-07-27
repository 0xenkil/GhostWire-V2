import asyncio
from core.session import EngagementSession
from tools.tool_manager import ToolManager
from core.wsl_executor import WSLExecutor
from core.state_store import StateStore


async def main():
    store = StateStore(":memory:")
    session = EngagementSession("http://test.com", "test_dynamic", store)
    executor = WSLExecutor()
    executor.connect()
    manager = ToolManager(session=session, state_store=store)
    manager.remote = executor
    manager.ensure_installed = lambda x: True

    # Test 1: Broken flag (nmap --max-retries-count)
    print("=== TEST 1: Broken Flag ===")
    cmd = "nmap --max-retries-count 1 127.0.0.1"
    print(f"Original Command: {cmd}")
    res = manager.run("nmap", cmd, "test", timeout=30)
    print(f"Final Command executed: {res.command}")
    print(f"Success: {res.success}, Exit Code: {res.exit_code}")
    print("-" * 40)

    # Test 2: Broken path (ffuf -w /fake/path/resolv.conf)
    print("=== TEST 2: Broken Path ===")
    cmd = "ffuf -w /tmp/antigravity_fake_path/resolv.conf -u http://127.0.0.1/FUZZ"
    print(f"Original Command: {cmd}")
    res = manager.run("ffuf", cmd, "test", timeout=30)
    print(f"Final Command executed: {res.command}")
    print(f"Success: {res.success}, Exit Code: {res.exit_code}")
    print("-" * 40)

    # Test 3: Nuclei templates
    print("=== TEST 3: Nuclei Template ===")
    cmd = "nuclei -u http://127.0.0.1 -tags cve"
    print(f"Original Command: {cmd}")
    res = manager.run("nuclei", cmd, "test", timeout=300)
    print(f"Final Command executed: {res.command}")
    print(f"Success: {res.success}, Exit Code: {res.exit_code}")
    print("-" * 40)

if __name__ == "__main__":
    asyncio.run(main())
