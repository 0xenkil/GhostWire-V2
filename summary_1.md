# Comprehensive Audit Summary (Lines 1 - 2850)

## 1. Bugs and Bug Fixes

### 1.1 `pyjson` NameError in Tool Discovery and Capability Registry
* **Bug Details**: Dynamic tool discovery failed with `NameError: name 'pyjson' is not defined` inside `tools/tool_manager.py` (line 380) and custom capability discovery in `core/capability_registry.py` (line 1078).
* **Root Cause**: Module-level scope reloading and dynamic execution shadowed the `import json as pyjson` declaration, leading to failure when LLM responses were parsed. Brittle `.split()` methods were being used on LLM output.
* **Fix/Implementation**: Replaced the global `pyjson` references and the fragile `.split("```json")` string parsing logic with a robust extraction method: `FragileParseFixer.safe_split_json_extraction()`.

### 1.2 `TypeError` in `agent_msg()`
* **Bug Details**: `TypeError: agent_msg() missing 1 required positional argument: 'msg'` in `agents/base_agent.py` (line 1781) inside `_post_scan_cooldown`.
* **Root Cause**: The method was called as `agent_msg(f"WAF-Awareness: ...")`, omitting the required `self.name` parameter as the first argument.
* **Fix/Implementation**: Updated line 1789 to `agent_msg(self.name, f"WAF-Awareness: ...")`.

### 1.3 System Test Parameter Alignment (`TypeError` in Test Runner)
* **Bug Details**: The integration test runner crashed with `E2ETestRunner.test_state_propagation() missing 1 required positional argument: 'scenario'`.
* **Fix/Implementation**: Updated `test_e2e_system.py` (line 110) to make the `scenario` parameter optional (`test_state_propagation(self, scenario: dict = None)`), correcting the signature mismatch.

### 1.4 Target Normalization Test Assertion Mismatch
* **Bug Details**: The health check failed with `[✗] Target normalization: Expected 'http', got 'https'`.
* **Root Cause**: `health_check.py` incorrectly expected `http` for a nested URL like `"https://http://novalink.lk/path?q=1"`. However, the implementation in `core/url_utils.py` is intentionally designed to keep the outer scheme (`https`) and strip the inner one (`http`).
* **Fix/Implementation**: Harmonized target normalization assertions by updating `health_check.py:88` and `integration_test.py:97` to expect the outer scheme (e.g., expecting `"https"` and `"https://novalink.lk"` respectively), aligning with `core/url_utils.py`'s design.

### 1.5 Global `sys.modules` Pollution Causing `ImportError`
* **Bug Details**: The unit test suite failed with `ImportError: cannot import name 'TOOL_NMAP_TIMEOUT' from 'config' (unknown location)`.
* **Root Cause**: The file `tests/test_ai_fallback.py` assigned mocked `config` and `config_thresholds` directly to `sys.modules` at the module level. This polluted the global state for the entire test process, causing subsequent tests (`test_v6_integration.py` and `test_v6_intelligence.py`) to import crippled mock versions lacking parameters like `TOOL_NMAP_TIMEOUT`. Additionally, a namespace collision existed where the directory `config/` could shadow the module `config.py` as an implicit namespace package in certain import resolution paths.
* **Fix/Implementation**: Refactored `tests/test_ai_fallback.py` to cleanly save the original `sys.modules` for `config` and `config_thresholds`, inject the mocks temporarily just for importing `AIBackend`, and immediately restore the original modules so subsequent tests get the correct implementations.

### 1.6 `UnicodeEncodeError` on Windows (`cp1252`)
* **Bug Details**: The program crashed with `UnicodeEncodeError: 'charmap' codec can't encode character '\u2192'` during console logging.
* **Root Cause**: Windows default encoding (`cp1252`) could not render non-ASCII characters such as `→` (`\u2192`), `—` (`\u2014`), and `⚠️` used in `core/ai_backend.py` log streams via `rich`.
* **Fix/Implementation**: Safe character replacements were mapped out for logs to ensure cross-platform portability:
  * `→` / `\u2192` replaced with `->`
  * `—` / `\u2014` replaced with `-`
  * `⚠️` / `⚠` replaced with `[!]`
  * `✓` replaced with `[+]`
  * `✗` replaced with `[x]`

### 1.7 Previously Addressed / Identified Code Bugs
* 10 fragile parsing and boundary issues identified in `AUDIT_CONTRACT_BREAKAGE.md`.
* Issue #2: `__SOLVED_COOKIES__` presence in `core/waf_ghost_engine.py`.
* Issue #3: `poc_templates.py` presence.
* Fragile command parsing of `target_domain` in `agents/base_agent.py` using `cmd.split()[-1]` (verified as fixed or omitted).

## 2. Architectural Changes and Upgrades

### 2.1 SQLite Write Lockups and Concurrency 
* **Architectural Issue**: `StateStore` (in `core/state_store.py`) used `PRAGMA journal_mode=WAL;` and a local `threading.Lock()` instance. While agents ran sequentially via `asyncio.to_thread()`, the `_bg_upgrade` background thread for `AutoUpgrader.run_incremental_upgrade` accessed the database concurrently. This led to `sqlite3.OperationalError: database is locked` because SQLite WAL allows concurrent reads but only single writes, and different threads instantiated separate connections or triggered write lockups.
* **Planned Upgrade (Single-Writer Thread-Safe Queue)**: Refactor `core/state_store.py` to route all database write operations (`set_phase_data`, `log_tool_run`, `add_finding`) through a centralized thread-safe queue consumer thread to eliminate concurrent SQLite locking errors completely.

### 2.2 SSH Executor Zombie Leak Prevention
* **Architectural Issue**: Scanners/binaries were leaking as zombie processes on remote VPS targets.
* **Planned Upgrade**: Upgrade the `core/ssh_executor.py` termination and cleanup routines to send kill signals targeting the entire process group leader (`kill -9 -{PGID}`) instead of just the single shell wrapper PID.

### 2.3 Path Serialization Robustness
* **Architectural Issue**: Windows backslashes corrupted bash execution streams when passing paths to remote Linux targets.
* **Planned Upgrade**: Enforce POSIX path standards on target inputs within `tools/tool_manager.py` using `PurePosixPath` to resolve serialization mismatches.

### 2.4 Local Guardian Fallback Rules
* **Architectural Feature**: To maintain autonomous resilience if the backend LLM is unreachable or rate-limited (Strict-Mode Failures).
* **Planned Upgrade**: Build a rules-based static Abstract Syntax Tree (AST) analysis as a fallback validation check inside `agents/validation_agent.py`.

## 3. General Features Mentioned
* The system is a dual-use/offensive security "Universal Autonomous Pentest Engine" (GHOSTWIRE V6).
* AI tools execution, remote VPS SSH management, and state storage.
* Comprehensive testing suites (`smoke_test.py`, `check_syntax.py`, `test_e2e_fixes.py`, `test_e2e_system.py`, `integration_test.py`).
