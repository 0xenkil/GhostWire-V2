# Full Program Architecture Report

---

## Overview
This document provides a comprehensive, code‑driven architectural analysis of the **Red Team** automation framework located at `C:/Users/ASUS/Desktop/red team`. Every component, package, and key class is described based solely on the source code, without external assumptions.

---

## Architecture Diagram

![](file:///C:/Users/ASUS/.gemini/antigravity/brain/9192f495-4fd4-4963-a820-51a956d44cda/full_analysis_diagram_1779786713009.png)

---

## Package / Module Overview

| Package | Key Modules / Classes | Primary Responsibility |
|---------|----------------------|------------------------|
| **agents** | `base_agent.BaseAgent`, `exploitation_agent.ExploitationAgent`, `recon_agent.ReconAgent`, `...` | High‑level autonomous agents that receive goals from the orchestrator and drive tool execution. |
| **core** | `orchestrator.Orchestrator`, `session.EngagementSession`, `target_context.TargetContext`, `state_store.StateStore`, `ip_rotator.IpRotator`, `waf_ghost_engine.WafGhostEngine`, `waf_evasion_engine.WafEvasionEngine` | Core runtime engine, state management, IP rotation, WAF evasion logic, and session bookkeeping. |
| **utils** | `display`, `validator`, `network`, `file_utils` (if present) | Helper functions for pretty printing, input validation, and low‑level OS interactions. |
| **config** | `config.py`, `config_backends.py`, `config_paths.py`, `config_thresholds.py` | Central configuration values, feature flags, API keys, and threshold constants. |
| **tests** | `integration_test.py`, `test_e2e_system.py`, `smoke_test.py`, etc. | Unit and integration test suite exercising end‑to‑end flows. |
| **scripts** | Various helper scripts (`health_check.py`, `audit_hardcoded.py`, etc.) | Maintenance and diagnostic utilities. |
| **core/ai_backend** | `ai_backend.AIBackend` | Abstraction over local (Ollama) and cloud LLM providers. |
| **core/target_context** | `TargetContext` | Parses and normalises user‑provided target strings (URL, IP, domain). |
| **core/state_store** | `StateStore` | SQLite‑based persistence layer for engagement state. |
| **core/ip_rotator** | `IpRotator` | Tor integration for dynamic proxy rotation. |
| **core/waf_ghost_engine** | `WafGhostEngine` | Implements three evasion levels (header randomisation, payload mutation, protocol obfuscation). |
| **core/waf_evasion_engine** | `WafEvasionEngine` | Orchestrates `WafGhostEngine` based on stealth config. |
| **core/orchestrator** | `Orchestrator` | Drives the ReAct loop: selects actions, invokes agents, handles retries, logs to `StateStore`. |
| **core/session** | `EngagementSession` | Holds runtime context (mode, target, scope, ROE, operator, AI backend, stealth config). |
| **core/debug_snapshot** | Utilities for debug logging. |
| **main.py** | Entry point, CLI argument parsing, pre‑flight checks, session creation, orchestrator launch. |

---

## Data Flow (High‑Level)
1. **CLI / Headless Invocation** → `main.py` parses arguments.
2. **Pre‑flight Checks** → Validates platform, Python version, AI backends, required config, and writes a test file to `results/`.
3. **Configuration Gathering** → Functions `get_mode`, `get_target`, `get_scope`, `get_ai_choice`, `get_roe`, `get_stealth_config`, `get_operator` populate a `EngagementSession`.
4. **Session Creation** → `EngagementSession` stores all runtime parameters and creates a unique `results_dir`.
5. **Orchestrator Instantiation** → `Orchestrator(session)` loads the `StateStore` and sets up the ReAct loop.
6. **ReAct Loop** (in `core/orchestrator.py`):
   - Agent (e.g., `BaseAgent`) receives a goal → generates a tool‑call plan.
   - `Orchestrator` executes the plan, optionally passing through `WafEvasionEngine` and `IpRotator`.
   - Results are persisted via `StateStore` and logged to the console.
7. **Shutdown** → On completion or interrupt, the orchestrator closes the `StateStore` and cleans up resources.

---

## Detailed Component Walk‑through
### `main.py`
- Sets UTF‑8 handling for Windows.
- Uses **Rich** for interactive prompts and styled output.
- Performs **pre‑flight diagnostics** (platform, Python, AI backends, required modules).
- Handles **legal consent** flow.
- Constructs the **session** object with all user‑chosen parameters.
- Instantiates **Orchestrator** and runs it inside an asyncio event loop.

### `core/orchestrator.py`
- Contains the `Orchestrator` class with `run()` method.
- Implements the **ReAct** decision loop: selects actions via an LLM, parses tool calls, executes them, and feeds back observations.
- Interfaces with `StateStore` to record each step, enabling replay and audit.
- Handles **graceful shutdown** and exception logging.

### `core/session.py`
- Holds immutable configuration for the engagement.
- Generates a unique `engagement_id` and creates `results_dir`.
- Provides convenience properties for accessing stealth config, ROE, AI backend, etc.

### `core/state_store.py`
- SQLite wrapper that stores **events**, **tool calls**, and **agent observations**.
- Provides query utilities for reporting and debugging.

### `core/waf_ghost_engine.py`
- Implements three evasion **levels**:
  1. Header randomisation and user‑agent rotation.
  2. Payload mutation (string obfuscation, base64 encoding).
  3. Protocol‑level tricks (delayed sends, chunked encoding).
- Exposes `transform(request)` that applies enabled levels based on the stealth config.

### `core/ip_rotator.py`
- Starts a Tor subprocess (via `stem` library) when `rotate_ip` is enabled.
- Provides `rotate()` method returning a new SOCKS proxy address for each request.

### `agents/base_agent.py`
- Abstract base for concrete agents (`ExploitationAgent`, `ReconAgent`, etc.).
- Implements `analyze`, `plan`, `execute` hooks that the orchestrator calls.
- Uses the injected `AIBackend` to generate reasoning steps.

### `agents/exploitation_agent.py` (example)
- Focuses on vulnerability verification and payload delivery.
- Calls `WafEvasionEngine` before sending exploit payloads.

### `utils/display.py`
- Centralised Rich‑based UI helpers (`banner`, `section`, `info`, `error`, etc.).
- Provides consistent theming across CLI.

---

## Recommendations / Observations
- **Documentation Gap**: While code is self‑descriptive, a high‑level README summarising the flow would aid new contributors.
- **Testing Coverage**: Integration tests cover the happy path; consider adding unit tests for `WafGhostEngine` level‑specific transformations.
- **Thread‑Safety**: `StateStore` currently uses a single SQLite connection; if parallel agents are introduced, migrate to a writer thread (actor pattern) to avoid contention.
- **PDF Export**: The markdown can be rendered to PDF with Pandoc (see the generated `full_analysis_report.pdf`).

---

*End of Report*
