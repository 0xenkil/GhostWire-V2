<div align="center">

# ⚡ GHOSTWIRE V8 — Autonomous AI Red Team Engine ⚡

[![Python Version](https://img.shields.io/badge/Python-3.12%2B-blue?style=for-the-badge&logo=python)](https://www.python.org/)
[![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)](LICENSE)
[![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20WSL2%20%7C%20VPS-orange?style=for-the-badge&logo=linux)](https://ubuntu.com/)
[![Architecture](https://img.shields.io/badge/Architecture-Multi--Agent%20Autonomous-purple?style=for-the-badge)](https://github.com/0xenkil/GhostWire-V2)
[![Proof](https://img.shields.io/badge/Findings-Evidence--Proven-red?style=for-the-badge)]()
[![Status](https://img.shields.io/badge/Status-Active%20Development-brightgreen?style=for-the-badge)]()

*An autonomous security-assessment engine that doesn't just **find** vulnerabilities — it **proves** them, with non-forgeable, re-measurable Evidence.*

</div>

---

## 📌 Executive Overview

**GHOSTWIRE V8** is a fully autonomous, AI-driven penetration-testing engine built around one hard rule: **a vulnerability is only "confirmed" if the engine can PROVE it with a measured control-vs-test differential — never because a tool's output contained a scary-looking string.**

Most autonomous scanners inflate their reports with unverified matches. V8's **Evidence-first proof spine** makes that impossible by construction: every "proven" finding is backed by a persisted, re-measurable `Evidence` object in a single-writer `ProofLedger`. If the measurement doesn't reproduce, the finding degrades to an honest *lead* — the engine under-reports rather than fabricates.

On top of that spine sits a **zero-hardcoding multi-agent pipeline** that recons, reasons, evades WAFs, exploits, and — the headline capability — **autonomously discovers a parameter and proves an injection on it end-to-end.**

> ⚠️ **Disclaimer**: For legal security research, authorized penetration testing, and defensive auditing under explicit written consent only.

---

## 🔥 Key Features

### 🧬 1. Evidence-First Proof Spine — *no false victories*
- **`core/proof.py`** — `ProofLedger` / `ProofContext` / `ProofRegistry`. `stamp()` is the **sole** way to mint Evidence; it **re-measures** `is_proven()` and only persists on success.
- **Non-forgeable proof types**: `differential` (measured control-vs-test delta, similarity < 0.97), `artifact` (canary present-in-test / absent-in-control), `oob` (observed out-of-band token). `proof_type` alone is never sufficient.
- **One gate everywhere** — `finding_is_proven()` re-computes proof from the persisted row; severity validation, ops-sanity, and the report all key on it, never on a substring like `"VULN_PROVEN"`.
- **Honest success signal** — `ToolResult.produced_result()` separates "the tool ran" from "the tool found something," so a clean-but-empty scan reads `NO_FINDINGS`, not a win.

### 🎯 2. Autonomous Exploit → Proof
- **Surface probe + lead bridge (`agents/exploitation_agent.py`)** — discovers parameterized endpoints (mines crawl output and self-fetches the target), then proves injections with a deterministic **true/false differential** (`param AND 1=1` vs `AND 1=2`) sent as **exact** HTTP requests and stamped through the ledger. Generic — no per-tool parsing, no hardcoded payload tables.
- Correctly leaves **secure parameters alone** (a stable response ⇒ no differential ⇒ no finding), so it discriminates real bugs from hardened decoys.

### 🤖 3. Zero-Hardcoding AI Decision Engine
- **Strategic Advisor** — durable, proven-fed knowledge of tool effectiveness and evasion tactics (atomic writes, multi-writer safe).
- **Grounding** — before running any tool, the engine fetches its real `--help` and rewrites the command to match, correcting flag hallucinations for *any* tool, including ones it has never seen.
- **Truth-gated self-upgrade** — learned optimizations apply only when a held-out **proven-rate** is non-regressing.

### 🛡️ 4. Self-Learning WAF Evasion & Egress Causality
- Fingerprints Cloudflare / AWS WAF / Akamai / Imperva / ModSecurity and adapts payloads (headers, encoding, chunking, HPP), remembering what worked per tech-stack.
- **Egress-causality probe** distinguishes a *target* block from a *self-egress* (your own Tor/proxy) block, so the engine stops wasting the whole budget rotating IPs against its own 403.

### ⚙️ 5. Convergence, Budget & Resilience
- **Deterministic convergence breaker** (staleness-since-last-gain) abandons doomed loops with no LLM call — a single early finding no longer grants a stuck loop permanent immunity.
- **Bounded** AI-recovery and rate-limit sleeps (a hostile `Retry-After: 3600` can't freeze an engagement); async recovery so phase timeouts can fire; budget-gated self-correction.

### 👥 6. Multi-Agent Orchestration
- **Recon** (subdomains, ports, services, web crawl) → **Exploitation** (hypothesis test → validate → prove) → **Weaponization** (sandboxed payloads) → **Reporting** (proven-vs-lead split, CVSS, remediation).

### 🌐 7. Flexible Execution
- Native Linux, **WSL2** (Windows host), or **VPS**. Runs `nmap`, `nuclei`, `sqlmap`, `ffuf`, `gobuster`, `subfinder`, `httpx`, `katana`, `gau`, `dnsx`, etc. — auto-installed per package manager (apt / pip / **`go install`**, arch-correct). Optional Tor / proxy-chain routing with **fail-closed stealth**.

---

## 🏗️ Architecture

```
                          ┌───────────────────────────────┐
                          │      Target, Scope & ROE       │
                          └───────────────┬───────────────┘
                                          │
                          ┌───────────────▼───────────────┐
                          │   Orchestrator + Strategic     │
                          │   Advisor (proven-fed memory)  │
                          └───────────────┬───────────────┘
        ┌─────────────────────────────────┼─────────────────────────────────┐
 ┌──────▼────────────┐          ┌──────────▼──────────┐          ┌───────────▼─────────┐
 │ Reconnaissance    │          │  WAF Evasion +      │          │  Grounding + Tool   │
 │ (subdomains/web)  │          │  Egress Causality   │          │  Catalog / Installer│
 └──────┬────────────┘          └──────────┬──────────┘          └───────────┬─────────┘
        └─────────────────────────────────┼─────────────────────────────────┘
                                          │
                          ┌───────────────▼───────────────┐
                          │   Exploitation Agent          │
                          │   hypothesis → TEST → PROVE    │
                          │   (surface probe + differential)│
                          └───────────────┬───────────────┘
                                          │  proof_ctx
                          ┌───────────────▼───────────────┐
                          │   ProofLedger (single writer) │
                          │   stamp() ⇒ re-measure is_proven│
                          └───────────────┬───────────────┘
                                          │  finding_is_proven
                          ┌───────────────▼───────────────┐
                          │   Reporting (Proven vs Lead)  │
                          └───────────────────────────────┘
```

---

## 📁 Codebase Structure

```text
GhostWire-V2/
├── agents/
│   ├── base_agent.py            # Agent base: LLM loop, command grounding/repair, convergence breaker
│   ├── recon_agent.py           # Recon; WAF signal derivation (labelled hypothesis, not fact)
│   ├── exploitation_agent.py    # Hypothesis test → PROVE; surface probe + lead→self-proof bridge
│   ├── weaponization_agent.py   # Sandboxed payloads (real proof, no substring wins)
│   └── reporting_agent.py       # Proven-vs-lead split, CVSS, remediation
├── core/
│   ├── proof.py                 # ★ ProofLedger / ProofContext / ProofRegistry / finding_is_proven
│   ├── result_contracts.py      # Evidence.is_proven(), ToolResult.produced_result()
│   ├── state_store.py           # Single-writer store; tool_run→finding linkage
│   ├── egress_probe.py          # Self-egress vs target block attribution
│   ├── orchestrator.py          # Phase controller (async, checkpointed)
│   ├── ai_backend.py            # Multi-provider LLM client; bounded recovery
│   ├── llm_backend.py           # LLMBackend Protocol (token budget aligned)
│   ├── failure_record.py        # Structured observability
│   └── capability_registry.py   # Tool capability definitions
├── intelligence/
│   ├── hypothesis_engine.py     # Reason → hypothesise → validate (differential judge)
│   ├── learning_signal.py       # Proof-anchored LearningOutcome
│   ├── truth_gate.py            # Gate self-upgrade on held-out proven-rate
│   ├── strategic_advisor.py     # Durable, proven-fed tool/evasion memory
│   ├── objective_ledger.py      # Proof-gated objective completion
│   └── waf_bypass/technique.py  # WafTechnique Protocol → Evidence|None
├── tools/
│   ├── tool_manager.py          # Local-or-remote exec, grounding, wordlist/path/output repair, installs
│   ├── tool_catalog.py          # Capability-keyed catalog (apt/pip/go install methods)
│   └── output_parser.py         # CR-safe, fidelity-preserving parsers
├── tests/                       # 486 tests (proof spine, bridge, convergence, egress, …)
├── config*.py                   # Config (env > YAML > default)
├── main.py                      # CLI entrypoint (fail-fast Python 3.12+ guard)
└── requirements.txt
```

> V8 removed dead modules that inflated trust or misdirected audits: `constraint_engine`, `finding_scorer`, `engagement_recorder`, `unified_config_loader`, `attack_graph`, `config_manager`.

---

## 🚀 Installation & Setup

### Prerequisites
- **OS**: Linux (Ubuntu 22.04+) or Windows 10/11 with **WSL2**. VPS supported.
- **Python 3.12+** — required (the engine uses PEP 701 multi-line f-strings; it will **not** run on 3.10/3.11).
- **Security tools** (Linux/WSL): `nmap`, `nuclei`, `sqlmap`, `subfinder`, `httpx`, `ffuf`, `gobuster`, `katana`, `gau`, `dnsx`. Missing Go tools are auto-installed via `go install` (arch-correct).

### Step 1 — Clone
```bash
git clone https://github.com/0xenkil/GhostWire-V2.git
cd GhostWire-V2
```

### Step 2 — Virtual environment & dependencies
```bash
python3.12 -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

### Step 3 — Configure `.env`
Copy `.env.example` to `.env` and fill in keys (never commit `.env`):
```ini
AI_BACKEND=groq                    # Groq is PRIMARY; Gemini is the FALLBACK
GROQ_API_KEYS=gsk_key1,gsk_key2    # single key or comma-separated pool
GOOGLE_API_KEY=                    # Gemini fallback (paid key recommended for full runs)
GOOGLE_MODEL=gemini-3.1-flash-lite
OLLAMA_BASE_URL=http://localhost:11434
OLLAMA_MODEL=

# Execution backend (WSL is auto-disabled on non-Windows hosts)
USE_WSL=true
USE_REMOTE_VPS=false
```

---

## 💻 Usage

Autonomous, headless engagement against an authorized target:
```bash
python main.py --headless --yes --ai groq --target example.com
```

Common flags:
```bash
--target <host|url>     # authorized target (in-scope)
--headless --yes        # non-interactive, auto-confirm
--ai groq|gemini        # lead AI backend
--stealth               # route via Tor (fail-closed if unverifiable)
--destructive           # allow destructive actions (off by default)
--brute-force           # allow brute-force (off by default)
```

Findings are split into **PROVEN** (a `[proof:<id>]` token backed by a ledger row that re-measures) and **leads** (unverified, honestly labelled).

---

## 🧪 Testing

```bash
python -m pytest tests/ -q
```
**486 tests** cover the proof spine, the exploit→proof bridge, convergence, egress attribution, budget/recovery bounds, and command-quality repair.

---

## 🔒 Safety & Legal

- **Strict scope enforcement** — targets outside the declared scope, and **loopback / private / reserved ranges** (`127.0.0.0/8`, `10.0.0.0/8`, `192.168.0.0/16`, …), are refused by `core/scope_enforcer.py`.
- **Fail-closed stealth** — if requested anonymity can't be verified (e.g. raw-socket tools under Tor), the run blocks rather than leaking the real IP.
- **No fabricated findings** — the proof spine under-reports before it over-claims.

> **LEGAL NOTICE**: Unauthorized penetration testing is illegal. The developers assume no liability for misuse. Use strictly under explicit authorization and applicable law.

---

## 📜 License

Distributed under the **MIT License**. See `LICENSE`.
