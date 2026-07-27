<div align="center">

# ⚡ GHOSTWIRE V7 — Autonomous AI Red Team Engine ⚡

[![Python Version](https://img.shields.io/badge/Python-3.10%2B-blue?style=for-the-badge&logo=python)](https://www.python.org/)
[![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)](LICENSE)
[![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20WSL2%20%7C%20Windows-orange?style=for-the-badge&logo=linux)](https://ubuntu.com/)
[![Architecture](https://img.shields.io/badge/Architecture-Multi--Agent%20Autonomous-purple?style=for-the-badge)](https://github.com/)
[![Status](https://img.shields.io/badge/Status-Active%20Development-brightgreen?style=for-the-badge)]()

*Next-generation autonomous security assessment framework powered by adaptive LLM reasoning, persistent engagement memory, and dynamic evasion techniques.*

</div>

---

## 📌 Executive Overview

**GHOSTWIRE V7** is an advanced, fully autonomous AI-driven penetration testing and red teaming platform. Built from the ground up to replace static rule-based scanners, Ghostwire leverages a **multi-agent AI pipeline**, **dynamic attack-graph reasoning**, and **zero-hardcoding decision engines**.

Rather than relying on static scripts, Ghostwire learns from every scan: tracking tool success rates, observing technology stacks, fingerprinting WAF behaviors, mutating payloads in real time, and maintaining strategic memory across engagements.

> ⚠️ **Disclaimer**: This tool is developed exclusively for legal security research, authorized penetration testing, and defensive auditing under explicit written consent.

---

## 🔥 Key Features

### 🤖 1. Zero-Hardcoding AI Decision Engine
- **Strategic Advisor (`intelligence/strategic_advisor.py`)**: Persistent knowledge base that tracks tool effectiveness, success probabilities, average execution times, and optimal discovery pathways.
- **Self-Awareness Engine (`intelligence/self_awareness_module.py`)**: Continuously monitors agent confidence levels, validates assumptions, tracks knowledge gaps, and prevents overconfident execution.
- **Reasoning Engine (`intelligence/reasoning_engine.py`)**: Evaluates attack prerequisites, risk factors, and exploit chains prior to payload execution.

### 🛡️ 2. Self-Learning WAF Ghost Engine & Evasion
- **WAF Fingerprinter & Learner (`waf_fingerprinter.py`, `waf_learner.py`)**: Identifies Cloudflare, AWS WAF, Akamai, Imperva, ModSecurity, and custom web application firewalls.
- **Adaptive Payload Mutation**: Automatically tries header manipulation, rate-limit bypassing, character encoding, chunked transfer encoding, and HTTP parameter pollution when WAF blocks are encountered.
- **Historical Evasion Memory**: Remembers proven evasion tactics per target tech-stack to bypass security controls on future runs.

### 👥 3. Multi-Agent Autonomous Orchestration
- **Reconnaissance Agent**: Subdomain enumeration, service fingerprinting, port scanning, and OSINT aggregation.
- **Exploitation Agent**: Dynamic CVE lookup, exploit routing, and vulnerability validation.
- **Weaponization Agent**: Custom payload generation, sandboxed syntax validation, and obfuscation.
- **Objectives & Persistence Agent**: Post-exploitation validation, target graph expansion, and privilege escalation pathway mapping.
- **Reporting Agent**: Generates comprehensive executive summaries, technical vulnerability details, CVSS scoring, and actionable remediation steps.

### 🌐 4. Flexible Execution Environment
- **WSL2 & Native Linux Execution**: Seamlessly executes security tools (e.g., `nmap`, `nuclei`, `sqlmap`, `ffuf`, `subfinder`, `httpx`, `amass`) via native Linux shell or WSL integration.
- **VPS & Remote Execution**: Supports remote SSH execution and VPS pool management for distributed assessments.
- **IP Rotation & Stealth Proxying**: Integrated proxy chain capabilities and TOR/VPS routing to prevent IP banning.

---

## 🏗️ Architecture

```
                                ┌───────────────────────────────┐
                                │     Target Objective & Scope  │
                                └───────────────┬───────────────┘
                                                │
                                ┌───────────────▼───────────────┐
                                │    Strategic AI Advisor       │
                                │  (Persistent Knowledge Base)  │
                                └───────────────┬───────────────┘
                                                │
       ┌────────────────────────────────────────┼────────────────────────────────────────┐
       │                                        │                                        │
┌──────▼────────────────┐            ┌──────────▼───────────┐            ┌───────────────▼────────┐
│ Reconnaissance Agent  │            │ Self-Awareness Module│            │  WAF Evasion Engine    │
│ (Subdomain/Ports/Web) │            │ (Knowledge & Gaps)   │            │ (Fingerprint & Bypass) │
└──────┬────────────────┘            └──────────┬───────────┘            └───────────────┬────────┘
       │                                        │                                        │
       └────────────────────────────────────────┼────────────────────────────────────────┘
                                                │
                                ┌───────────────▼───────────────┐
                                │     Attack Graph Engine       │
                                │   (Finding Scorer & CVEs)     │
                                └───────────────┬───────────────┘
                                                │
       ┌────────────────────────────────────────┴────────────────────────────────────────┐
       │                                                                                 │
┌──────▼────────────────┐                                                       ┌────────▼───────────────┐
│ Exploitation Agent    │                                                       │ Reporting & Analytics  │
│ (PoC & Verification)  │                                                       │ (HTML/JSON/MD Reports) │
└───────────────────────┘                                                       └────────────────────────┘
```

---

## 📁 Codebase Structure

```text
ghostwire-v7/
├── agents/                      # Autonomous Specialized Agents
│   ├── base_agent.py            # Core Agent base class & LLM interaction loop
│   ├── recon_agent.py           # Passive & Active Reconnaissance logic
│   ├── exploitation_agent.py    # Target exploitation & vulnerability validation
│   ├── weaponization_agent.py   # Payload sandboxing & obfuscation
│   ├── persistence_agent.py     # Attack path expansion & post-exploitation
│   ├── objectives_agent.py     # Goal tracking & target state analysis
│   └── reporting_agent.py       # Technical & Executive report generation
├── core/                        # Engine Core & Execution Handlers
│   ├── orchestrator.py          # Central engine controller & state manager
│   ├── ai_backend.py            # Multi-provider LLM API client wrapper
│   ├── capability_registry.py   # Tool capability definitions & execution wrappers
│   ├── wsl_executor.py          # WSL2 Linux bridge for Windows host
│   ├── ip_rotator.py            # Dynamic proxy & IP rotation controller
│   ├── target_graph.py          # Attack surface node-link graph
│   └── waf_ghost_engine.py      # Core WAF detection & payload mutation pipeline
├── intelligence/                # AI Intelligence & Learning Modules
│   ├── strategic_advisor.py     # Historical learning & tool recommendations
│   ├── self_awareness_module.py # Confidence tracking & knowledge gap analysis
│   ├── reasoning_engine.py      # Multi-step strategic attack planner
│   ├── cve_database.py          # Technology-to-CVE mapper
│   ├── finding_scorer.py        # Severity, confidence & priority calculator
│   └── waf_evasion_engine.py    # WAF tactic strategy selector
├── tools/                       # Tool Integration & Execution Wrappers
│   ├── tool_manager.py          # Native CLI tool execution & timeout handlers
│   └── output_parser.py         # Standardized JSON parser for security tool output
├── config.py                    # Global system configuration & safety thresholds
├── main.py                      # CLI entrypoint & interactive shell
└── requirements.txt             # Python dependencies
```

---

## 🚀 Installation & Setup

### Prerequisites
- **OS**: Linux (Ubuntu 22.04+ recommended) or Windows 10/11 with **WSL2** installed.
- **Python**: Python 3.10 or higher.
- **Security Tools** (Installed on Linux/WSL): `nmap`, `nuclei`, `sqlmap`, `subfinder`, `httpx`, `ffuf`, `amass`.

### Step 1: Clone Repository
```bash
git clone https://github.com/0xeni0l/red-team-V2.git
cd red-team-V2
```

### Step 2: Set Up Virtual Environment & Dependencies
```bash
python3 -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

### Step 3: Configure Environment (.env)
Create a `.env` file in the root directory:
```ini
# LLM API Provider Keys
GEMINI_API_KEY=your_gemini_api_key_here
OPENAI_API_KEY=your_openai_api_key_here
ANTHROPIC_API_KEY=your_anthropic_api_key_here

# OSINT API Keys (Optional but Recommended)
SHODAN_API_KEY=your_shodan_key
SECURITYTRAILS_API_KEY=your_securitytrails_key
VIRUSTOTAL_API_KEY=your_virustotal_key

# WSL Configuration (If running on Windows host)
USE_WSL=true
WSL_DISTRO=Ubuntu
```

---

## 💻 Usage

### 1. Interactive Mode
Run Ghostwire's CLI shell to launch guided engagements:
```bash
python main.py
```

### 2. Autonomous Target Assessment
Launch an automated full-scope assessment against a target domain:
```bash
python main.py --target example.com --mode full --output ./reports/example_scan
```

### 3. Reconnaissance-Only Mode
```bash
python main.py --target example.com --mode recon
```

---

## 🔒 Safety & Legal Disclaimer

Ghostwire V7 includes mandatory safety constraints and scope-enforcement safeguards:
- **Written Consent Safeguard**: Built-in confirmation flags to verify authorization before executing active scans.
- **Strict Out-of-Scope Blocking**: Automatically drops any target IP/domain outside the explicit authorization list.
- **Circuit Breaker System**: Prevents accidental DoS conditions by enforcing rate limits and monitoring server response health.

> **LEGAL NOTICE**: Penetration testing without prior authorization is illegal. The developers of Ghostwire assume no liability for misuse, unauthorized scanning, or damages caused by this software. Use strictly in compliance with applicable local and international cybersecurity laws.

---

## 📜 License

Distributed under the **MIT License**. See `LICENSE` for more information.
