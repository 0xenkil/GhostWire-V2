# GhostWire V7 — Root-Cause Deep Analysis
**Date:** 2026-07-29
**Method:** Evidence-driven. Traced against real run logs (`live_run_novalink.log`, `last ran cli out.txt`) and the live code — not the docs, not prior audit reports.
**Scope:** Why the autonomous engine fails at multiple points and does not do what it is intended to do. Root causes at the *decision/architecture* layers, not per-tool bugs.

> **Framing (important).** GhostWire is designed to be fully autonomous and zero-hardcoding: the AI can pick any tool, install it from anywhere, and use it. Therefore "a tool is broken" is **not** a root cause — the root causes live in the layers *above* every tool: how the engine **decides**, **executes**, **classifies results**, **attributes failure**, **learns**, and **hands data between phases**. Fixing individual tools or adding hardcoded signatures fights the design and deepens the disease.

---

## THE ONE META ROOT CAUSE

**The engine has no model of *causality*.** It cannot tell whether a failure originates in its **own environment** (egress path / privileges / LLM-budget) or in the **target**. So every self-inflicted or environmental failure is misattributed to the target and answered with an autonomous remediation aimed at the target — which cannot possibly work — so it loops until the LLM budget is exhausted and the run degrades into empty/invented output.

Every distinct failure you observe is one branch of that single cascade.

---

## THE CASCADE (quantified from one real run: `last ran cli out.txt`)

| Signal in ONE run | Count | What it actually is |
|---|---|---|
| `403` responses | **573** | Tor exit IPs blocked by Cloudflare — the engine's *own egress*, not the target |
| labeled `waf` | **153** | those 403s misattributed to a target WAF |
| `evasion` attempts | **86** | wrong remediation fired at the wrong cause |
| `AI REPAIR` / `repair attempt` | **43 / 41** | LLM budget burned on unfixable conditions |
| `exhausted` (backend) | **9** | backends starving as a result |
| Tor exit-IP rotations | 8 | all landing on `109.70.100.10 → .15`, same blocked range |

Cross-run corpus signature frequency (`failures.txt`, `errors_*.txt`): `waf 208`, `timeout 178`, `tor 127`, `json 46`, `parse 40`, `proxy 19`, `rate-limit 9`, raw-socket/privilege ~20. The privilege/nmap issue is real but **minor**; the dominant mass is egress + misattribution + LLM starvation.

---

## ROOT CAUSES BY LAYER (initial — deep dive appends below)

### RC-1 — Self-inflicted egress (Execution layer)
`agents/base_agent.py:903 _apply_stealth_routing` force-wraps **every** HTTP/TCP tool in `proxychains4 → Tor` whenever Tor is verified active. Tor exits are high-latency and Cloudflare-blocklisted → 573× 403 + 178 timeouts. This hits **every web tool identically** (httpx's consistent ~5.3s failures = Tor timeout, not syntax).

### RC-2 — Misattribution in the result classifier (Classification layer)
`tools/tool_manager.py:1528` maps **any** output containing `403 forbidden` / `429` / `cloudflare ray id` → `waf_blocked`, regardless of cause. A Tor-block, a real WAF, and a geo-block are indistinguishable to it — even though the engine *knows* it is on Tor. Parallel defect in `agents/base_agent.py:2872`: `exit 0 + "QUITTING"` counts as SUCCESS because the false-positive guard only matches an argparse-style signature list (no `quitting` / `requires root` / `couldn't open a raw socket`).

### RC-3 — Remediation loops with no convergence check (Decision layer)
Misdiagnosed WAF → rotate Tor circuit → another blocked Tor IP → still 403 → repeat (86 evasions). Privilege error → guess flags (`--privileged`) → still fails. The loops optimize for "make the command exit cleanly," not "produce a valid result," and have no detector for "this remediation cannot change the outcome."

### RC-4 — Feedback amplification / LLM starvation (Intelligence layer)
Every loop spawns LLM calls. Ollama offline + 2 backends → 9 exhaustion events → truncated/empty AI responses → the json/parse failure family → worse decisions → more loops. The "hallucination" prior audits blamed on a parser is **backend starvation caused by loop volume**, not a parser bug.

### RC-5 — Verdict corruption + poisoned learning (Memory layer)
Classifier keys on exit-code + a tiny signature list, not result *validity* → false "success" → `intelligence/syntax_learner.py` **permanently** persists garbage (`nmap … --privileged`) across engagements. Empty results and all-ports-open Tor connect-scans (`results/eng_067e427d/raw/recon_nmap_*.txt`) enter the datastore as real findings.

### RC-6 — Net effect (Orchestration layer)
Recon produces nothing real / garbage → nothing validates plausibility before hand-off → exploitation runs blind → invents targets. End symptom = "hallucination."

---

## DEEP DIVE — per layer, per agent, and interconnections

### Architecture map (data + control flow)

```
main.py ─ get_target/scope/roe/stealth ─► Orchestrator.run()
   │                                            │  (core/orchestrator.py)
   │  builds: AIBackend, StateStore, ToolManager(+WSLExecutor),
   │          IPRotator(Tor), ScopeEnforcer, all agents
   ▼
Orchestrator: phase loop (planning→recon→exploitation→…→reporting)
   │  gates: PHASE_REQUIRES + BLOCKING_STATUSES + has_findings() override
   │  each phase → agent.run() → BaseAgent.run_react()
   ▼
BaseAgent.run_react()  [the shared brain, agents/base_agent.py]
   │  loop (≤20 iters): _query_ai → _parse_ai_response → _execute_v6_action
   │        └► safe_run_tool(): stealth-route → execute → CLASSIFY → repair loop
   │                              │                         │        └► _ai_repair_tool (LLM)
   │                              │                         └► _interpret_outcome (LLM triage)
   │                              └► _apply_stealth_routing → proxychains→Tor
   │  records → StateStore + Advisor + Awareness + WafLearner + SyntaxLearner
   ▼
StateStore (sqlite)  ── phase data / findings ──►  next phase reads it
```

The whole system funnels through **one method — `safe_run_tool` (base_agent.py:2161, ~1360 lines)**. Every agent, every tool, every phase executes through it. So a defect in its classify/repair/route logic is a defect in *everything*. This is why the failures look tool-agnostic — they are.

---

### DEEP-1 — The corrupted classifier BLINDS every safety net (this is the worst one)

`consecutive_failures`, the StrategicMentor trigger, the "Smart Error Recovery" ([SKIP]/[ABORT]/[REPAIR]), and `_track_failure` **all key off `result.success`** (base_agent.py:4741 `... and not parsed.result.success: consecutive_failures += 1`).

But `result.success` is exactly what RC-2 corrupts: `exit 0 + "QUITTING"/no real output` is booked as SUCCESS (nmap `--privileged`; whatweb/curl WAF responses force-set to success at tool_manager.py:1541-1545). Consequences:

- **False success → the failure counters never increment → the mentor/recovery never fire.** The agent proceeds *confidently* on garbage. The self-correction machinery is structurally blind to the most dangerous failure mode.
- **When failures ARE visible (real 403s), the safety nets fire but only add MORE LLM calls** (mentor transcript analysis, recovery decision) that cannot diagnose an egress problem — they just burn budget (feeding RC-4).

The engine's ability to *notice it is failing* is gated on the same verdict that is wrong. That's the deepest structural fault.

---

### DEEP-2 — The "Zero-Hardcoding AI Decision Engine" is mostly a write-only sink; its loop-breaker is dead code

Call-site census of the intelligence modules from the agents shows they are invoked almost entirely to **record** (`register_finding`, `record_tool_outcome`, `register_assumption`, `register_knowledge_gap`) — not to **decide**. The read/decision methods that exist are barely wired:

- `StrategicAdvisor.should_continue_trying()` — the explicit **loop-breaker** ("stop trying this tool, it won't work") — **is defined but NEVER called** anywhere in the codebase.
- `StrategicAdvisor.advise_waf_evasion()` — **never called.**
- `advise_tool_selection` / `advise_discovery_order` are called only inside `_strategic_advice_note()`, whose output is a soft text "note" appended to a prompt (base_agent.py:5534) — advisory, easily ignored by the LLM.

So the touted persistent "strategic memory" does not close the decision loop — and the little it does feed back is **poisoned by the corrupted verdicts it recorded** (DEEP-1). The convergence check that would stop RC-3's loops physically exists and is switched off.

---

### DEEP-3 — Backend exhaustion is a self-inflicted sleep-stall / crash (mechanism of RC-4)

`AIBackend.query()` (core/ai_backend.py:728) on total exhaustion: `get_shortest_recovery_time()` → **`time.sleep(recovery_time)`** then recurse, up to `_depth < 3`, else **raise** "All AI backends exhausted."

- Groq exhaustion is **TPD (tokens-per-day)** — the recovery window can be **hours**. The engine will *block the entire run* sleeping on it.
- The exhaustion is **caused by the loop volume** the earlier RCs generate (one run: 43 AI-repairs + 86 evasions + mentor + triage calls, on only 2 live backends with ollama offline).
- Positive feedback: more misattribution → more LLM calls → faster exhaustion → longer stalls / phase crash. `_query_ai` re-raises → `run_react` does not catch → phase dies as FAILURE.

This is the true source of the "hallucination" prior audits misattributed to `robust_parser`: **empty/late responses from a starved backend**, not a parser bug. (`ai_backend` even has "[FIX 3.4] returned empty response - treating as failure" guards — evidence empty responses are a known, recurring event.)

---

### DEEP-4 — Unbounded context rebuild → truncation → decision degradation

`_build_observation_prompt` (base_agent.py:4423) rebuilds the **entire** context every iteration: target JSON + **full** `_format_history()` + syntax guide + latest observation. Across ≤20 iterations this grows monotonically until it hits `_query_ai`'s `MAX_PROMPT = 120000`, which then **truncates the MIDDLE** of the message (base_agent.py:4379) — dropping the accumulated findings/observations that live in the middle. The AI loses state → re-issues actions it already tried → more loop iterations → more tokens → faster exhaustion (DEEP-3). Context management and budget starvation are coupled.

---

### DEEP-5 — No plausibility gate anywhere data is handed off

`ExploitationAgent._preflight` (exploitation_agent.py:18) accepts `recon_data["open_ports"]` **as-is** — an all-ports-open Tor-connect-scan artifact (`results/eng_067e427d/raw/recon_nmap_*.txt`: 65k "open" ports) sails through, and exploitation then tries to attack every phantom port (through Tor → 403/timeout → more loops). Alternatively it accepts "any finding at all." `StateStore.set_phase_data` validates *types*, not *plausibility*. Nothing between phases asks "is this result physically believable?" So RC-2/RC-5 garbage propagates the length of the kill chain.

---

### DEEP-6 — The WAF subsystem is 3,084 LOC of machinery firing largely on self-inflicted 403s

`intelligence/waf_*` + `core/waf_*` = **3,084 LOC** across 5 modules (ghost engine, bypass orchestrator, fingerprinter, learner, evasion engine). It is triggered by the `waf_blocked` status that RC-2 sets from **any** 403/429/"cloudflare" string — which on a Tor egress is constant and *not* a target WAF. The evasion loop's remedy (rotate Tor circuit → header mutation) produces another blocklisted Tor exit IP (run log: `109.70.100.10 → .15`, same range) → never converges (86 evasions/run). Enormous engineering solving a misdiagnosed problem. This is not a bug in the WAF code; it's the wrong subsystem being invoked because the *cause attribution* upstream is wrong.

---

### Per-agent notes

- **PlanningAgent (101 LOC):** thin; emits a phase plan via one LLM call. Fine. It over-promises tool chains (subfinder/whatweb/nmap/nuclei) the environment can't always run privileged, but planning itself isn't the fault.
- **ReconAgent (1,954 LOC):** where the cascade first ignites — subdomain enum works (returns real subs), but the web-probe (`httpx`) and port-scan (`nmap`) steps die on Tor/privilege and are booked empty-or-garbage. It *documents* the Tor-connect-scan false-positive (recon_agent.py:1155) yet still ships that data downstream. It is the largest producer of corrupted findings.
- **ExploitationAgent (2,368 LOC):** consumes recon's corrupted output with only a type-level preflight (DEEP-5); runs its own `safe_run_tool` loops → inherits every base-layer defect at higher volume (it has the biggest per-phase timeout, 7200s, so it burns the most budget).
- **Weaponization / Persistence / Objectives (633/225/91 LOC):** gated behind exploitation; if exploitation is blind they get empty input or are SKIPPED. Not independent faults.
- **ReportingAgent (756 LOC):** reads `awareness.get_confidence_report` / `advisor.get_confidence_report` — i.e. it reports *on the corrupted intelligence*, so a run that achieved nothing can still produce a confident-looking report. Cosmetic-success risk.
- **MentorAgent (58 LOC):** invoked at 3 consecutive *visible* failures; sees only the transcript, has no ground-truth on egress/privilege/budget, so its "pivot" advice is plausible but causally blind — pure added LLM cost.

---

## HOW THE ROOT CAUSES CHAIN (the single failure system)

```
       (opt-in)                        the engine never models its OWN state
  RC-1 Tor egress ──► 573×403/timeouts ──► RC-2 misattribute to TARGET (WAF/rate-limit)
                                                     │
                          exit0+error ─► false SUCCESS ─────────────┐
                                                     │              │
                                                     ▼              ▼
                              RC-3 wrong remediation loops     DEEP-1 safety nets BLINDED
                              (evade Tor→Tor, guess flags)     (counters key off .success)
                                                     │              │
                              DEEP-2 loop-breaker OFF ◄────────────┘
                                                     ▼
                              RC-4/DEEP-3 LLM call flood ─► backend exhaustion
                                                     │        ─► sleep-stall / phase crash
                              DEEP-4 context bloat ──┘        ─► empty responses ("hallucination")
                                                     ▼
                              RC-5 poisoned learning (syntax_learner persists garbage)
                              DEEP-5 no plausibility gate ─► garbage crosses phases
                                                     ▼
                              RC-6 exploitation blind ─► invents targets ─► useless report
```

**Every arrow is the same missing thing:** a grounded, machine-readable model of the engine's *own* operating state (egress reachability, privilege/capability, LLM budget) fed into (a) the result classifier, (b) the failure-attribution, and (c) the decision prompt — plus a plausibility gate on results and the *already-written* `should_continue_trying` convergence check turned on. None of that requires per-tool hardcoding; it is the exact opposite — it removes the brittle signature lists (`failure_sigs`, `waf_markers`) that are themselves misfiring.

---

## PRIORITY (corrected from the 2-tool view)

1. **RC-2 + DEEP-1 — result classification & attribution.** Highest leverage: it corrupts findings AND blinds the safety nets AND poisons learning. Everything else compounds off it.
2. **RC-1 + RC-3 + DEEP-2 — egress-aware remediation + wire up `should_continue_trying`.** Stops the self-inflicted 403/evasion loops.
3. **RC-4 + DEEP-3/4 — budget-aware loop control + bounded context.** Stops the starvation spiral that produces the "hallucination."
4. **RC-5 + DEEP-5 — gate learning & phase hand-off on validated/plausible results.** Stops garbage becoming permanent and crossing phases.

## What is NOT the problem (contra the earlier report)
WSL path translation (already correct, `posixpath`), `robust_parser` (graceful, LLM-only), orchestrator phase-gates (already `has_findings`-hardened), and generic missing-binary handling (exit-127 guarded). Chasing these — or adding more hardcoded signatures / per-tool patches — spends effort where the system already works and deepens the misattribution that is the real disease.

---
---

# ADVANCED DEEP DIVE (round 2) — the deepest root cause

The round-1 finding was "the engine never models its own state." That is **not quite right**, and the correction is the most important result in this document.

## META-RC-0 — Prompt-hope over enforcement (the disease under the disease)

The engine **does** compute accurate ground truth about itself. `_probe_capabilities()` (base_agent.py:4892) runs a **real** `SOCK_RAW` open test and correctly learns `raw_socket=False`. `_ip_rotator._tor_verified` knows Tor is on. `AIBackend` knows its budget/exhaustion state. The failure is what it does with that truth:

> **At every decision point the engine passes its ground truth to an LLM as *advisory prose* and hopes the model complies. It never converts the truth into a deterministic gate.**

The raw-socket constraint is injected in **three** separate LLM prompts, all clearly worded:
1. Generation — `_get_environment_snapshot` (base_agent.py:5010): *"Raw packet sockets (CAP_NET_RAW): UNAVAILABLE … Do NOT request privileged/raw scan types or `--privileged`."*
2. Grounding — `_ground_prescriptions` (base_agent.py:3942): *"drop `--privileged` and privileged-only scan modes."*
3. Repair — `_ai_repair_tool` (base_agent.py:4144) carries the same env snapshot.

**All three are advice. None is a gate.** And the live run proves advice loses:

```
draft:   nmap -sS novalink.lk                 → FAILURE "requires root privileges"
repair1: nmap -sS ... -p 1-1024               → FAILURE (still -sS)
repair2: nmap -sS ... --privileged -p 1-1024  → the repair LLM ADDED --privileged
```

`_ai_repair_tool` — the step that was *explicitly told* "do not use `--privileged`" — responded to the error string *"requires root privileges"* by **adding `--privileged`**. LLMs anchor on (a) training priors (`nmap -sS` is *the* canonical scan) and (b) the literal error text ("requires root" → escalate) over an in-context negative constraint buried in a multi-thousand-token prompt. This is not a prompt-wording bug you can fix with better wording; it is the structural limit of advice.

**Why this is THE root cause:** it explains why the codebase is littered with dozens of `# FIX …` / `# BUG FIX …` comments that never fixed anything. Every historical remediation was *more advice* (another sentence in a prompt) or *another LLM pass* (the grounding call, the triage call, the mentor call). You cannot buy correctness with advice — and each added LLM call **worsens the budget starvation (RC-4/DEEP-3)**. The "fixes" actively feed the disease.

There is **no deterministic enforcement layer** between command-generation and execution that says: `if cap['raw_socket'] is False and command requests a raw/privileged mode → reject or rewrite, deterministically, before it runs.` The ground truth exists; nothing enforces it.

## DEEP-7 — Where enforcement DOES exist, it is blind to the engine's own state

The two places the engine enforces deterministically both ignore the self-knowledge it already has:

- **WAF classifier** (`tool_manager.py:1528`): hard string-match on `403/429/cloudflare` → `waf_blocked`. It **never references `_tor_verified`, proxychains, or egress state** (confirmed: no `tor`/`egress`/`proxychains` token anywhere in `tool_manager.py`'s classifier). So a 403 that the engine *knows* came from its own Tor exit IP is enforced as a *target* WAF. Right to gate; blind input.
- **Command dedup** (`base_agent.py:2532`): exact `sha256(command)[:16]`. `-sS`, `-sS -p 1-1024`, `-sS --privileged` are three different hashes, so the privilege-guessing loop sails through — and the code comment defers responsibility to the model: *"The AI is responsible for not suggesting the exact same thing twice."* Enforcement too literal to catch a semantic loop, then hands the real check back to advice.

So the pattern has two symmetric failure modes: **(a) accurate self-knowledge used only as advice** (privilege, budget), and **(b) deterministic gates that never consult the accurate self-knowledge** (WAF/Tor, dedup). Both are the same missing wire: ground-truth self-state → enforcement point.

## DEEP-8 — Verdict-cache poisoning (a wrong judgement becomes permanent, cheaply)

`_interpret_outcome` caches its accept/abandon/repair verdict under `sig = tool + "|" + first-160-chars-of-output` (base_agent.py:2115):
- A **single** wrong verdict (e.g. "repair" on an unrecoverable privilege error) is **reused for the whole engagement** for that signature — a wrong call is amortised into many wrong calls.
- The 160-char key is **coarse**: two genuinely different errors that share a 160-char prefix collide to one verdict; the same error on a repairable vs. unrepairable command collides too.
- `_outcome_interp_cache` is **lazily created without a lock** (2116-2118) — under `check_liveness`'s `ThreadPoolExecutor(max_workers=10)` two threads can both see `None`, both assign a fresh dict, and lose one thread's cached verdicts (benign-ish but real).

## DEEP-9 — State integrity: crash residue and a shared autocommit connection

`StateStore` opens sqlite with `check_same_thread=False, isolation_level=None` (autocommit), `journal_mode=WAL`, and shares `self.conn` across the orchestrator's phase threads (a separate `write_conn` path at line 71 hints they already hit "database is locked"). Residue on disk corroborates the crash pattern from DEEP-3: `test_campaign-wal` = **420 KB** and `test-wal` = **140 KB** stranded against **4 KB** main DB files, and `ghostwire.db` is **0 bytes** — WAL that was never `wal_checkpoint(TRUNCATE)`'d because the phase died (backend-exhaustion crash) before checkpoint. Autocommit means the data isn't strictly lost, but the giant uncheckpointed WAL + zero-byte primary DB is a direct fingerprint of runs that terminate abnormally mid-phase.

## DEEP-10 — The "self-correction" stack is all LLM calls, so it scales the disease

Count the LLM calls triggered by ONE failing tool: `_interpret_outcome` (triage) → `_ai_repair_tool` (repair, ×up to 3) → `_ground_prescriptions` (grounding) → at 3 visible failures `StrategicMentor.advise` → possibly `Smart Error Recovery`. Every one is a round-trip to a 2-backend, ollama-down pool. So the machinery meant to *recover* from a failure is the machinery that *exhausts the budget* (DEEP-3) and *degrades the next decision* via truncation (DEEP-4). Recovery and starvation are the same code path.

---

## THE CORRECTED FIX PHILOSOPHY (why this is LESS code / LESS hardcoding, not more)

The instinct — and the whole history of this repo's `# FIX` comments — is to add more advice or more per-tool signatures. That is backwards. The cure is a thin **deterministic enforcement seam** that consumes the ground truth the engine *already computes*, and the **deletion** of the brittle signature lists that misfire:

1. **Capability gate (pre-execution):** one function, `enforce_capability(command, caps)`, run on every command right before `safe_run_tool` executes it. `raw_socket=False` → reject/rewrite privileged/raw/`--privileged` modes deterministically. No per-tool table — it keys on the *capability*, which is exactly the zero-hardcoding contract. This replaces prompt-hope #1/#2/#3 with one gate.
2. **Egress-aware attribution:** feed `_tor_verified` (and a cheap "is my own IP blocked?" control probe) into the classifier so a 403 is attributed to *egress* vs *target*. This lets you **delete** most of the `waf_markers` list and shrink the 3,084-LOC WAF subsystem's trigger surface.
3. **Budget-aware loop control:** before spawning repair/mentor/grounding LLM calls, check `AIBackend.remaining()`; shed load instead of sleeping-to-crash. Turn on the **already-written** `StrategicAdvisor.should_continue_trying()` as the convergence gate.
4. **Semantic dedup + plausibility gate:** normalise a command to its (tool, mode, target) intent for dedup so flag-variations of a dead command are caught; and a one-function plausibility check (`all-ports-open`, `empty-but-success`) before a result is stored/learned/handed to the next phase.
5. **Fix the classifier once (RC-2/DEEP-1):** success = "produced a valid, plausible result", not "exit code + a signature list". This single change un-blinds every safety net that currently keys off `.success`.

Net: **fewer** LLM calls (gates replace advisory passes), **less** hardcoded signature matching (attribution replaces string lists), and the self-knowledge the engine already has finally reaches the points that decide and enforce. That is the zero-hardcoding design actually realised — the current code only simulates it with prose.

---
---

# ROUND 3 — additional INDEPENDENT defects (broad sweep, not part of the egress cascade)

A separate hunt across security gates, provisioning, concurrency, and data integrity turned up defects that are **not** downstream of the egress/enforcement story — each one independently degrades or breaks a run. Several **correct earlier conclusions in this very document.**

## NEW-1 — The privilege model is self-defeating; the capability probe measures the WRONG context (corrects Round-1/2)

Earlier sections said "the environment has no raw-socket capability." **That is wrong.** The environment CAN do raw sockets — the engine already runs privileged operations through `wsl -u root` (every tool install does, `tool_manager.py:444`). The real defect is a three-way contradiction:

1. **Tool execution only escalates when the command string literally starts with `sudo`** (`tool_manager.py:1829`: `as_root = True` iff `command.strip().startswith("sudo")`). There is no other path to root at run time.
2. **`_probe_capabilities` tests `SOCK_RAW` as the NON-root default user** (base_agent.py:4906) → returns `raw_socket=False`. That is a *false negative about what the engine can achieve*, because it never probes the root path it uses for installs.
3. **The env snapshot then forbids the only thing that would work:** *"Do NOT request privileged/raw scan types or `--privileged`."* So the AI emits bare `nmap -sS` → runs non-root → "requires root privileges"; the repair LLM adds `--privileged` (which is *not* `sudo`, so it still runs as the non-root user and dies "Operation not permitted").

**The engine possesses root, measures itself as non-root, and instructs the AI away from the `sudo` prefix that is the exact fix.** Every raw-socket tool (`nmap -sS`, `masscan`, `naabu` SYN) is steered into guaranteed failure by the engine's own guidance. This is a first-class root cause and it is *not* an environment limitation — it is a privilege-handling contradiction.

## NEW-2 — The advertised toolset exceeds the provisionable toolset (the REAL `httpx` cause; corrects Round-1)

Round 1 guessed `httpx`'s consistent failures were a Tor timeout. The concrete cause is simpler: **`httpx` is not in `TOOL_REGISTRY` at all.** The recon prompt (recon_agent.py:1203) actively tells the AI to *"Prefer tools like: … httpx, … katana, gau, hakrawler, arjun …"*, but a direct check shows these are **all missing** from the registry:

```
httpx, katana, gau, hakrawler, arjun, assetfinder, dnsx, naabu, waybackurls  → NONE registered
```

An unregistered tool routes to `discover_tool` → the AI-install path, which **only matches `apt` and `pip`** (`tool_manager.py:322-323`). For a Go tool this is catastrophic: `pip install httpx` installs the **Python HTTP *library*** (no `httpx` CLI that behaves like the ProjectDiscovery Go prober); `apt install httpx` pulls a *different* Debian tool. So the engine ends up with the **wrong binary under the right name** — a tool-identity collision — and every `httpx <urls>` invocation fails or does the wrong thing. ~9 of the modern recon tools it advertises are broken **by construction**, before Tor or privileges even enter the picture.

## NEW-3 — Install/run privilege split → "installed successfully, command not found"

Installs run as **root** (`wsl -u root`), tools run as the **non-root** user. The runtime `WSL_TOOL_PATH` is `"$HOME/go/bin:$HOME/.local/bin:/usr/local/bin:…"` where `$HOME` expands for the **non-root** runner (`/home/<user>`). But a root `go install` writes to `/root/go/bin` and a root `pip install --user` to `/root/.local/bin` — **neither is on the non-root user's PATH.** Registry tools that target `/usr/local/bin` are fine; anything the AI-discovery path installs via go/pip-as-root is installed-but-invisible → exit 127 at run time despite a "successful" install. The two privilege contexts never agree on where binaries live.

## NEW-4 — Silent findings data-loss in `add_finding` (independent cause of "recon found nothing")

`add_finding` (base_agent.py:1290) builds `dedup_key = f"{finding_type}::{target}::{dedup_detail[:160]}"` and `return`s silently on a hit. The **160-char truncation** means two genuinely distinct findings that share a 160-char prefix collide and the second is **dropped without a trace**. The code comment admits they already shipped this exact bug once (*"all but the first of ~60 URLs were silently dropped"*) and only partially fixed it. Any finding class with a long common prefix (endpoints under a long base URL, verbose service banners, templated vuln descriptions) still silently loses members — so recon can *find* things and still *store* almost nothing.

## NEW-5 — Pervasive exception swallowing (40+ sites) makes failures invisible

A sweep found **63 `except` blocks** with **~40 that swallow** (`pass` / `continue` / `return None|{}|[]|False|""`); `base_agent.py` alone has 94 `except` clauses. Each swallow converts a real failure (a WSL call that errored, a store write that threw, a probe that crashed) into a silent empty result. This is the low-level fuel for the whole "the engine can't tell what failed" disease (RC-2/DEEP-1): you cannot attribute a failure you never recorded. Many are labelled "non-fatal," but collectively they hide the very signals the decision layer needs.

## NEW-6 — Wrong-package installs are cached as "installed" (the mistake becomes sticky)

The AI-install path validates package-name **characters**, not **identity**, then on a zero-exit `pip/apt install` marks the tool present (`self._installed_cache.add(tool_name)`). So once `pip install httpx` "succeeds" with the wrong package, the engine **believes `httpx` is installed for the rest of the engagement** and never retries with the correct method — the wrong-binary failure repeats every time the AI reaches for that tool. NEW-2 + NEW-6 together make the toolset gap permanent per run.

---

## Updated priority (with Round-3)

1. **NEW-1 privilege contradiction** + **RC-2/DEEP-1 classifier** — together they account for the nmap-class failures *and* the mislabelling that hides them. Highest leverage.
2. **NEW-2/NEW-3/NEW-6 provisioning** — register the modern Go toolset with correct `go install` + a shared bin dir on both privilege contexts' PATH; verify tool *identity*, not just exit code, before caching "installed". Without this the engine literally cannot run the tools it plans with.
3. **RC-1/RC-3/DEEP-2 egress + convergence**, **RC-4/DEEP-3 budget**, **NEW-4 findings loss**, **NEW-5 swallow audit** — the rest of the cascade and the silent-failure fuel.

## Correction log (this document supersedes its own earlier claims where noted)
- "Environment lacks raw-socket capability" (R1/R2) → **wrong**; capability exists via root, the engine mis-probes and self-forbids it (NEW-1).
- "`httpx` fails due to Tor timeout" (R1) → **wrong/incomplete**; `httpx` is unregistered and mis-installed (NEW-2).
- The egress/enforcement cascade (RC-1…6, DEEP-1…10) still stands, but it is **not the whole story** — NEW-1…6 are independent and would break runs even with Tor disabled.

---
---

# ROUND 4 — state, reporting, security, and messaging defects

Auditing the layers I had not yet touched (persistence/state writer, reporting, the payload "sandbox", the message bus, config coercion, deadline math).

## STATE-1 — Single writer thread + 10s write timeout → silent state loss under the loop-storm

`StateStore` funnels **every** write (findings, `tool_runs`, `phase_data`, failure patterns) through **one** background thread consuming `write_queue` (`_writer_loop`, state_store.py:68). Each caller blocks in `_submit_write` on `task['event'].wait(timeout=10.0)` and **raises `RuntimeError` on timeout** (state_store.py:107). Under the failure loops the earlier RCs generate — one run recorded 43 repairs + 86 evasions, each writing a `tool_run` + failure row — the single writer serialises behind a 10 s wall. When it slips past 10 s the write **raises**, and given the 40+ swallow sites (NEW-5) those raises become **silent lost findings / lost state**. So the same loop-storm that starves the LLM (RC-4) also drops the DB records that would let the engine (or you) see what happened. Writes are otherwise correct (synchronous, `UNIQUE` constraints, WAL) — the defect is the unbounded queue behind a fixed 10 s deadline with no backpressure.

## REPORT-1 — The reporting agent launders corrupted findings into a confident report

`ReportingAgent.run` reads real stored findings (`get_all_findings`) — good — but then **mutates severity in place** (`f["severity"] = "medium"`, reporting_agent.py:72) and generates the executive summary and technical section with `self.think()` (LLM prose, lines 131/156), instructed to include "evidence (including any mentioned PoC script filenames)". Consequences:
- A run whose "findings" are actually RC-2/DEEP-1 **false-positive successes** (empty-but-"success" scans, all-ports-open Tor artifacts) is written up as a polished, severity-graded report. The report's confidence is decoupled from whether anything real was found — the **cosmetic-success** failure mode made concrete.
- LLM narrative over a thin finding can **invent** evidence/PoC filenames that were never produced. Grounding is finding *counts*, not narrative *claims*.

So the last phase actively obscures the fact that the run achieved nothing — the operator sees a clean report, not the 573 self-inflicted 403s behind it.

## SEC-1 — "PayloadSandbox" is not a sandbox (misleading safety guarantee)

`core/payload_sandbox.py` is named and documented as *"Executes validated payload scripts in an isolated subprocess"*. It is neither validated-safely nor isolated:
- **The validator is a bypassable AST denylist.** `SafePayloadValidator` blocks a fixed set of module/function *names* (`os`, `subprocess`, `eval`, `open`, …). It is defeated by standard Python escapes it never inspects: `().__class__.__base__.__subclasses__()` introspection to reach `subprocess`, `getattr(__builtins__, 'ev'+'al')`, subscript/attribute chains on non-`Name` nodes, and whole dangerous surfaces that simply aren't on the list (`urllib`, `requests`, `http.client`, `pathlib.Path.write_text`, `compile`, `globals`, `breakpoint`). A denylist without an allowlist over a Turing-complete language is not a security boundary.
- **There is no isolation.** After the fig-leaf check it runs `python3 /tmp/sandbox_*.py` on the WSL host as the normal user — no container, namespace, seccomp, network isolation, or resource limit. The "isolated subprocess" claim is false; it is an ordinary subprocess with full user privileges and network.
- The live PoC path (`WeaponizationAgent._synthesize_and_execute_poc` → `python3 {remote_script_path}`, weaponization_agent.py:449) runs **AI-synthesised** exploit code through the same weak `validate_python` guardian and then executes it on the host.

**Impact:** in an autonomous run, exploit code the LLM writes — and the LLM is influenced by attacker-controlled target responses (prompt-injection surface) — executes on the operator's machine behind a filter that provides false assurance. For a lab this is "works", but the naming invites misplaced trust; the boundary should be an actual sandbox (disposable container / nsjail / seccomp) or the code should stop calling it one.

## BUS-1 — Message bus has no delivery guarantee for late subscribers

`MessageBus.publish` (message_bus.py:20) delivers **only** to handlers subscribed *at publish time* and swallows per-handler exceptions (logs + continues). Agents subscribe as they are constructed in phase order, so a payload published on channel `recon` before the exploitation agent subscribes is **delivered to no one** — there is no retention/replay (the store copy is for *audit*, not redelivery). The recon→exploitation bus path (`exploitation_agent.py:204` sets `self._recon_data`) can therefore be silently empty while `StateStore.get_phase_data("recon")` holds the data. The run survives only because the **store** is the real handoff; the bus is a second, timing-dependent source that can disagree with the store — a latent inconsistency waiting for any code that trusts `_recon_data` over the store.

## Minor / edge defects
- **CONFIG-1:** `ConfigLoader.get_int` does `int(val)` with no guard (config_loader.py:165). A non-numeric env override (`THRESHOLD=300s`) raises `ValueError` → crash or (if swallowed) silent fallback to default — config that looks applied but isn't.
- **DEADLINE-1:** `soft_deadline = start + phase_timeout - 120` (base_agent.py:4695). Any phase whose configured timeout is < 120 s yields a deadline in the past → the ReAct loop logs "soft deadline reached" and completes having done **nothing**. Current defaults are all > 120 s, but it is a config-fragile invariant with no guard.
- **SANDBOX-parse:** `PayloadSandbox.run` calls `ast.parse(script_code)` *outside* its try/except (payload_sandbox.py:80); a syntax error in AI code raises out of `run()` instead of returning the intended "Blocked" string.

---

## Consolidated defect inventory (all rounds)

| ID | Layer | Defect | Independent of egress? |
|----|-------|--------|------------------------|
| RC-1 | egress | all web tools force-routed through Tor | — (is the egress) |
| RC-2 | classify | 403/429/exit-0 misattributed (WAF / false success) | partly |
| RC-3 | decision | remediation loops, no convergence check | partly |
| RC-4 | intelligence | LLM-call flood → backend exhaustion | partly |
| RC-5 | memory | poisoned learning (syntax_learner persists garbage) | yes |
| RC-6 | orchestration | garbage propagates, blind exploitation | yes |
| DEEP-1 | classify | corrupted `.success` blinds all safety nets | yes |
| DEEP-2 | intelligence | advisor write-only; `should_continue_trying` dead | yes |
| DEEP-3 | ai_backend | exhaustion = sleep-stall / phase crash | partly |
| DEEP-4 | context | unbounded prompt rebuild → mid-truncation | yes |
| DEEP-5 | handoff | no plausibility gate between phases | yes |
| DEEP-6 | waf | 3,084 LOC firing on self-inflicted 403s | — |
| META-RC-0 | whole | prompt-hope over enforcement | yes |
| DEEP-7 | classify/dedup | gates blind to own Tor/state; exact-hash dedup | yes |
| DEEP-8 | classify | verdict-cache poisoning, coarse key, unlocked | yes |
| DEEP-9 | state | uncheckpointed WAL / crash residue | yes |
| DEEP-10 | recovery | self-correction stack = the starvation source | partly |
| NEW-1 | privilege | can run root, mis-probes as non-root, forbids `sudo` | yes |
| NEW-2 | provisioning | 9 advertised recon tools unregistered → wrong install | yes |
| NEW-3 | provisioning | install-root vs run-nonroot PATH mismatch | yes |
| NEW-4 | data | `add_finding` 160-char dedup drops distinct findings | yes |
| NEW-5 | everywhere | 40+ exception-swallow sites hide failures | yes |
| NEW-6 | provisioning | wrong-package install cached as "installed" | yes |
| STATE-1 | state | single writer + 10s timeout → silent lost writes | partly |
| REPORT-1 | reporting | launders corrupted findings into confident report | yes |
| SEC-1 | security | "sandbox" is a bypassable denylist + host execution | yes |
| BUS-1 | messaging | no delivery guarantee for late subscribers | yes |

**Reading of the table:** the majority of defects are **independent of the Tor egress cascade**. Disabling stealth would quiet RC-1/RC-2's volume but leave the privilege contradiction (NEW-1), the provisioning gap (NEW-2/3/6), silent data loss (NEW-4, STATE-1), the blinded safety nets (DEEP-1), and the reporting/whitewash (REPORT-1) fully intact. The engine has *many* independent ways to fail its intent — which is why single-symptom fixes never moved the needle.

## Still not audited (candidate next passes)
`target_graph`/`attack_graph` expansion logic; `guardian.py` command-repair correctness; per-phase token-budget accounting accuracy; the recon subdomain/liveness pipeline internals.

---
---

# ROUND 5 — self-upgrade, dual registries, stealth integrity, concurrency

Auditing the "self-improvement" loop, the provisioning source-of-truth, the IP rotator, and the WAF transform.

## UPGRADE-1 (HIGH) — The self-upgrade loop permanently bakes corrupted learning into the rules (RC-5 escalated)

At every engagement end the reporting agent calls `AutoUpgrader.run_system_upgrade(..., dry_run=False)` (reporting_agent.py:363 — **live, not a dry run**). The pipeline: analyse the engagement → derive "insights" → generate tool-effectiveness/timeout **optimizations** and new **rules** → validate → **write them to persistent files** (`_apply_changes`: insights, rules, `tool_metrics.json`, recommendations). Two fatal properties:

1. **It learns from corrupted signals.** The "insights" are built from the same `tool_runs`/findings that RC-2/DEEP-1 mislabel (empty-but-"success", all-ports-open, false WAF). So the derived tool-success rates, timeout adjustments, and generated rules encode the corruption.
2. **`_validate_changes` checks SCHEMA, not TRUTH** (auto_upgrader.py:187 — verifies value ranges and duplicate rule-IDs only). Corrupted-but-well-formed changes pass and are applied.

Net: each run **rewrites the persistent rule/metric layer** from a distorted picture, with only a schema gate. Over multiple engagements the engine's own "learning" drives it *away* from working behaviour — a compounding, cross-engagement corruption amplifier that outlives any single run and cannot be seen in a single-run log. It also persists **AI-discovered tool configs** to disk (`register_new_tool` → `{name}.json` + runtime `register_tool`), so a bad tool definition becomes permanent too. This is the most damaging feedback loop in the system because it is *designed* to be permanent.

## DUAL-REGISTRY-1 (MEDIUM) — Two competing tool source-of-truth systems that disagree

There are **two** independent tool databases:
- `tools/tool_registry.py::TOOL_REGISTRY` — consumed by `ToolManager.ensure_installed` for **installation**. Missing `httpx`, `katana`, `gau`, … (NEW-2).
- `core/capability_registry.py` — ~20 `CapabilityTool` records with their own per-OS `install_cmds`, consumed by `cap_reg.resolve` for **capability→command** building. This one *does* define e.g. `subfinder` with a correct GitHub-release install.

Command *selection* runs through one registry, command *installation* through the other, and they do not share entries. A capability can resolve to a tool the installer then mis-provisions (or vice-versa), and a fix applied to one registry silently fails to help the other. Fragmented source-of-truth is itself a defect class — there is no single answer to "what tools does this engine actually have and how are they installed?"

## STEALTH-DEGRADE-1 (MEDIUM) — Anonymity silently downgrades to DIRECT under sustained blocking

`IPRotator` sets `self._tor_verified = False` and *bypasses Tor* precisely when a Tor exit is blocked (ip_rotator.py:138-140: *"SOCKS port is listening, but we cannot route traffic (Tor likely blocked). Bypassing Tor."*) — which per RC-1 is the **common** case. Because `_apply_stealth_routing` only wraps a command in proxychains when `_tor_verified` is True, once Tor is de-verified the engine stops routing new commands through Tor and they run **direct**. The `_stealth_leak_guard` (fail-closed) protects the operator's IP **only if `rotate_ip` was requested**; a `ghost_mode`-only run has no such guard and can leak the real IP after the first block. So under the very conditions the engine faces most (Tor blocked), its "stealth" quietly degrades — either to a hard stop (leak guard) or to a silent de-anonymised direct connection.

## CONCURRENCY-1 (LATENT / LOW) — Unlocked shared dedup + verdict caches

`_command_history` (dedup) and `_outcome_interp_cache` (triage verdicts) are read/written across many methods with **no lock** (only the separate `_findings_lock` guards findings). The main recon/exploitation paths run tools **sequentially**, so this is not firing today — but `Orchestrator.delegate_to_specialist` and the `run_agent_async` TaskGroup path are async, and `check_liveness` uses a 10-worker pool. Any future concurrent `safe_run_tool` would corrupt the dedup map and verdict cache (lost dedup → a dead command re-loops; cross-thread verdict overwrite). A latent bug seeded for the moment concurrency is switched on.

## WAF-TRANSFORM (NOTE) — Defensively guarded, but blind to the false premise

`WafGhostEngine.transform` is actually careful: it refuses to mutate a command without block-evidence (waf_ghost_engine.py:80-90, explicitly because header mutation *"has repeatedly broken tools"*) and skips raw-socket tools. But the "block-evidence" it keys on is RC-2's **misattributed Tor-403**. So when evasion is *forced* on a false block, it still injects headers into a working command and can corrupt it — the guard prevents needless mutation but cannot help when the upstream premise ("this is a WAF block") is itself wrong. Good local code, wrong global input — the same shape as DEEP-7.

---

## Severity-ranked master list (all rounds, for triage)

**Tier 1 — corrupts correctness AND hides itself (fix first):**
RC-2/DEEP-1 (misclassification blinds safety nets) · NEW-1 (privilege contradiction) · UPGRADE-1 (permanent corrupted self-learning) · RC-5 (poisoned syntax memory).

**Tier 2 — breaks core function independent of egress:**
NEW-2/NEW-3/NEW-6 (provisioning: unregistered tools, PATH split, wrong-install cached) · NEW-4 + STATE-1 (silent findings/state loss) · DEEP-5 (no plausibility gate) · REPORT-1 (whitewashed report).

**Tier 3 — the egress cascade (loud but partly self-inflicted):**
RC-1 (force-Tor) · RC-3/DEEP-2 (loops, dead convergence check) · RC-4/DEEP-3/DEEP-10 (LLM starvation spiral) · DEEP-6 (WAF over-engineering) · STEALTH-DEGRADE-1.

**Tier 4 — latent / security-posture / edges:**
SEC-1 (fake sandbox) · DUAL-REGISTRY-1 · BUS-1 · DEEP-4 (context bloat) · DEEP-8/DEEP-9 (cache/WAL) · CONCURRENCY-1 · NEW-5 (swallow audit) · CONFIG-1 · DEADLINE-1.

**One-line synthesis:** GhostWire computes good self-knowledge and then, at every layer, either uses it as ignorable advice or acts on a corrupted version of it — and its two "learning" loops (`syntax_learner`, `auto_upgrader`) make the corruption permanent. The Tor cascade is the loudest symptom, not the disease; the disease is *unenforced, unvalidated self-knowledge feeding compounding feedback loops.*

---
---

# ROUND 6 — phantom intelligence, registry fragmentation, and what actually works

Auditing the graph/intelligence layer for wired-vs-advertised, and the tool-gating systems. This round also records the parts that are **genuinely sound**, so the picture is fair.

## PHANTOM-1 — A large slice of the advertised "intelligence layer" is dead or write-only

The README headlines "dynamic attack-graph reasoning" and a "Zero-Hardcoding AI Decision Engine." Measured against the code:

- **`AttackGraph` (core/attack_graph.py) is write-only.** It is instantiated (base_agent.py:121) and its `add_node`/`add_edge` are called (1347-1367), but its **read** methods — `get_filtered_context`, `get_dependencies`, `get_dependents` — are **never called anywhere**. The engine builds an attack graph that no decision ever consumes. "Dynamic attack-graph reasoning" writes a graph and reasons over nothing.
  - (Latent bug for whenever it *is* wired: `get_filtered_context`'s 2-hop BFS appends an edge for every neighbour *before* the visited/depth check, so it returns edges pointing to nodes absent from its own node set, plus duplicates.)
- **`constraint_engine` (275 LOC) and `finding_scorer` (264 LOC) are imported by ZERO non-test files.** ~540 LOC of "intelligence" that is built and unit-tested but never wired into any agent or the core loop.
- **`advisor.should_continue_trying` and `advise_waf_evasion` are dead methods** (DEEP-2) — the convergence check that would break the loops exists and is never called.

So a substantial body of code (~800+ LOC across AttackGraph reads, the two dead engines, and the dead advisor methods) exists to *look* like sophisticated autonomy while never touching a decision. This is not merely wasted effort: dead/write-only modules **mask what actually runs**, so the operator (and past auditors) over-trust the system's "reasoning," and each new "FIX" is aimed at machinery that isn't in the path.

## TRIPLE-REGISTRY-1 — Three tool-gating systems that don't share a source of truth (sharpens DUAL-REGISTRY-1)

A tool must pass **three** independent gates, defined in three places that disagree:

| Gate | File | Question | `httpx`? |
|------|------|----------|----------|
| Allowlist | `utils/guardian.py:20` | may this tool run? | ✅ allowed |
| Capability | `core/capability_registry.py` | capability → which tool/command | partial |
| Install | `tools/tool_registry.py` | how to install it | ❌ absent |

`httpx` **passes** guardian's allowlist (it is listed) but is **absent** from `TOOL_REGISTRY`, so it is green-lit to run and then mis-installed via the apt/pip fallback (NEW-2/NEW-6). The most permissive gate (guardian says "yes") admits a tool the installer cannot provision — the disagreement is exactly what lets a broken tool reach execution. There is no single authoritative answer to "does this engine have tool X and how does it get it," and the three gates fail in different directions.

## What actually WORKS (for balance and accurate triage)

Not everything is broken; several mechanisms are correctly built and wired, and fixes should preserve them:

- **`is_phase_budget_exhausted` IS wired** — checked in the recon loop (recon_agent.py:894) and exploitation loop (exploitation_agent.py:1676), gated by a minimum loop count. Real token-budget circuit-breaking (unlike the dead `should_continue_trying`).
- **`TargetGraph` (core/target_graph.py, 483 LOC) is genuinely used** — exploitation reads it for credential reuse and lateral-movement/pivot decisions (`get_all_credentials`, `register_pivot`, port-22 checks at exploitation_agent.py:438-456). It is starved by corrupted recon, but the machinery itself is sound.
- **`guardian.validate_ai_command` is a substantive gate** — denylist of destructive patterns, destructive-action approval gating, tool allowlist, target-in-command enforcement (anti out-of-scope), length cap, plus repair. Real defence-in-depth (its only fault is disagreeing with the other two registries).
- **`ScopeEnforcer`** is fail-closed (raises on out-of-scope; suffix-match to avoid `notcloudflare.com` bypass) — correct, with one edge gap (skips when no host is extractable).
- **`WafGhostEngine.transform`** refuses to mutate without block-evidence (learned from breaking tools) — locally correct, only let down by RC-2's false premise.
- **`robust_parser`, WSL path handling, `safe_executor` exit-classification** — all correct (contra the first external report).

The importance of this list: the disease is **not** "the whole codebase is bad." It is a handful of load-bearing defects (Tier 1/2) surrounded by both sound components and dead ornamentation. A fix program should target the Tier-1 wires, delete the dead weight, and leave the working gates intact.

## Updated "still not audited"
`hypothesis_engine` / `attack_frontier` / `objective_ledger` decision-influence depth; `evidence_router` correctness; `tripwire_detector` false-positive behaviour; `guardian`'s repair transform (does it corrupt valid commands like the WAF path once did?). Diminishing returns — the load-bearing root causes are now well-characterised across Rounds 1-6.

---

## FINAL SYNTHESIS (Rounds 1-6)

GhostWire's failure is not one bug and not the Tor cascade the surface logs scream about. It is a **system** of ~30 defects that cluster into four mutually-reinforcing pathologies:

1. **Unenforced self-knowledge** (META-RC-0, NEW-1, DEEP-7): the engine measures its own state accurately, then applies it as ignorable prompt-advice or acts on a corrupted reading — so it runs `nmap -sS` non-root it forbade itself from fixing, and calls its own Tor-403s a target WAF.
2. **A corrupted success signal that blinds everything downstream** (RC-2, DEEP-1): "success" means exit-code + a signature list, not a valid result — so false successes are stored, the failure-counters/mentor/recovery never fire, and reports look clean over empty runs.
3. **Compounding feedback loops made permanent** (RC-4/DEEP-3/DEEP-10, RC-5, UPGRADE-1): the self-correction stack is the same code that starves the LLM budget, and the two learning loops persist the corruption into syntax memory and the rule layer across engagements.
4. **Provisioning and source-of-truth fragmentation** (NEW-2/3/6, TRIPLE-REGISTRY-1, PHANTOM-1): the engine advertises tools it can't install, gates them through three disagreeing registries, and drapes the whole thing in dead/write-only "intelligence" that hides what really runs.

Fix order that respects the dependency structure: **(2) fix the success signal → (1) enforce self-knowledge at gates → (3) break/validate the feedback loops → (4) unify provisioning and delete the dead weight.** Doing (4) or the Tor cascade first — or adding any new hardcoded signature — moves nothing, because the corrupted signal and unenforced knowledge will re-poison whatever is built on top.

---
---

# ROUND 7 — the output-sanitization path (a new independent data-loss cause)

Auditing the code that touches **every** tool's output before anything else sees it, plus the honeypot pruner and PoC generator.

## SANITIZE-1 (MEDIUM-HIGH) — `clean_text` silently destroys `\r`-terminated tool output

`utils/sanitizer.clean_text` runs on **every** tool's stdout and stderr in the non-streaming execution path (`wsl_executor.execute`: `out_str = clean_text(res.stdout)`) *before* parsing or classification. It contains:

```python
text = re.sub(r'[^\n]*\r', '', text)   # "simulate terminal carriage-return overwrite"
```

The intent is to collapse progress-bar redraws. The effect is broader — **proven** with the live code:

```
'RESULT: success\r'                          -> ''                       # entire output deleted
'found port 80 open\rfound port 443 open'    -> 'found port 443 open'    # port 80 finding deleted
'[Status: 200, Size: 1420]\r'                -> ''                       # ffuf hit line deleted
'progress 50%\rDONE: 5 findings\n'           -> 'DONE: 5 findings'       # (correct case)
```

Any tool output where the meaningful content sits on a line that is terminated by `\r` **without** a following `\n` — a result printed without a trailing newline, a status line, a `\r`-joined sequence — is **wholly or partially deleted before the engine ever parses it.** Consequences:

- **Manufactured "empty output"** → the classifier's `real_output_len < 200` path and the empty-result checks fire → a *successful* tool is booked as failed/empty (feeds RC-2 from a new direction) → repair/evasion loops on a tool that actually worked.
- **Silent finding loss** → the `[Status: 200 …]` example is exactly the gobuster/ffuf hit line the sanitizer's *own comment* says it must preserve; it doesn't strip the brackets, but the `\r` rule deletes the whole line anyway.

This is independent of Tor, privilege, and dedup — a pure text-processing defect at the universal choke point, and a fourth distinct mechanism (alongside NEW-4, STATE-1, and misclassification) by which "the tool ran but the engine saw nothing." The streaming path is partly protected (it `rstrip("\r\n")`s per line before joining), so the bug bites the many quick, non-streaming tool calls hardest.

## TRIPWIRE-1 (LOW-MEDIUM) — Honeypot pruning is a double-edged blade

`TripwireDetector` is wired into recon (recon_agent.py:122-172): `is_honeypot_active` flags a host whose open-port count exceeds `HONEYPOT_PORT_THRESHOLD=50`, then `prune_honeypot_ports` removes ports.

- **Upside:** it is the one thing that partially catches the all-ports-open Tor-connect-scan garbage (DEEP-5) — >50 ports trips density pruning.
- **Downside:** a *legitimate* host with >50 open ports (a jump box, a device, a dev server) is flagged a honeypot and its **real ports pruned** → genuine recon data dropped. The corroborating `check_banner_similarity` is reasonably guarded (needs ≥5 non-standard ports at 0.95 Jaccard, excludes 80/443/22), so it is not wildly trigger-happy — but the density gate alone can prune real findings, and on uniform-response targets (WAF/CDN returning the same page on every port) the similarity check can classify a real host as a honeypot.

So the same feature both cleans Tor garbage and can erase a legitimate wide-open host — its correctness depends entirely on whether the >50 ports are real, which (post-clean-scan) the engine cannot reliably tell.

## HARDCODE-1 (NOTE) — Weaponization is template-first, contradicting the zero-hardcoding ethos

`utils/poc_templates.py` is explicitly *"Hardcoded exploit templates per vulnerability class"* and `get_poc_template` selects one by **keyword substring match** on the vuln type (poc_templates.py:567-574), falling back to AI generation only on no match. This is pragmatic (templated PoCs come with proof-guards and `VULN_PROVEN/NOT_PROVEN` discipline, which is *good* for avoiding false positives), but two things are worth flagging: (1) it contradicts the project's stated "zero-hardcoding" identity, so the design philosophy is applied unevenly; (2) substring keyword matching can select the **wrong** template for a compound/novel vuln type, and there is no check that the chosen template actually fits the finding beyond the keyword hit.

## Round-7 severity placement
- **SANITIZE-1 → Tier 2** (breaks core function independent of egress; sits beside NEW-4/STATE-1 as a silent data-loss cause and beside RC-2 as a misclassification source).
- **TRIPWIRE-1 → Tier 4** (edge/data-quality; mitigates one problem while risking another).
- **HARDCODE-1 → note** (design-consistency, not a functional break).

## Still open (thin, diminishing returns)
`self_awareness_module` confidence calibration (cosmetic vs. decisive); `hypothesis_engine`/`attack_frontier` influence depth; `evidence_router`; `guardian`'s repair-transform corruption risk; `output_parser.py` (the tool-specific parsers — a likely next SANITIZE-class hunting ground). The four-pathology model from the Round-6 synthesis is not changed by these; SANITIZE-1 slots cleanly under pathology #2 (corrupted/empty success signal).

---
---

# ROUND 8 — the parser layer (stdout → structured findings)

`OutputParser` (`tools/output_parser.py`) is the bridge from raw tool stdout to the structured `open_ports` / `discovered_paths` / `subdomains` that phases hand each other. It runs **after** `clean_text` (SANITIZE-1) and its output feeds the recon→exploitation handoff (`tool_manager.py:1755` → `parsed["open_ports"]` → recon `phase_data` → `ExploitationAgent._preflight`). Three findings.

## PARSER-1 (MEDIUM) — No parser for the liveness/fingerprint tools; their *discriminating* signal is discarded

The dispatch map has dedicated parsers for **14** tools (nmap, masscan, nikto, whois, theharvester, subfinder, gobuster, dirb, ffuf, enum4linux, hydra, sqlmap, nuclei, wafw00f). Everything else falls to `_generic`, which extracts **only URLs** (`re.finditer(r'https?://…')`). That is fine for crawlers (katana/gau/hakrawler/waybackurls emit URLs), but it silently loses the *discriminating* output of the tools recon depends on most:

- **`httpx`** — its job is to say *which* hosts are LIVE and with what status/title/tech. `_generic` keeps the URLs and throws away the live/dead verdict, status codes, and tech tags — i.e. exactly the signal that separates a real web server from a dead name. So even after you fix `httpx`'s install (NEW-2), its output is still not turned into "live_hosts". The registry gap and the parser gap are two independent walls in front of the same tool.
- **`whatweb`** — its output is tech-stack tags (`HTTPServer[nginx]`, `title[...]`), not URLs, so `_generic` extracts essentially nothing. The tech fingerprint that drives wordlist provisioning and tech-aware decisions is dropped.

Net: the modern web-recon signal (liveness + fingerprint) is structurally unrepresented; downstream phases see URLs but not which are alive or what they run.

## PARSER-2 (MEDIUM) — Ports reach exploitation via a lossy string round-trip, not the structured parser

There are **two** port-extraction paths and the one that feeds the final bundle is the fragile one:
1. `OutputParser._nmap` → `parsed["open_ports"]` (structured ints), used for emission/pruning.
2. Recon then **re-derives** `open_ports` at bundle time by regex-scanning its own human-readable findings: `re.search(r'Port (\d+)', f.get("detail",""))` (recon_agent.py:1408), and it is *this* set that becomes the bundle's `"open_ports"` (recon_agent.py:1539) handed to exploitation.

So a port's journey is: nmap stdout → `clean_text` (SANITIZE-1 may delete the line) → `_nmap` regex (needs a service field, PARSER-3) → structured int → **formatted into a `"Port N …"` detail string** → `add_finding` (NEW-4 160-char dedup may drop it) → **regex-extracted back to an int**. Every hop is lossy, and the authoritative value for exploitation is the *last* one — recovered from a display string, not the structured parse. If the finding was deduped away or the detail format drifts, the port silently never reaches exploitation even though nmap found it.

## PARSER-3 (LOW) — `_nmap` regex requires a service field and mishandles slashed services

`r'(\d+)/(tcp|udp)\s+(open|filtered|closed)\s+([\w.-]+)(?:\s+([^/\n]+))?'` requires a service token (`\s+([\w.-]+)`) after the state, so a port line lacking one is missed, and a slashed service (`ssl/http`) is truncated to `ssl`. Minor next to PARSER-1/2, but it is the first lossy hop in the chain above.

## PARSER × SANITIZE interaction (compounding)
The `_ffuf`/`_gobuster` parsers key on `[Status: NNN]` lines — the very lines SANITIZE-1 was shown to delete when they end in `\r`. So a correct parser receives empty input for real hits. The two defects multiply: sanitize removes the line, then the parser has nothing to match, then recon re-derives from findings that were never created.

## Round-8 placement
- **PARSER-1, PARSER-2 → Tier 2** (they break the core recon→exploitation data path independent of egress, and compound NEW-2/NEW-4/SANITIZE-1).
- **PARSER-3 → Tier 4**.

## Balance (what's fine here)
`_generic`'s URL harvesting is a sensible catch-all for crawlers; the structured parsers that *do* exist (nmap ports, ffuf/gobuster paths, nuclei findings) are reasonable regexes; `parse()` never raises (returns `{raw, parse_error}`). The layer is not incompetent — it just has gaps exactly where the modern PD toolset and the port-handoff live, and it inherits SANITIZE-1's upstream damage.

---

## RUNNING TALLY (Rounds 1-8)
~35 distinct defects. The recon→exploitation data path alone is now shown to lose findings at **five** independent points before exploitation ever runs: `clean_text` `\r`-deletion (SANITIZE-1) → `_nmap` regex gaps (PARSER-3) → `add_finding` 160-char dedup (NEW-4) → the string round-trip re-parse (PARSER-2) → the single-writer 10 s write-timeout (STATE-1). Any one of these can turn "nmap found 12 ports" into "exploitation sees none" — which is precisely the observed "recon found nothing → exploitation blind" symptom, and it happens **with Tor entirely disabled.** This is the strongest evidence yet that the egress cascade is a loud co-symptom, not the root: the data path is independently lossy end-to-end.

---
---

# ROUND 9 — CVE intelligence, cosmetic self-awareness, and the dead-code census (closing round)

Final pass over the remaining intelligence/feature modules and a whole-codebase accounting of what is actually wired.

## CVE-1 (MEDIUM) — "Dynamic CVE lookup" is a static, stale table with a broken version match

The README headlines "Dynamic CVE lookup." `intelligence/cve_database.py` is a **hardcoded dictionary** of CVEs spanning ~2019-2021 only (nothing 2022-2026 — five years missing). Two functional defects on top of the staleness:
- **Version-key granularity mismatch (logic bug):** `find_cves_for_tech` truncates the queried version to `MAJOR.MINOR` — `version_key = '.'.join(version.split('.')[0:2])` — but the table stores **patch-level** keys for the high-value entries (`"2.4.49"`, `"2.4.50"` → Apache CVE-2021-41773/42013 path-traversal RCE). Querying Apache `2.4.49` truncates to `"2.4"`, which is **not a key**, so those critical CVEs are **never matched**. The table's WordPress entries use `MAJOR.MINOR` keys and *do* match — so the lookup works for some tech and silently fails for others depending on how that vendor's keys were written.
- **Zero-hardcoding contradiction:** a hardcoded CVE table in a "zero-hardcoding" engine, and one that returns empty for anything modern (the AI fallback returns `cves: []`, not fabricated CVEs — so at least it does not hallucinate, but it also contributes nothing for current tech).

Low blast radius (thinly wired), but it is a headline feature that is largely non-functional and, where it does fire, can miss the exact critical CVE it was built to surface.

## PHANTOM-2 (MEDIUM) — ~1,000+ LOC of advertised capability is dead or cosmetic

A whole-codebase import census (imported by **zero** non-test files = dead):

| Module | LOC | Advertised as | Status |
|--------|-----|---------------|--------|
| `browser_driver` | 228 | "browser automation for JS-heavy/SPA targets" | **DEAD** |
| `stealth_proxy` | 124 | "IP rotation & stealth proxying" | **DEAD** (real work is in `ip_rotator`) |
| `constraint_engine` | 275 | reasoning-engine constraint checks | **DEAD** |
| `finding_scorer` | 264 | finding prioritisation | **DEAD** |
| `evasion_controller` | 31 | "adaptive rate-limit bypass" | **DEAD** |
| `c2_simulator` | 26 | C2 / beaconing | **DEAD** |
| `obfuscator` | 15 | "payload obfuscation" | **DEAD** (and naive base64-exec if it ran) |
| `waf_policy` | 10 | WAF policy | **DEAD** |
| `engagement_learner` | 50 | cross-engagement learning | **DEAD** |
| **subtotal** | **~1,023** | | **never imported** |

Plus **write-only / cosmetic** (imported but never decisive):
- `attack_graph` (52) — the README's "dynamic attack-graph reasoning"; nodes written, never read (Round 6).
- `self_awareness_module` (387) — README: "prevents overconfident execution." It **records** confidence into `known_facts`/`uncertain_facts`/`confidence_by_type` and is **never used to gate, block, or defer any action** (the only confidence gates in the agents are the WAF-fingerprinter's, not this module's). It prevents nothing.
- `advisor.should_continue_trying`, `advise_waf_evasion` — dead methods (Round 5/DEEP-2).

**Interpretation.** Roughly 1,500+ LOC — spanning the advertised **browser automation, stealth proxying, obfuscation, adaptive evasion, C2, attack-graph reasoning, self-awareness gating, constraint reasoning, and finding scoring** — is either dead or write-only. The engine's *advertised* capability surface is far larger than its *wired* capability surface. This is not benign bloat: it (1) makes the system look far more capable than it is, so operators and prior audits trust "reasoning"/"evasion"/"self-awareness" that does not execute; (2) inflates maintenance/attack surface; and (3) hides the ~8-10 small, load-bearing components that actually decide behaviour. Deleting it is part of the cure, because it clarifies what must actually be fixed.

## What IS wired and real (final accounting)
The engine that actually runs is much smaller than the repo: `main` → `Orchestrator` (phase loop) → `BaseAgent.run_react`/`safe_run_tool` (the ~1,360-line choke point) → `ToolManager`/`WSLExecutor` → `StateStore`; with `AIBackend` for LLM, `guardian`+`scope_enforcer` as real gates, `TargetGraph`/`hypothesis_engine` genuinely consulted in exploitation, `is_phase_budget_exhausted` as a real breaker, the WAF cluster genuinely firing (on false premises), and `auto_upgrader`/`syntax_learner` as the two real (and corrupting) learning loops. Everything else is dead ornament or write-only telemetry.

---

# EXPLORATION COMPLETE — final statement

After nine rounds spanning entry, orchestration, the shared agent brain, execution, classification, decision/ReAct, the AI backend, the intelligence layer, the two learning loops, provisioning, state, reporting, security, output sanitisation, parsing, target parsing, CVE lookup, the WAF cluster, and a whole-codebase dead-code census, the exploration has reached the point of **diminishing returns with no new load-bearing findings likely**. Remaining unread code (`attack_frontier`, `structured_analyzer`, `authz_tester`, `display`, `poc_customizer`, `vps_optimizer`, a few thin agents) is peripheral and, by the same import census, either thinly wired or telemetry — reading it will refine wording, not the diagnosis.

**The diagnosis in one paragraph.** GhostWire fails not from one bug or from Tor, but from a *system* of ~37 defects with a common shape: it **computes accurate self-knowledge and either ignores it (advice, not enforcement) or acts on a corrupted version of it**; its **success signal means "exited" not "produced a valid result"**, which **blinds every safety net and launders empty runs into confident reports**; its **recon→exploitation data path loses findings at five independent points with Tor off**; its **two learning loops make the corruption permanent across engagements**; its **provisioning is fragmented across three disagreeing registries and can't provision the tools it advertises**; and **~1,500 LOC of advertised "intelligence/evasion/automation" is dead or cosmetic**, masking how small the real decision core is. The Tor cascade is the loudest symptom because it is the highest-*volume* one, but it is downstream of, and independent from, the structural faults. **Fix order:** success-signal correctness → enforce self-knowledge at gates → break/validate the feedback loops → unify provisioning and delete the dead weight. No amount of new hardcoded signatures or per-tool patches moves any of it.

*End of analysis. 9 rounds, ~37 distinct defects, severity-triaged, evidence-anchored to `live_run_novalink.log` / `last ran cli out.txt` and the live code.*

---
---

# ROUND 10 — COMPLETE FILE COVERAGE (per operator directive: read every file before fixing)

Systematic pass over every remaining source file (see `FILE_COVERAGE_LEDGER.md` for the per-file status matrix). This round confirms mechanisms concretely, adds a few defects, and — importantly — records the substantial amount of code that is **sound**, so the fix effort is aimed correctly.

## LEARN-1 (HIGH, concrete confirmation of the amplifier) — ALL THREE learning loops read the corrupted success signal

The single most important complete-coverage result: every persistence/learning loop derives its "what worked" from the **same corrupted classifier verdict** (DEEP-1). Traced to the exact lines:
- `intelligence/engagement_analyzer.py:107` — `success = status == "success"` over `tool_runs` → tool-effectiveness rates → `heuristic_optimizer` → `auto_upgrader` writes them to persistent rules/metrics (UPGRADE-1).
- `intelligence/tool_success_tracker.py:log_tool_result(success)` — fed the same boolean; "did the tool find something" is actually "did the classifier say success".
- `intelligence/waf_learner.py:165` — `success = run.get("success", False)` → tactic-effectiveness scores; and `waf_evasion_engine.record_tactic_result(success)` — WAF tactics scored on the same corrupted signal, for "WAFs" that were often Tor-403s.
- `intelligence/syntax_learner` — persists the command string of any run the classifier called success (RC-5).

**Consequence, made concrete:** the engine learned that `nmap … --privileged` is *highly effective* (the classifier marked its no-op runs "success"), so the optimizer boosts its score and the upgrader persists it — the system **actively trains itself to prefer the commands that do nothing.** This is why fixing the success signal (Tier 1) is load-bearing for *all four* learning loops at once: one fix cleans every learner's input.

## ARCH-1 (MEDIUM) — Four overlapping, independently-maintained failure-analysis systems

Complete coverage revealed the same decision — "did this tool result fail, and is it worth retrying?" — is made by **four** different code paths that do not share a verdict: `base_agent._interpret_outcome` (AI triage), `reasoning_engine.analyze_tool_failure` (AI, base_agent.py:1075), `safe_executor.should_retry` (exit-code), and `guardian.validate_ai_command` (pattern gate). They can disagree (e.g. AI triage says "repair" while `should_retry` says "no"), and each is maintained separately with its own hardcoded hints. This redundancy is both a source of inconsistent behaviour and a reason past fixes to "the retry logic" never fully landed — there are three other retry brains.

## Minor defects found during coverage
- **SSH-1 (LOW):** `core/ssh_executor.py` carries the same install-root/run-nonroot privilege split as WSL (NEW-1 applies in VPS mode); its `timeout` wrapper lacks the `-k` force-kill that `wsl_executor` uses (line 43), so an SSH tool that ignores SIGTERM is not hard-killed; and it has a stray `to_wsl_path` method (copy-paste from the WSL executor) — dead/confusing in an SSH class.
- **TCTX-1 (LOW):** `core/target_context.py` defaults `scheme="http"`; an https-only target first probed over http can redirect-loop or fail before the engine settles on https.
- **ORIGIN-1 (INFO):** `waf_bypass/origin_discovery.py` is real and wired but has 2 `TODO` capability gaps (ASN confirmation, timing/DNS-rebind internal detection) — advertised origin-discovery is partially stubbed.

## Confirmed SOUND during complete coverage (do not "fix" these)
- `hypothesis_engine.py` (478) — genuinely well-designed AI researcher-brain (observe→hypothesise→test→validate, no canned exploit tables); only weakness is an 8000-char evidence truncation and being starved by corrupted recon.
- `reasoning_engine.py`, `evidence_router.py`, `target_profiler.py`, `authz_tester.py` (real IDOR/BOLA), `attack_frontier.py`, `structured_analyzer.py` — functional; mostly limited by corrupted inputs, not their own logic.
- `waf_bypass_orchestrator.py` gates aggressive WAF *attacks* (ReDoS/buffer/HPP in `waf_attacker.py`) behind a `WafAttackAuthorizationRequired` exception — a real safety gate.
- `origin_discovery.py` (CDN origin-IP discovery) — substantive and correct in structure.

## Dead-code total after full waf_bypass sweep
Adding the `waf_bypass/` dead modules (`hardcore_evasion` 554, `request_smuggler` 379, `oob_exfil_engine` 377, `credential_finder` 135) to the Round-9 list brings confirmed dead code to **~2,468 LOC** across 13 modules — much of it advertised capability (request smuggling, OOB exfil, hardcore evasion, C2, obfuscation, browser automation). See `FILE_COVERAGE_LEDGER.md`.

## Final-sweep minor defects (plumbing/utils)
- **VALIDATOR-1 (LOW):** `utils/validator.normalize_target` strips the port via `target.split(":")[0]`, which **mangles IPv6 addresses** (`::1` → empty, `[2001:db8::1]:443` → `[2001`) — IPv6 targets fail validation/normalisation. Also `is_valid_domain` requires a dotted TLD, so single-label internal hostnames are rejected.
- **STEALTH-UA (LOW, ironic):** `utils/stealth.get_random_ua()` is named "random" but returns a **constant** `"antigravity-security-assessment"` — UA-rotation evasion is a no-op, and the fixed UA actively *announces the tool* to the target. (Tiny/thinly-used, but the opposite of stealth.)
- **HIL — correctly handled (not a bug):** `request_hitl_authorization` returns DENY in batch/headless mode when no approver is wired (base_agent.py:388) — no stdin hang. Consequence (by design, not a defect): an autonomous run with non-permissive ROE self-limits to passive recon.
- `tls_fingerprint.py:126` `verify=False` and `app_session` `verify_tls=False` defaults are intentional for a probing tool (not defects). `vps_optimizer` deletes via `find` (not `rm -rf`) and skips sysctl on WSL — careful. `installers.py`/`ast_analyzer.py` are intentional dead-code-removal stubs.

## COVERAGE STATUS: COMPLETE
Every source file (excluding `.venv`, caches, `tests/`, `scratch/`) has now been read and classified — see `FILE_COVERAGE_LEDGER.md`. Breakdown: ~8-10 load-bearing decision files (deeply analyzed), a ring of functional-but-input-starved intelligence modules, real safety gates (`guardian`, `scope_enforcer`, HITL, WAF-attack authorization), and **~2,470 LOC of confirmed-dead code across 13 modules** plus several write-only/cosmetic modules. No further file is expected to alter the diagnosis; the remaining risk surface is fully mapped.

**Total distinct defects across Rounds 1-10: ~40**, grouped under the four pathologies (unenforced self-knowledge · corrupted success signal · permanent corrupted feedback loops · provisioning/source-of-truth fragmentation + dead ornamentation). The complete-coverage pass's biggest contribution is **LEARN-1**: proof that all four learning loops read the one corrupted success signal, so the Tier-1 fix (make "success" mean "valid, plausible result") simultaneously repairs classification, every safety net, and every learner's training input. **The codebase is now fully characterized and ready for a fix plan.**

---
---

# WAF SUBSYSTEM — full inventory + hardening plan (make it attack more / evade more)

> Design-only. No code edited here. This section catalogues every WAF capability the engine has today (wired vs dead), states the one defect that undermines all of it, and lays out a concrete plan to make the WAF handling stronger: fix the trigger, wire the useful dead modules, salvage the good parts of the dead ones, and add net-new evasion/attack techniques — all within the zero-hardcoding, enforcement-not-advice philosophy.

## A. Current WAF capabilities (as-built)

### ✅ WIRED (actually executes)
| Capability | Module | Role |
|---|---|---|
| WAF fingerprint / type detection | `intelligence/waf_fingerprinter.py` (663) | header-signature + rate-limit probing → `waf_present` / `waf_fingerprint` + confidence (recon) |
| Block classification | `tools/tool_manager.py:1528` | flags `waf_blocked` on `403/429/cloudflare ray id/access denied` |
| "NOT-A-BLOCK" guard | `agents/base_agent.py` | strips false `waf_blocked` when it's really a syntax/transport error |
| Primary evasion (command mutation) | `core/waf_ghost_engine.py` (728) | injects stealth headers/mutations — **only on real block evidence** (conservative by design) |
| Evasion-tactic tracking | `intelligence/waf_evasion_engine.py` (452) | `EvasionTactic` + `record_tactic_result` |
| TLS-fingerprint evasion | `waf_bypass/tls_fingerprint.py` (143) | JA3/JA4 randomization |
| IP-reputation evasion | `core/ip_rotator.py` (357) | Tor circuit rotation (opt-in `--stealth`) |
| Rate-limit backoff | `base_agent._should_rate_limit` / `_wait_rate_limit` | 429 handling |
| Bypass-around: origin discovery | `waf_bypass/origin_discovery.py` (496) | find origin IP behind CDN (DNS history, cert IPs, ASN, rDNS) → hit direct (recon) |
| Bypass-around: cache deception | `waf_bypass/cache_deception.py` (186) | CDN edge cache deception/poisoning probe (safety-limited) (exploitation) |
| Direct WAF attack | `waf_bypass/waf_attacker.py` (56) | ReDoS fail-open, buffer/padding exhaustion, HPP — **gated by `WafAttackAuthorizationRequired`** |
| Orchestration | `intelligence/waf_bypass_orchestrator.py` (714) | ties bypass tactics together + enforces the attack auth gate (exploitation) |
| Cross-run learning | `intelligence/waf_learner.py` (517) | persists tactic effectiveness (⚠ from the corrupted success signal — LEARN-1) |

### ⚠️ CORRECTION (after full line-by-line read of `waf_bypass_orchestrator.py`)
My earlier "dead" verdict on three modules was **WRONG** — it came from a census that only grepped `agents/` and `core/`, missing that the orchestrator (in `intelligence/`) imports and instantiates them at `waf_bypass_orchestrator.py:50-60`:
```
self.origin_discovery = OriginDiscovery()
self.credential_finder = CredentialFinder(state_store)   # ← WIRED (was called dead)
self.request_smuggler  = RequestSmuggler()               # ← WIRED (was called dead)
self.oob_engine        = OOBExfilEngine()                # ← WIRED (was called dead)
self.waf_attacker      = WafAttacker()
```
The orchestrator is wired into exploitation, so **`request_smuggler` (379), `oob_exfil_engine` (377), and `credential_finder` (135) are LIVE**, dispatched by `execute_bypass` → `_execute_smuggling_bypass` / `_execute_oob_bypass` / `_execute_credential_bypass`. This **removes ~891 LOC from the dead total** (revised dead ≈ **1,577 LOC**, not 2,468).

### 💀 ACTUALLY DEAD (confirmed after full read)
| Module | LOC | Note |
|---|---|---|
| `waf_bypass/hardcore_evasion.py` | 554 | NOT imported by the orchestrator either — genuinely dead; mostly broken/obsolete; salvage only timing + TLS bits |
| `core/waf_policy.py` | 10 | stub |
| `strategic_advisor.advise_waf_evasion` | — | method to recommend the next tactic — **never called** |

## B. The one defect that undermines ALL of the above (fix this first)

**The trigger is egress-blind.** `waf_blocked` is set from a `403/429/cloudflare` string match (`tool_manager.py:1528`) that never consults the engine's own state (`_tor_verified`, "is my exit IP blocklisted?"). Under `--stealth` this fires on nearly every request (Tor exits are Cloudflare-blocklisted → 573× 403 in one run), so the whole WAF stack runs on a **false premise**:
- evasion mutates working commands (can break them),
- the orchestrator burns budget rotating to another blocked Tor IP,
- `WafLearner` records "tactic X beat the WAF" when there was no WAF → **poisoned tactic memory**.

**No amount of *more* evasion/attack helps until the trigger can tell "real target WAF" from "my own egress is blocked."** This is DEEP-6/DEEP-7/RC-2. So step 1 of "make WAF better" is *accuracy*, not *volume*.

## C. Hardening plan — make it attack more & evade more (design)

### Tier W1 — Fix the trigger (prerequisite for everything else)
1. **Egress-aware block attribution.** Feed `ip_rotator._tor_verified` + a cheap control-probe ("does a known-good baseline URL also 403 from this exit right now?") into the classifier. If the baseline is also blocked → attribute to **egress**, rotate/abandon the exit, do **not** label it a target WAF or run evasion.
2. **Confidence-gated WAF verdict.** Require `WafFingerprinter` confidence + a *content* check (Cloudflare interstitial / `cf-ray` header / challenge page), not a bare `403` substring, before `waf_blocked` triggers the stack. This deletes most false positives and lets you shrink the `waf_markers` list.
3. **Gate `WafLearner` on validated blocks only.** Only record tactic effectiveness when the block was a *confirmed* WAF block and the follow-up was a *validated* success (ties into the Tier-1 success-signal fix). Stops poisoned tactic memory.

### Tier W2 — Fix the bypass modules that ARE wired but broken/unreachable (revised after full read)
*(These are already wired via the orchestrator — the work is repair, not wiring.)*
4. **Fix the two permanently-unreachable attacks (WAF-ORCH-1).** `_execute_exhaustion_bypass` (l.640) and `_execute_parser_confusion_bypass` (l.653) raise `WafAttackAuthorizationRequired` **unconditionally** — unlike `_execute_smuggling_bypass` which correctly guards `if not authorized_attack`. So even *with* operator authorization, ReDoS/padding and HPP can never execute. Add the `if not authorized_attack:` guard so an authorized attack actually runs.
5. **Replace the fake protocol bypass (WAF-ORCH-2).** `_execute_protocol_bypass` (l.626) just appends `?_quic=true` to the URL — a no-op query param, not real HTTP/3. Either implement a genuine h3/h2c path or drop the layer; the differential validator currently (correctly) downgrades it to failure, so it wastes a slot.
6. **Persist evasion-tactic learning (WAF-EVA-1).** `WafEvasionEngine` already has the right structure (declarative tactics, success-rate-weighted ordering) but `record_tactic_result` updates **in-memory only** — `_initialize_tactics` never loads from `WAF_DATABASE_FILE` and nothing saves back, so tactic stats reset to 0.5 every run and cross-engagement adaptation (its own docstring promise) never happens. Load/save the per-`(waf_type, tactic)` counts so the ordering actually improves — but only after W1.3 makes the success signal trustworthy.
7. **Wire `advise_waf_evasion`** (the dead advisor method) so tactic selection is *recommended from persisted effectiveness* instead of priority-order-only.

### Tier W3 — Salvage the good parts of `hardcore_evasion`, drop the rest
7. **Keep:** the **timing strategies** (`slow_steady / burst_with_gaps / random_jitter / exponential_backoff`, l.219-268) and **TLS cipher/curve randomization** (l.353-396) — sound, and richer than what's wired. Fold them into `waf_evasion_engine` as selectable tactics.
8. **Drop / do not wire:** unicode-combining and UTF-8-overlong encoders (produce *different* paths → request garbage), null-byte (dead since ~2011), fake `[DELAY]` "fragmentation" (theater, unsendable), and blanket IP-spoof headers (`X-Forwarded-For`/`CF-Connecting-IP` random — flags you, doesn't bypass). Then **delete the module**.

### Tier W4 — Add net-new evasion/attack techniques (expand the arsenal)
Evasion (per-request, tactic-selectable, applied only on a *confirmed* block):
- **Payload-position mutation** for injection: comment/whitespace/case vari/inline-encoding *of the payload token only* (not the whole path) — WAF-regex bypass that doesn't corrupt the request.
- **HTTP/2 & h2c downgrade / smuggling** and **chunked transfer-encoding** variants (real desync surface beyond CL.TE).
- **Header-order / duplicate-header / Unicode-in-header-name** parser-differential tricks (the WAFFLED class) — richer than the current header injection.
- **Path-normalization differentials** (`..;/`, `%2e%2e`, trailing-dot host, `;`/matrix params) between the CDN and origin.
- **Multipart / content-type confusion** (send SQLi as `multipart/form-data` or `text/xml` when the WAF only inspects urlencoded).

Attack-the-WAF (auth-gated, `redteam` mode only):
- **Fail-open induction beyond ReDoS**: oversized JSON depth / deeply-nested params to exceed inspection budget; **body-past-inspection-limit** (WAFs often inspect only first 8-128 KB — already hinted in `waf_attacker.generate_padding`, make it a first-class tactic).
- **Parameter-pollution matrix** tuned to the *fingerprinted* WAF's known first-vs-last-param behaviour.
- **Rate-limit-state probing** to discover the exact window/threshold, then pace *just under* it (drives the timing tactics from a measured value, not a guess).

### Tier W4b — Fix the broken tactics ALREADY in `WafEvasionEngine` (found in full read)
Several wired tactics are counterproductive (same class as `hardcore_evasion`), so they *degrade* real bypass attempts:
- `_tactic_null_bytes` (l.298) replaces **spaces** with `%00` — corrupts the payload, doesn't inject a null byte where one helps.
- `_tactic_payload_encoding` hex (l.231) emits `\xNN` **shell escapes**, not HTTP/URL encoding — sends literal `\`,`x`,`N`,`N` to the server.
- `_tactic_case_variation` (l.306) upper/lowercases path segments — **breaks case-sensitive servers** (`/Admin`≠`/admin` → 404).
- `_tactic_http_method_variation` (l.205) swaps GET→HEAD/OPTIONS — **destroys the response body** the scanning tool needs.
Fix or remove these; they should only fire on the payload token (injection context), never blanket-mutate the path/method of a discovery tool.

### Tier W5 — Selection is already adaptive-by-structure; make it *persistent* and richer
9. **The structure already exists** — `WafEvasionEngine.build_evasion_strategy` maps detected behaviors→tactics and sorts by `(priority, -success_rate)`, and the orchestrator ranks 11 layers by evidence-scaled viability with a per-layer risk profile. The missing piece is **persistence (W2.6)** and trustworthy inputs (W1). So W5 is *not* "build a bandit from scratch" — it is "persist the counts and let them drive order."
10. **De-hardcode the layer confidences (WAF-ORCH-3).** The orchestrator's `_analyze_*` methods return **static confidence values** (e.g. `protocol: 0.6`, `legitimacy: 0.7`) that are only scaled by recon evidence afterward. Replace the static seeds with actual lightweight probes (or the fingerprinter's real confidence) so the ranking reflects *this* target, not canned guesses — consistent with zero-hardcoding.
11. **Per-WAF playbooks as data, not code.** Keep tactic definitions declarative (already the shape of `EvasionTactic`) so new techniques are added as data.

---

## E. Full-read findings & the ONE thing worth copying system-wide

**New defects (from reading `waf_bypass_orchestrator.py` + `waf_evasion_engine.py` line-by-line):**
- **WAF-ORCH-1 (MED):** `exhaustion` + `parser_confusion` attacks are **permanently unreachable** — unconditional `raise WafAttackAuthorizationRequired` (l.648, l.658), missing the `if not authorized_attack` guard that `_execute_smuggling_bypass` has. Two attack vectors that can never fire even when authorized.
- **WAF-ORCH-2 (LOW):** `_execute_protocol_bypass` is a **placeholder** (`?_quic=true` query param, not real HTTP/3).
- **WAF-ORCH-3 (LOW):** the 11-layer "analysis" uses **hardcoded static confidences**, only evidence-scaled afterward — semi-canned, contradicts zero-hardcoding.
- **WAF-EVA-1 (MED):** `WafEvasionEngine` tactic learning is **in-memory only** — never loaded/saved to `WAF_DATABASE_FILE`; "learns for future engagements" (its docstring) is false, stats reset to 0.5 each run.
- **WAF-EVA-2 (MED):** 4 wired tactics are broken/counterproductive (null_bytes/hex/case/method — see W4b).
- **WAF-EVA-3 (LOW):** tactics emit **marker dicts** (`_evasion_delay`, `_proxy_request`, `_send_dummy_requests`) that only take effect if the executor honors them — effect is executor-dependent and unverified end-to-end.

**The GOOD find — copy this pattern everywhere:** `WafBypassOrchestrator._validate_bypass_differential` (l.355-399) is a genuine **plausibility gate done right**. It proves a claimed bypass with a **control→test differential** — send a known-bad probe to the normal path (must be blocked) and via the bypass (must be allowed); a lone `200` proves nothing, and if the differential isn't observed it **downgrades `success=False`** with `unverified_reason` ("the novalink failure"). This is exactly the missing plausibility check the rest of the engine needs (DEEP-5, RC-2/DEEP-1): a result is only "success" if it *demonstrates* the expected effect, not if it merely ran. **The Tier-1 success-signal fix should generalize this differential/expected-signal idea from WAF bypass to every tool outcome.** The WAF subsystem already contains the template for the single most important fix in this document.

**Net corrected picture of the WAF subsystem:** it is *bigger and better-wired* than the survey suggested — an 11-layer evidence-ranked orchestrator with real HITL gating, a differential validator, and a declarative behavior-mapped tactic engine. Its problems are (1) the egress-blind trigger feeding it false blocks (W1, the dominant issue), (2) two unreachable attacks and one fake layer (W2/WAF-ORCH), (3) broken individual tactics (W4b), and (4) learning that never persists (W2.6). Fix those and wire the smuggler/OOB (already present) into the tactic ranking with confidence, and it becomes a genuinely strong, adaptive WAF-handling stack — without adding much new code.

---
---

# ROUND 11 — `base_agent.py` FULL READ (corrects several earlier survey claims)

Per the "read every line before fixing" directive, `base_agent.py` (5,590 LOC) was read across its decision-critical span (init/wiring, phase gates, findings, liveness, command cleaning, the ReAct action→command path, the full repair loop, `_ai_repair_tool`, `think()`, strategic advice, assumption validation). This overturned or softened multiple claims — logged honestly below.

## CORRECTIONS to earlier rounds (the survey was too harsh)
1. **`self_awareness_module` is NOT cosmetic (corrects PHANTOM-1 / DEEP-2).** It is consumed in three decisive places: (a) `_ops_sanity_backstop` (l.1248) calls `awareness.ops_sanity_check` to **downgrade** implausible high/critical findings to "UNVERIFIED LEAD"; (b) `_validate_assumptions` (l.5392) has the AI judge each open assumption SUPPORT/REFUTE/UNKNOWN against evidence and **surfaces refuted ones into failure memory**; (c) `suggest_data_collection` feeds the "collect-next" hints into `think()`. It gates and feeds back — it is *advisory-wired*, not write-only.
2. **`StrategicAdvisor` is NOT write-only (corrects DEEP-2).** `_strategic_advice_note` (l.5300) injects `advise_tool_selection` recommendations, **STOP-SIGNS (`warning_signs`), PIVOT suggestions, KNOWLEDGE-GAP**, and (recon) EARLY-EXIT conditions into every `think()` full-mode prompt. What is genuinely dead is only the two specific methods `should_continue_trying` and `advise_waf_evasion`. The advisor's *guidance* does reach the AI (as advice, not enforcement — consistent with META-RC-0).
3. **DEEP-4 (context bloat) was overstated.** `think()` compacts context: task→16 000 chars, env→2 000, awareness/advisor→1 500 each (`_compact_ai_context`), and `_format_history` feeds only the **last 5** ReAct entries. Context is bounded, not unbounded; the mid-truncation risk in `_query_ai` remains but is a smaller factor than claimed.
4. **PARSER-1 softened.** `_auto_ingest` (l.4585) is a **universal regex extractor** run on *every* tool's stdout in the ReAct path — it harvests subdomains, `.php/.asp/...` endpoints, `login/admin/auth` paths, a hardcoded tech-stack map, WAF vendor, and `N/tcp open` ports. So httpx/whatweb output missing a dedicated parser still yields tech/WAF/subdomain/port findings here. (Also makes `_auto_ingest` a *third* WAF-detection path — redundancy, not absence.)
5. **RC-3 softened for the WAF path.** An **evasion circuit-breaker** exists (l.3166): if WAF evasion produces the same failure signature twice, it abandons evasion and routes to AI triage — a real convergence check the survey said was missing.
6. **RC-1/timeout softened.** Timeout escalation is **Tor-aware** (l.3456): 240 s floor under Tor vs 90 s direct, precisely because "under Tor a timeout means Tor is slow, not too much work." A real mitigation of the ban-everything-under-Tor problem.
7. **Token management is deliberate.** `think()` has nano/slim/full tiers, awareness-injection suppression (`_awareness_needed`, loop-1/every-5th), and model routing that keeps command *generation* on the strong 70B while only mechanical calls use the 8B (they learned the 8B emits malformed commands). Softens the "loop-storm is pure waste" framing — the volume is real (RC-4) but they do throttle context/model per call.

## New defects found in the full read
- **WAF-LEARN-1 (MED):** at l.3249, `self._waf_learner.update_tactic_effectiveness(str(tactic), False, …)` passes **`str(tactic)`** — the *stringified dict* `"{'name': 'header_mutation', …}"` — as the tactic key, not the tactic name. Every block records effectiveness under a malformed/derived key, so WAF tactic learning is corrupt independent of LEARN-1.
- **WAF-EVA-4 (MED, reclassifies WAF-EVA-2):** in the block handler (l.3226-3236) only `_evasion_delay` and `_proxy_request` markers from `WafEvasionEngine.apply_tactic` are honored — the header/payload/method/case mutations the tactics compute are **discarded** (actual command mutation is `WafGhostEngine`'s job). So the broken tactics (null_bytes/hex/case/method) are *harmless* (output thrown away), but the engine is **~decorative** for command mutation — it effectively contributes only a delay and an optional proxychains wrap.
- **CAPREG-ATTR (LOW):** `__init__` sets **both** `self.cap_registry` (the raw arg, may be `None`, l.119) and `self.cap_reg` (auto-constructed, always set, l.168). Any code path using `self.cap_registry` would hit `None`. Duplicate-attribute footgun.
- **DEAD-EXPR (TRIVIAL):** l.4263 `any(k in err_lower for k in syntax_keywords)` computes a boolean and **discards it** (no assignment) — vestigial after a "flawed check removed" refactor.

## Confirmations (unchanged)
- **META-RC-0 confirmed precisely:** `_ai_repair_tool` (l.4134) injects the env snapshot ("raw sockets UNAVAILABLE, don't use `--privileged`") into the repair prompt, yet repair-rule l.4237 ("read the Error Output closely … specific syntax errors") steers the AI to answer *"requires root privileges"* by adding `--privileged`. The repair guards check echo-back, shell-parse validity, and dedup — but **never capability-compliance**. The enforcement gap is exactly where NEW-1's fix must go.
- **DEEP-5 at the gate:** `validate_phase_prerequisites` lets exploitation proceed on *any* finding/port/sub/dir (substring type-match, where `"port" in t` even matches "re**port**") — no plausibility gate. (But note the *good* counterweights found here: `_validate_severity` caps unproven findings at medium, and `_ops_sanity_backstop` downgrades implausible exotic findings — so there IS finding-level validation, just not port-level.)
- **NEW-4 confirmed but narrower:** the URL dedup now keeps scheme+host+path (the "60 URLs dropped" bug is fixed for URLs); the 160-char `dedup_detail` collision remains only for long non-URL details.

**Verdict on base_agent after full read:** the decision core is **more defensively engineered than the survey concluded** — finding-severity gating, ops-sanity downgrades, assumption validation, an evasion circuit-breaker, Tor-aware timeouts, tiered token use, and a universal ingest fallback all exist. The load-bearing defects still stand (META-RC-0 enforcement gap, corrupted success signal feeding learners, WAF-LEARN-1 key bug), but the picture is "a well-built engine with a few load-bearing wiring/enforcement holes," not "cosmetic intelligence over a broken core." This is exactly why the full read was necessary — the survey over-indexed on grep-visible call counts and under-counted the advice-injection paths.

## D. Ordering (why accuracy before volume)
```
W1 (fix trigger)  ─►  W3 (salvage timing/TLS)  ─►  W2 (wire smuggler/OOB/advisor)  ─►  W4 (new techniques)  ─►  W5 (adaptive selection)
     must be first        cheap wins               big capability, already written      arsenal growth          only trustworthy after W1
```
Adding W2/W4/W5 *before* W1 just makes the engine fire more (broken) evasion at self-inflicted 403s and poison its learning faster. Fix the trigger, then the existing + salvaged + new tactics all become genuinely useful. Net effect once ordered: **more real evasion, two strong new bypass classes (smuggling, OOB), an authorized richer attack set, and adaptive per-WAF tactic selection — without the false-positive churn that currently wastes it all.**


---
---

# ROUND 12 — `tool_manager.py` FULL READ (2,090 LOC, resolves the nmap false-success inconsistency)

Read end-to-end: module helpers (`_produced_real_output` l.54, `_wsl_which` l.114), `_ensure_installed_unlocked` (l.224, the full VPS+WSL install/AI-repair/PATH-locator engine), `discover_tool` (l.611), `learn_tool_syntax` (l.672), the help-grounding pair (`get_tool_valid_flags` l.851, `get_tool_help_brief` l.892), the universal input-repair cluster (`_canonical_hosts_file`/`_canonical_wordlist`/`_canonical_substitute`/`_fix_glued_path_flags` l.1002-1172), `_validate_and_fix_command` (l.1173), `run` (l.1374), `_execute` (l.1800). This was the file where I had flagged an unresolved inconsistency (nmap `--privileged` scored SUCCESS). It is now resolved, and the classifier turns out to be the **second, independent locus of the corrupted success signal** (Pathology 2) — the first being base_agent's outcome triage.

## The nmap false-success — RESOLVED (this is Pathology 2 at the classifier level)
- **TOOLMGR-1 (HIGH) — banner-only nmap scored SUCCESS.** In `_execute()` the exit-code classifier (remote l.1919-1962, local l.2004-2030) marks a run SUCCESS in two ways that both catch a privileged nmap that printed its banner and quit:
  - if nmap **exits 0** -> l.1940 `elif exit_code == 0:` -> stdout non-empty (banner present) -> `SUCCESS`;
  - if nmap **exits non-zero** -> l.1956 `known_partial_success = {nmap,masscan,nikto,nuclei,gobuster,ffuf}` + `len(stdout.strip()) > 50` + `not has_fatal_error` -> `SUCCESS`.
  The raw-socket error string ("Couldn't open a raw socket. Operation not permitted" / "dnet: failed to open device") is **not in `fatal_error_markers`** (l.1904-1914), so `has_fatal_error=False`. Either branch yields **SUCCESS on a scan that produced zero results** — the classic "exited != valid result."
- **`_produced_real_output` is NOT in this path.** My earlier note ("it should catch nmap --privileged") was wrong about the mechanism: `_produced_real_output` (l.54) is only consulted inside the **syntax-error** override branches (l.1590, l.1665). A raw-socket banner is not a syntax marker, so it never reaches that guard. The only thing standing between banner-nmap and a false SUCCESS is the dedicated recovery block in `run()` (l.1499-1517), which rewrites `-sS->-sT` and sets `result.status=FAILURE` — **but only when `attempt < retry_count - 1`** (a retry remains). On the **final/only attempt** (and nmap can be a single-attempt tool depending on `FAST_TOOLS`), the recovery is skipped and the false SUCCESS flows downstream as a "successful" empty scan. This is the same defect class as base_agent's triage, in a different file — confirming Pathology 2 is **multi-locus**, not a single bug.
- **Fix alignment:** the Tier-1 differential/expected-signal gate must live at the ToolResult classifier too (or be applied by callers to `_execute`'s output), not only in the AI triage. A "SUCCESS" nmap with an empty `parsed.open_ports` and a raw-socket string in stderr is definitionally not a success.

## Other real defects found
- **TOOLMGR-2 (MED) — VPS installs never treated as transient.** l.547 `err_msg = str(result.stderr).lower() if 'result' in locals() and result else ""`. On the **VPS** install path the local `result` variable is never bound (VPS uses `exit_code/out/err_out`), so `'result' in locals()` is False -> `err_msg=""` -> the transient-network branch (l.548, "ssh"/"connection failed"/"banner") can never fire. Every VPS install failure — including a transient SSH banner/drop — is written to `_failed_cache` for 300 s (l.235-239), blackholing a tool that would install fine seconds later. WSL path is unaffected (it does bind `result`).
- **TOOLMGR-3 (MED) — stateless WafGhostEngine re-instantiated every retry.** l.1431-1437 builds a **fresh** `WafGhostEngine(remote_executor=self.remote)` inside the retry loop with `force=True`, so it carries no accumulated block-rate feedback and re-derives its transform from scratch each attempt. Combined with `TOOL_RETRY_COUNT`, every WAF "block" — which under the Tor-egress cascade (W1) is frequently a benign 403 — spins escalating `level=N` transforms with zero memory. This is a **third** evasion-amplification path (alongside base_agent's repair loop and the orchestrator), all fed by the same egress-blind trigger.
- **TOOLMGR-4 (LOW) — "quitting" over-match.** l.1505 treats any `"quitting"` substring as a raw-socket failure and rewrites `-s[SUAFNX]->-sT`. nmap prints "QUITTING!" for many fatal conditions (bad flag, resolve failure), so an unrelated failure can be silently rewritten into a TCP-connect scan. The `-sT` fallback is usually harmless, but it is an over-broad heuristic that can mask the real error from the repair loop.
- **TOOLMGR-5 (LOW) — ambiguous input classified as hosts.** `_canonical_substitute` (l.1135-1137) breaks ties toward the host-list. A wordlist whose filename lacks a word-keyword and sits behind a non-standard flag would be replaced with a **host list** fed to ffuf/gobuster as a wordlist. Edge case, but a silent wrong-SOURCE substitution.

## Corrections / strengths (the "SURVEYED" tag undersold this file)
1. **`validate_and_filter_flags` is DELIBERATELY disabled (l.979-1000), and the rationale is exactly right.** The old "proactive flag corrector" regex-extracted "valid" flags from `--help` and silently dropped anything else — which mangled `nmap -sS/-sT/-sA` (slash-separated in help) into bare `nmap`, running unbounded scans the AI never saw. It now returns the command unchanged and lets a real usage-error drive AI repair. This is a **model example of the zero-hardcoding philosophy the user insists on** — a place where they already removed exactly the kind of brittle heuristic the survey feared.
2. **The classifier is otherwise defensive.** The single-request-vs-scanner distinction (l.1933-1939 / l.2012-2018) stops a scanner being marked BLOCKED for one sub-request error; the deterministic no-retry guard (l.1611-1628) breaks instantly on unresolvable/refused/closed-port failures instead of burning 3 retries; exit-0 syntax dumps are overridden to FAILED only when `_produced_real_output` is False (l.1588-1599), preserving good data whose output merely *contains* a marker substring. These are correct, well-commented guards.
3. **Universal input-repair is a genuine zero-hardcoding strength.** `_canonical_hosts_file` (materializes all known hosts+subdomain findings to a stable file), `_canonical_wordlist` (AI micro-wordlist -> installed lists -> last-resort written fallback so dir-busting never dies on a missing file), and `_canonical_substitute` (classifies a missing input as host-list vs wordlist from **standard flag names + filename keywords**, not per-tool logic) form a tool-agnostic recovery system. `get_tool_help_brief` (l.892) even guards against grounding on a not-yet-installed tool's "command not found" stub (l.928-949) — a subtle correctness win.
4. **AI install-repair is bounded and sanitized.** Both VPS (l.317-412) and WSL (l.439-527) install loops cap at 3 attempts, simulate apt first (`apt-get -s`, l.335), reject non-apt/pip commands and shell-operator injection (l.300-303, l.328-333), auto-inject `--break-system-packages` for PEP-668, and run a PATH-locator+symlink when an install returns 0 but leaves the binary off-PATH (l.365-391 / l.449-490). The WSL locator explicitly avoids the `/mnt` full-`find` hang (l.456-471).

**Verdict on tool_manager after full read:** like base_agent, **better-built than the survey implied** — the install engine, input-repair, and most of the classifier are solid and philosophy-aligned. The one load-bearing hole is **TOOLMGR-1**: the ToolResult classifier is a second independent source of the corrupted success signal (banner-only nmap -> SUCCESS), which the Tier-1 fix must close at the classifier, not just in the AI triage. TOOLMGR-2/-3 are real secondary bugs (VPS retry blackout; stateless evasion amplification feeding the egress cascade).

---
---

# ROUND 13 — `exploitation_agent.py` FULL READ (2,368 LOC — the best-gated agent, with ONE self-contradicting hole)

Read end-to-end: `run()` (l.557, multi-scope orchestration + WAF orchestrator + CIDR + cross-target pivot), `_exploit_single_target` (l.1169-2368, the full port-probe → hypothesis → Phase-B ReAct loop → confirmed-vuln state machine → SSH brute), both finding-creation paths (`_emit_exploit_findings` l.220, `_test_hypotheses` l.859), `_is_false_positive` (l.208), `_validate_recon_bundle` (l.355). Headline: this agent **already contains the finding→state plausibility gate the survey said was missing** — and it contains a **second, contradictory path that can fabricate a "confirmed critical" from an output substring.** The fix target here is precise.

## THE load-bearing hole
- **EXPLOIT-EMIT-1 (HIGH) — the "dynamic severity" branch mints unproven VULN_PROVEN/critical.** `_emit_exploit_findings` step 3 (l.312-351) proudly comments "NO hardcoded keyword->severity table" at l.242-248, then immediately implements exactly that for raw AI-attack output: if stdout contains `root:` / `uid=0` / `private key` / `-----begin` -> `add_finding(..., "VULN_PROVEN: ...", "critical")` (l.317-325). Two compounding problems:
  1. **No proof.** This is a bare substring match on the tool's stdout — no differential, no baseline diff, no PoC. A JSON API response, a raw-text cert/PGP dump, a docs endpoint echoing an example `-----BEGIN PRIVATE KEY-----`, or any body containing a `root:`-style string is scored **critical**. The only guard (l.315-316) skips output containing `<!doctype html>`/`<html>`/`wp-content`/`litespeed` — i.e. it only catches **HTML** pages; JSON/plain-text responses sail straight through.
  2. **It feeds the confirmed-vuln gate.** The detail string literally starts with `VULN_PROVEN`, and the state machine at l.2258 keys confirmation on `"vuln_proven" in f_detail`. So a benign response containing a cert/PGP block becomes an entry in `_exploitation_state["confirmed_vulns"]`, **advances the kill-chain stage** (l.2279-2288 via `_access_markers` `uid=`/`/bin/sh`), and is injected into the next prompt as "Confirmed Vulnerabilities" — telling the brain it owns access it never gained. This is Pathology 2 (corrupted success signal) at the finding level, and it is the single place in this agent that undercuts all its other rigor.
  - **Fix:** route this branch through the same `hypothesis_engine.validate_result(baseline=…)` differential the rest of the file uses, or at minimum emit it as an INFO `exploit_lead` (like the generic-error branch at l.344 already correctly does) and let the proof layer elevate it. Never mint `VULN_PROVEN` from an unvalidated substring.

## Other real defects
- **EXPLOIT-EMIT-2 (MED) — auto-SQLi chain is unbounded + fire-and-forget.** l.294-310: for every discovered path containing `?` (up to 20 per tool result, l.273), if `allow_exploitation`, it launches `sqlmap` — and the result `r` is **discarded** (not parsed, not emitted). So up to 20 sqlmap runs fire per emit call, their findings are lost unless a later parse re-surfaces them, and the loop's token/time budget is spent invisibly. Bound it and emit its output.
- **EXPLOIT-SSH-1 (MED) — hardcoded, usually-absent wordlist paths.** SSH brute (l.2331-2334) hardcodes `/usr/share/wordlists/metasploit/unix_users.txt` + `unix_passwords.txt`. These are frequently not installed, so hydra dies on a missing file — and this is the **one place** that bypasses tool_manager's canonical-wordlist system (`_canonical_wordlist`, which exists precisely to prevent this). Route it through the canonical wordlist provider. (Contradicts the zero-hardcoding philosophy the rest of the engine follows.)
- **EXPLOIT-PORT-1 (LOW) — Phase B consumes the last-iterated port's context.** `tech_info`, `is_spa`, `baseline_size`, `waf_present`, `waf_type`, `base_url` are set **inside** the port loop (l.1397-1507) and read by Phase B **after** it (l.1509+). With web_ports ordered `[443, …, 80]` and port-80 `continue`d when 443 is reachable (l.1417), the surviving values are usually 443's — but with non-standard port sets (`[443, 8080, 80]`, 443 unreachable) Phase B silently attacks with whichever port iterated last. Implicit SOURCE selection; make the "primary reachable port" explicit.
- **EXPLOIT-FP-1 (LOW) — `_is_false_positive` is nearly a no-op.** Only three substring checks (connect/timeout/wildcard-error, l.208-218); does no dedup or plausibility filtering. Fine as a floor, but it is not the FP defense its name implies.
- **ROE-ORDER (TRIVIAL) — WAF orchestration runs before the ROE gate.** `run()` executes the full `WafBypassOrchestrator.analyze_target` (l.629-669) **before** checking `roe.allow_exploitation` (l.671). Read-only, so harmless, but wasted work when exploitation is disabled.

## Corrections / strengths (the 🟡 "preflight/WAF/PoC paths only ~300 lines" tag badly undersold this file)
1. **The confirmed-vuln gate (l.2237-2274) is the plausibility gate the survey said was missing — it EXISTS here and is done right.** A vuln enters `confirmed_vulns` ONLY when actually proven: `vuln_proven` in detail, a `[differential]` marker, `confirmed_vulnerability`/`nuclei_confirmed`/`proven_*` type, or an authz confirmation. **Bare high/critical severity is explicitly rejected** (l.2242-2244 comment: "an unproven nuclei 'high' … would otherwise masquerade as an exploited vuln"). The kill-chain advances **at most one stage per loop** and **only on real access evidence** (`uid=`,`/bin/sh`,`valid_credential`,… l.2249-2288). This is exactly DEEP-5's missing gate — present, at the finding→state boundary. (EXPLOIT-EMIT-1 is dangerous precisely because it feeds a *pre-proven* token into this otherwise-sound gate.)
2. **`_test_hypotheses` (l.859-978) is textbook differential validation.** It runs the **full chained multi-step** test plan (not just step 1 — a prior truncation bug they fixed, l.876-882), judges via `hypothesis_engine.validate_result(..., baseline=_baseline_body)` (real similarity-to-normal differential, l.907-913), persists an evidence object, does exactly **one** disambiguating refine retry then re-judges (l.934-961), and closes the **confidence-calibration loop** (predicted confidence vs actual verdict, persisted cross-engagement, l.962-974). This is the correct template — the same one `_validate_bypass_differential` embodies in the WAF orchestrator.
3. **`_emit_exploit_findings` step 1 (l.242-255) is philosophy-correct.** Raw scanner strings go in as **INFO** with the explicit rationale that "the hypothesis engine / PoC is the severity AUTHORITY" — no keyword→severity inflation. The generic-error branch (l.334-351) likewise records an unverified `exploit_lead` at INFO, not a MEDIUM vuln. (Which is exactly why step 3's critical branch is an inconsistency, not the file's norm.)
4. **Idle-loop detection is correct (l.1692-1707).** A loop counts as empty only when the previous loop produced **neither new findings NOR new commands** — so a WAF-blocked-but-actively-probing loop is not scored idle (a real prior bug where the phase quit after ~3 loops with zero results). Momentum/effort signalling, the objective ledger (WS5 stop conditions past min-loops), the unified scored **attack frontier**, target-model injection (WS2), and the thin/rich **discovery↔exploit switch** (l.1600-1624) are all genuine strategic scaffolding, not decoration.
5. **Backend-exhaustion handling is graceful (l.2112-2124):** on `RuntimeError` it waits `get_shortest_recovery_time()` (≤5 min) and retries the same loop rather than quitting — directly relevant to the "LLM backend exhaustion → hallucination" cascade (it does NOT hallucinate; it waits).

**Verdict on exploitation_agent after full read:** the **most rigorously gated agent in the engine** — its confirmed-vuln state machine and `_test_hypotheses` differential path are the exact patterns the Tier-1 success-signal fix should propagate everywhere. The load-bearing defect is the single **EXPLOIT-EMIT-1** substring branch that can fabricate a confirmed critical, quietly undoing that rigor; EXPLOIT-EMIT-2 (unbounded fire-and-forget sqlmap) and EXPLOIT-SSH-1 (hardcoded absent wordlists) are the two secondary bugs. Fixing EXPLOIT-EMIT-1 alone closes the one place this agent poisons its own confirmed-vuln list and kill-chain state.

---
---

# ROUND 14 — `recon_agent.py` FULL READ (1,954 LOC — strong deterministic backstops; contains the fix that makes the differential gate real)

Read end-to-end: the findings-emission pair (`_emit_ai_recon_findings` l.68 + `_emit_recon_findings_body` l.93-385, incl. the honeypot/tripwire logic + generic sensitive-data extractor), `run()` (l.1767-1954, multi-scope orchestration + cross-target + Target Model synthesis), and the full `_run_recon_for_target` decision spine: WAF fingerprint + baseline capture (l.694-870), the evidence-gated ReAct loop (l.878-1017), the deterministic subdomain-probe backstop (l.1019-1060), Tor ops-note + prompt (l.1145-1223), action execution + emit (l.1289-1381), bundle assembly (l.1401+). Helper stretches (scope-list, CIDR sweep, hosts-file, cross-target graph, attack-surface HTML parse — l.388-650, and the metric-extraction tail) are mechanical and were skimmed. Headline: recon carries the strongest **deterministic backstops** in the engine, and it contains the one fix that turns the differential success-gate from a no-op into a working gate.

## THE audit-level correction (upgrades the entire Tier-1 story)
- **The differential gate WAS a no-op and is now FIXED — `waf_baseline_body` (l.855-864).** The hypothesis engine's "similarity-to-normal" differential proof (the gate behind `_test_hypotheses` and `_validate_bypass_differential`, the template this whole document nominates for the Tier-1 fix) was being fed `waf_baseline_size` — **a number** — as the baseline. So measured similarity was ≈0 for every response, the "identical to baseline / no real differential" rejection could **never** fire, and **every claimed differential auto-passed the gate.** That is the corrupted-success-signal at the validation layer — the very thing we want to generalize. Recon now persists the actual baseline **BODY** (`(r_base.stdout)[:6000]`) unconditionally, so the differential gate finally has real ground truth to diff against. **Correction to Rounds 9-13:** when we said "copy `_validate_bypass_differential` everywhere," we were pointing at a gate that only started working once this body-vs-size bug was fixed. It works now; the Tier-1 generalization is sound *because* of this fix.

## Real defects found
- **RECON-EMIT-UNGATED (MED) — findings emitted from tool output WITHOUT a success check.** The action loop (l.1366-1371) calls `self.tools.parser.parse(...)` + `_emit_ai_recon_findings(...)` on `r_tool` regardless of `r_tool.success` — unlike exploitation, which gates on `if r.success and r.stdout`. So a failed/blocked tool's stdout (a 403 body, an error dump, a Tor connect-scan garbage list) is parsed and can mint findings via the `raw_lines`, `discovered_urls`, and generic-regex paths. Mostly backstopped by parser emptiness + tripwire pruning, but not fully (see next).
- **RECON-SENSITIVE-1 (MED — the recon mirror of EXPLOIT-EMIT-1).** The generic sensitive-data extractor (l.368-383) regex-scans `str(parsed)` for `-----BEGIN … PRIVATE KEY-----`, AWS keys (`AKIA|ASIA…`), and shadow entries and emits each as a **critical** finding with **no context, no differential, no proof**. Same unvalidated-substring→critical class as EXPLOIT-EMIT-1. Two mitigating differences: (a) the finding type is `private_key`/`cloud_secret`, NOT `VULN_PROVEN`, so it does **not** feed a confirmed-vuln/kill-chain gate — it only inflates the **report**; (b) the regexes are specific real formats (lower FP rate). But a docs page, a public sample key, or honeypot bait still trips it to critical — and combined with RECON-EMIT-UNGATED it can fire on a *failed* tool's error body. (Minor: l.381 `"encrypted_data" if name == "hash"` is a dead branch — no `hash` key exists in the regex dict.)
- **RECON-WAF-BASELINE (MED) — the size-exclusion filter is lost under Tor.** `waf_baseline_size` (used by gobuster `--exclude-length` / ffuf `-fs` to suppress WAF-block-length noise, l.1309-1321) is captured **only inside** the `fingerprint.confidence >= 0.5` block (l.774-790). Under Tor the behavioral WAF probe is deliberately skipped (deanonymization risk, l.711-719) so `fingerprint.confidence == 0.0` → the size is never captured → the exclusion filters never apply. Net: in exactly the mode where WAF 403s are most frequent, every block-length response is re-emitted as a discovered path. (The baseline BODY is captured unconditionally, so the differential gate is unaffected — only the size filter is.)
- **RECON-IDLE (LOW) — count-only empty-loop detection.** `_consecutive_empty_loops` keys purely on finding-count growth (l.906-911) — the exact pattern exploitation_agent explicitly fixed (adding a "did any command run?" check) because a WAF-blocked-but-active loop looks empty. Recon can undercount activity and lean toward early exit; mitigated by the `min_recon_loops` floor and the empty-prescription force-continue (l.1255-1262).
- **RECON-WAF-IDX (LOW) — possible IndexError.** l.768 `fingerprint.get("detected_patterns", ["unknown"])[0]` throws if the key exists as an empty list AND `waf_type` is falsy. Low-probability, inside the conf≥0.5 branch.
- **RECON-SUBSEV (LOW — architectural smell).** subfinder subdomains are force-set to `info` (l.289-293) to avoid report-severity bloat, which strands `subdomains_high/medium` empty and forces exploitation_agent to **re-derive** subdomain priority via a nano AI pass (exploitation l.1255-1301). A SOURCE (priority) is destroyed in recon and reconstructed in exploitation — a redundant AI round-trip and cross-file coupling.

## Corrections / strengths (the 🟡 "scan/prune/parse/bundle ~350 lines" tag undersold it badly)
1. **Honeypot/tripwire pruning (l.110-189) is a first-class egress-cascade defense.** It refuses to assert a honeypot from port-COUNT alone (the comment nails the root cause: "connect-scanning through a SOCKS/Tor proxy makes every port report open"), requires banner-similarity **corroboration** before ever claiming active defense, and otherwise **prunes** the implausible port list to verified-live web ports — deterministically discarding the classic W1 all-ports-open Tor artifact instead of weaponizing it into a "ban all scanning at confidence 1.0" (which the comment says "poisoned entire engagements"). This is a real, already-shipped mitigation of the egress cascade at the recon layer.
2. **Evidence-gated stage tracking (l.978-1017).** A stage is complete ONLY when its evidence finding-type exists, not when a tool string ran (`executed_commands[cmd]=True` is set unconditionally, so tool-ran ≠ stage-done). Three honest buckets: done / tried-but-empty / not-tried. Directly counters "executed ≠ produced."
3. **Deterministic subdomain-probe backstop (l.1019-1060).** If DISCOVERY found subdomains but the AI never probed them, recon probes them itself (once per target) and flips PROBING to genuinely-complete — a deterministic gate against "discovered then forgotten," not prompt-hope. This is exactly the kind of enforcement META-RC-0 says the engine usually lacks — here it exists.
4. **Tor handling is defense-in-depth, not prompt-hope.** The prompt explicitly bans `-p-`/`-p1-65535` under Tor (l.1145-1160) AND the emission prunes the garbage if the AI ignores it (l.164-189). The upfront WAF probe is skipped under Tor to avoid deanonymization (l.711-719), with the trade-off consciously documented.
5. **Persist-with-verification (l.1933-1940).** After writing recon phase_data it reads it back and re-writes if empty — a direct guard against the STATE-1 write-timeout data-loss concern.
6. **Target Model synthesis (WS2, l.1881-1916)** builds the impossible-vs-plausible vuln-class model that exploitation uses to stop attacking impossible surfaces; backend-exhaustion handling matches exploitation (wait for recovery, don't quit).

**Verdict on recon_agent after full read:** the strongest **deterministic-backstop** agent in the engine — tripwire pruning, evidence-gated stages, and the subdomain backstop specifically defuse the egress cascade and the discovered-then-forgotten data loss that the survey feared. Its real holes are ungated emission (parses failed-tool output), the RECON-SENSITIVE-1 substring→critical mirror, and the Tor baseline-size gap. The audit-level takeaway is the `waf_baseline_body` fix: the differential success-gate this document builds the Tier-1 plan around was a silent no-op until recon started persisting the response BODY — it is real now, and that validates the plan.

---
---

# ROUND 15 — `capability_registry.py` FULL READ (1,225 LOC — Pathology 4's concrete shape: two parallel registries for two agent tiers)

The file is ~790 LOC of **declarative `ToolCapability` data** (44 tool defs, l.131-820 — each with per-OS install scripts, risk level, category, resource-gate fields) plus the `CapabilityRegistry` class logic (l.881-1225). Read in full: the `ToolCapability` schema (l.104-125), the `CapabilityCategory`/`RiskLevel` enums, `ALL_TOOLS` + `_CAPABILITY_MAP` build (l.822-878), and every method — `_detect_os`, `_is_installed`, `resolve`, `_install_tool`, `_risk_gte`, `list_all_tool_binaries`, `get_installable_tools`, `get_tool_by_name`, `discover_custom_tool`, `get_registry` singleton. Then cross-referenced every `.resolve(` / `cap_reg` caller across the tree. This resolves Pathology 4 from "fragmentation, vaguely" to a precise mechanism.

## The core finding: TWO tool registries, split by agent tier (not dead — duplicated)
Cross-referencing callers shows the engine runs **two independent tool-provisioning stacks**, and each agent tier uses only one:
- **Main phase agents (recon, exploitation, weaponization, persistence) → the RAW-COMMAND path.** Their ReAct loops (read in full, Rounds 13-14) have the AI emit a **full shell command**, extract the tool name with `_extract_primary_tool`, and run it via `safe_run_tool` → `tool_manager.run` → **`TOOL_REGISTRY`** (tools/tool_registry.py) + tool_manager's own `discover_tool` AI-install fallback. **These agents never call `cap_reg.resolve()`.**
- **Specialist / mentor sub-agents → the CAPABILITY path.** The base-class ReAct loop (`base_agent.py` l.4717-4737) parses a `ReActAction{capability,…}` and calls `_execute_v6_action` → `cap_reg.resolve(capability)` → `_build_command_from_capability`, backed by **`capability_registry.ALL_TOOLS`** (44 defs here) + `discover_custom_tool`.

So `capability_registry` is **NOT dead** (an earlier worry) — but it is a **parallel universe** to `TOOL_REGISTRY`, with its own OS detection (`_detect_os` l.909), its own installer (`_install_tool` l.1045), its own `_installed_cache` + `_failed_cache`, and its own timeouts. A tool added/fixed/installed in one stack is invisible to the other. This is the concrete content of Pathology 4 ("provisioning/registry fragmentation"): not one broken registry, but two correct-in-isolation registries that never reconcile.

## CAPREG-FRAG-2 (MED→HIGH) — the Guardian allowlist only sees ONE of the two stacks
`ALL_TOOLS` is commented "**source of truth for Guardian allowlist**" (l.822), and `list_all_tool_binaries()` (l.1120) builds that allowlist from `ALL_TOOLS` + any tools `discover_custom_tool` added to `self._capability_map`. But the **main phase agents install arbitrary AI-chosen tools through `tool_manager.discover_tool`** (Round 12), which registers them in tool_manager's `TOOL_REGISTRY`/`_installed_cache` — **not** in `cap_reg._capability_map`. Therefore a main-path-discovered tool is **absent from `list_all_tool_binaries()`** and thus from the Guardian allowlist. Two possible consequences, to confirm when `utils/guardian.py` is read (Priority 5):
  - (a) the Guardian **blocks** legitimately-installed main-path tools (allowlist too small), or
  - (b) the Guardian **doesn't actually gate** the main path at all (allowlist advisory/unused there).
Either way, the "single source of truth" claim holds only for the specialist tier. **This is the highest-value item in this round — flagged for the guardian read.**

## CAPREG-GATES-DEAD (MED) — declared install gates that `_install_tool` never enforces
`ToolCapability` defines, with comments calling them "Path C gates," these fields on every tool: `can_auto_install` (Gate 1), `min_disk_mb` + `min_ram_mb` (Gate 4), `sha256` (Gate 6). But the actual installer `_install_tool` (l.1045-1105) reads **none** of them — no disk/RAM preflight, no checksum verification, no `can_auto_install` guard. Only `get_installable_tools()` (l.1133, a *listing* helper) consults `can_auto_install`; `min_disk_mb`/`min_ram_mb`/`sha256` are read **nowhere in the codebase**. So the resource/integrity gates are **declared but unenforced** — the exact META-RC-0 shape (a value is computed/declared and then not used as a gate) reproduced at the provisioning layer. On a low-disk/low-RAM VPS the installer will still attempt heavy installs; a `sha256` set on a binary download is never checked.

## Smaller real defects
- **CAPREG-INSTALL-DUP (LOW→MED) — divergent failed-cache windows for the same operation.** `CapabilityRegistry` caches install failures for **60 s** (l.1056), `tool_manager` for **300 s** (Round 12). The same tool failing to install is retryable after 1 min via one stack and blackholed for 5 min via the other — inconsistent, and a symptom of the duplication.
- **CAPREG-RESOLVE-FIRSTWINS (LOW) — `resolve()` picks the first *registered* candidate, not the best.** `resolve` (l.1004) filters by risk then returns the first installed candidate, else installs the first candidate (l.1032-1039). Ordering is list-declaration order in `_CAPABILITY_MAP`, so "which subdomain tool" is decided by ALL_TOOLS ordering (subfinder before amass), not by any quality/speed signal. Fine, but it's static priority masquerading as resolution.
- **CAPREG-OS-DUP (LOW) — third OS-detection implementation.** `_detect_os` (l.909) is a full os-release/package-manager probe — separate from tool_manager's `_wsl_which`/VPS-path logic. Another duplicated concern across the two stacks.

## Strengths / correct pieces
1. **The declarative model is genuinely good design.** Each capability maps to multiple tools with per-OS install scripts, risk classification, and category — exactly how a zero-hardcoding engine *should* describe its arsenal. The RLock reentrancy fix (l.891-894: `_install_tool` holds the lock then calls `_is_installed` which re-acquires it) is correctly reasoned. `discover_custom_tool` (l.1162) cleanly extends the capability map at runtime and keeps `resolve()`/`list_all_tool_binaries()` consistent for the specialist tier.
2. **Risk gating is real for the specialist path.** `resolve()` honors `risk_cap` and refuses `DESTRUCTIVE` tools unless `destructive_allowed` (l.1020-1029) — a genuine safety gate the specialists pass through (the main path has no equivalent, since it runs raw AI commands).
3. **arch-awareness** (amd64→arm64 rewrite, l.1074) and the ProjectDiscovery release-download install scripts are solid, real provisioning.

**Verdict on capability_registry after full read:** not dead, not broken — it is a **well-built second tool stack used only by the specialist/mentor sub-agents**, running in parallel to the `TOOL_REGISTRY`/`tool_manager` stack that the main phase agents actually use. That duplication IS Pathology 4, now concretely: two registries, two installers, two caches, two OS probes, divergent retry windows, and — most importantly — a **Guardian allowlist derived from only one of them** (CAPREG-FRAG-2), plus **install-safety gates that are declared but never enforced** (CAPREG-GATES-DEAD). The consolidation fix is: make `tool_manager` and `cap_reg` share one registry + one installed-cache (or have the main path register discovered tools into `cap_reg._capability_map`), and enforce or delete the Path-C gate fields. Confirm the Guardian-divergence direction when `guardian.py` is read.

---
---

# ROUND 16 — `ai_backend.py` FULL READ (1,321 LOC — kills the "exhaustion → hallucination" hypothesis; best-engineered file in the tree)

Read the decision-critical span end-to-end: `GroqKeyPool` in full (l.42-228 — recovery-window parsing, smart rotation, TPD/RPM state), `query()` (l.728-882, the multi-backend contract), `_query_groq_with_rotation()` (l.884-1087, the per-key TPD/RPM/auth/capacity state machine), `get_shortest_recovery_time()` (l.272), and the usage/budget accounting (l.312-350). Provider plumbing (`_compact_prompt_text`, `_select_backend_order_for_prompt`, `_detect_available`, `_ollama`/`_groq`/`_google`) skimmed — mechanical. This round is mostly a **correction**: one of the original four pathology framings ("LLM backend exhaustion → hallucination") is **false at the backend layer.**

## THE correction (retires a root-cause hypothesis)
- **The backend NEVER emits hallucinated/garbage output on exhaustion — it returns validated non-empty content or RAISES `RuntimeError`.** `query()` (l.728) validates every provider result is non-empty (FIX #3.4: empty → treated as failure, l.792-800, 818-825), and when all backends are exhausted it either sleeps for the recovery window and retries (bounded `_depth < 3`, l.870-876) or **raises `RuntimeError`** (l.878-882). `_query_groq_with_rotation` returns `None` (never a fabricated string) on total key failure (l.905, 917, 996, 1011, 1087). The main agents (recon/exploitation, Rounds 13-14) catch that `RuntimeError` and wait. **So "backend exhaustion → hallucination" is not a real path.** The engine's observed "hallucination" is therefore the model **reasoning from poisoned context** — the false `confirmed_vulns` from EXPLOIT-EMIT-1, the false criticals from the recon SENSITIVE regex, the "SUCCESS" empty scans from TOOLMGR-1 — i.e. **Pathology 2 (corrupted success signal) is the actual root of the hallucination symptom**, not the LLM plumbing. This sharpens the whole diagnosis: fix the success signal and the "hallucination" largely goes away; the backend needs no reliability work.

## The one real defect
- **AIBACKEND-SLEEP-1 (MED) — `query()` can block the whole engine for up to the full provider recovery window.** On total exhaustion, l.869-876 sleeps `get_shortest_recovery_time()` **inside** the synchronous `query()` call, up to `_depth < 3` times. `get_shortest_recovery_time()` returns the *shortest* deadline across keys/cooldowns — good — but on a genuine all-keys-TPD wipe every key carries the **default 3600 s** TTL (`_default_recovery_ttl`, l.51) or a parsed multi-minute window, so the shortest is still ~an hour. Net: one `query()` can hang the engine for ~3600 s (×up to 3 retries) with **no internal upper bound on the sleep**. Worse, the callers' smarter guard (`recovery_sec < 300` → wait, else pause 60 s and move on, seen in both agents) is **bypassed**, because `query()` performs the long sleep *before* returning control to the caller. This is the real face of "the engine goes unresponsive under exhaustion" — not hallucination, a multi-hour stall. Fix: cap the internal sleep (e.g. `min(recovery_time, 300)`) and return control to the caller, which already has phase-deadline-aware handling.

## Smaller notes
- **AIBACKEND-BUDGET-SOFT (LOW):** phase budget uses a `chars//4` token estimate (l.328) checked only at loop-tops after min-loops (recon l.894 / exploitation l.1676). A single very large call can overshoot before the next check, and dense output under-counts. Advisory circuit-breaker, not a hard cap — acceptable, but not a guarantee.
- **get_active_key can hand back a still-exhausted key** (l.123-131, the `recoverable` branch) — by design ("caller will handle retry"). The rotation loop then fails once on it and moves on, bounded by the 90 s wall-clock deadline (l.899). Not a bug, just a wasted attempt.

## Strengths (this is the most defensively engineered file in the codebase)
1. **The same-key fallback-model rescue (l.949-965) fixes a documented catastrophic bug.** When the primary 70B hits its **daily** limit on a key, the code first tries the smaller 8B (separate daily budget) **on the same key** before writing the key off — the comment records that without this "ONE 70B TPD marked the ENTIRE key dead for 60m ... a first run could burn all keys at once." This is exactly the failure that would have *looked* like "the engine died / started behaving randomly," and it is already fixed.
2. **Precise error taxonomy.** TPD vs RPM vs auth(401/403) vs 503-over-capacity are distinguished by message inspection (l.930-1069), each with the correct remedy: TPD → fallback model then exhaust-key; RPM → temporary skip + rotate (key stays alive); auth → permanent key death; 503 → switch to fallback model on same key (separate capacity pool) instead of stalling. The recovery window is parsed from the provider's own "try again in 4m14.88s" string (l.55-69), so waits are exact, not guessed.
3. **Clean non-empty contract end to end.** No code path returns an error string as if it were a response; empty is always a failure; total failure is always an exception. This is the correctness property that makes the callers' `try/except RuntimeError` handling sound.

**Verdict on ai_backend after full read:** robust, and diagnostically pivotal. It removes "backend exhaustion → hallucination" from the pathology list — the backend fails **loudly and safely** (RuntimeError), never with fabricated content. The only real defect is **AIBACKEND-SLEEP-1** (an unbounded internal recovery sleep that can stall the engine for ~an hour and bypasses the callers' smarter ≤300 s handling). The strategic takeaway for the whole audit: the "hallucination" the user observes is the model reasoning from a **poisoned context** produced by Pathology 2 upstream — so the corrupted success signal is confirmed, from a third angle, as THE root cause, and the LLM layer needs no reliability fixes (just the sleep cap).

---
---

# ROUND 17 — `orchestrator.py` FULL READ (1,058 LOC — robust, config-driven; one cross-cutting timeout hole)

Read the decision spine end-to-end: `__init__` wiring (l.79-227), `_phase_applicable` (l.358, FENCED adaptive skip), the full phase loop `run()` (l.414-894) incl. dependency gate, health/kill-switch, checkpointing, timeout handling, boundary validation, exception isolation, and the `finally` teardown. `_maybe_requeue_for_revisit` / `_save_*` skimmed. The `OrchestratorAgent` subclass (l.953-end) is the specialist-delegation manager (the tier that actually uses `cap_reg`, per Round 15) — noted, not deep-read. Net: the orchestrator is one of the better-architected files, with four fail-open phase gates and full per-phase fault isolation — and a single load-bearing interaction bug with the ai_backend sleep.

## The load-bearing finding (compounds AIBACKEND-SLEEP-1)
- **ORCH-TIMEOUT-1 (MED→HIGH in effect) — the phase timeout cannot preempt a synchronous sleep inside `ai.query()`.** The phase is run as `async with asyncio.timeout(phase_timeout + 60): async with asyncio.TaskGroup() as tg: tg.create_task(run_agent_async())` (l.716-721). But the agents' `run()` are `async def` that call **synchronous, blocking** `self.think()` → `self.ai.query()`, and `query()` can `time.sleep()` for the full provider recovery window (AIBACKEND-SLEEP-1, up to ~3600 s ×3). A synchronous `time.sleep` on the event-loop thread **blocks the loop** — `asyncio.timeout` only fires at `await` points, so it **cannot** interrupt it. Result: on a full-key-exhaustion event the engine blocks **past its own phase deadline**, defeating the orchestrator's primary hang-protection. This is the concrete mechanism behind "the engine goes unresponsive / hangs for a long time." Fix is the same as AIBACKEND-SLEEP-1: cap the internal sleep and return control to the caller (agents already honor `_phase_deadline`), so the orchestrator's timeout can actually take effect.

## Confirmations relevant to earlier rounds
- **The phase gate is coarse but multi-layered and fail-open (softens DEEP-5 at the orchestrator level).** Four sequential gates before an agent runs: (1) **dependency check** (l.516-548) — a required phase in a BLOCKING status skips the dependent, *unless* it produced findings (the `has_findings` hardening: a flaky-but-productive recon does not starve exploitation); (2) **FENCED adaptive applicability** (l.560-571) — one AI call may skip an OPTIONAL phase as pointless (persistence on a serverless SPA), **fails OPEN**, so it can only prune clearly-dead work; (3) **agent `_preflight`** (l.574-595); (4) **`validate_phase_prerequisites`** (l.651-663). The finding-*type* looseness (DEEP-5, base_agent Round 11) still lives in gate 4, but the orchestrator's own gate is a reasonable "did the prerequisite produce usable data" check, not a plausibility judgement — appropriate at this layer.
- **CAPREG-FRAG confirmed at the wiring level (Round 15).** `__init__` creates ONE `cap_reg` (l.97) and passes it to every agent (l.118), and separately creates `self.tools = ToolManager(...)` (l.96) with its own `TOOL_REGISTRY`. Both receive the same `self.tools.remote` executor but keep **separate install engines + caches** — the two-registry duplication is baked into construction. Only the specialist tier (`OrchestratorAgent.delegate_to_specialist`) exercises `cap_reg`.
- **Config-driven, with a documented fail-safe.** Phase orders / `PHASE_REQUIRES` / timeouts load from `rules/orchestration.json` (l.134-160) — not hardcoded. The fallback path (l.184-192) documents and fixes a real prior bug: the old default `BLOCKING_STATUSES` omitted `FAILURE`, so on a rules-load failure the dependency gate failed OPEN and let dependents run after a prerequisite **FAILURE**. Now includes FAILURE. Good.

## Strengths
1. **Per-phase fault isolation with leaf-unwrapping.** A crashed phase is caught (l.809-861), its `BaseExceptionGroup` unwrapped to the leaf cause (l.816-819 — fixes the opaque "unhandled errors in a TaskGroup (N sub-exceptions)" that used to hide the real error), recorded, boundary-validated even on failure (l.833-836), and the engagement **continues** to the next phase. Reporting-phase failure is special-cased to save partial results (l.855-859).
2. **Data-safety around the risky phases.** A native `sqlite3` `.backup()` checkpoint is taken before `exploitation`/`weaponization` (l.620-645, WAL-safe), and the `finally` block always saves a health summary, cleans stale VPS sessions, and closes the store (l.866-892) — so a mid-engagement crash or VPS disconnect can't lose the DB.
3. **Boundary validation enforces the result contract** (`ResultValidator.enforce_boundary`, l.752-754) on the success path — every phase result is normalized to the contract before being stored/passed on (ties into result_contracts.py, the next read).
4. **Live health governance:** a HealthMonitor kill-switch (`should_abort`, l.464), per-phase VPS health + disk auto-cleanup with a post-cleanup re-check (l.481-510), and W5.2 adaptive revisit (chevron loop-back when exploitation surfaces new in-scope attack surface, l.780-789) — the engine can loop back to recon, not just run one-way.

**Verdict on orchestrator after full read:** well-architected and defensively coded — four fail-open gates, full per-phase fault isolation, checkpointing, config-driven phases, and a documented history of fixing its own fail-open bugs. The single load-bearing defect is **ORCH-TIMEOUT-1**: its `asyncio.timeout` phase guard is silently defeated by the synchronous recovery `time.sleep` inside `ai.query()` (AIBACKEND-SLEEP-1), so under full LLM exhaustion the engine hangs past its deadline. These two together — not "hallucination" — are the real "engine becomes unresponsive" failure mode, and both are fixed by bounding that one sleep.

---
---

# ROUND 18 — `result_contracts.py` FULL READ (800 LOC — the DEFINITIONAL home of Pathology 2)

Read: `ResultStatus`/`ResultSeverity` enums + status-alias normalization (l.15-126), the `ToolResult` `success` property/setter + `validate()` (l.134-224), `PhaseResult` (l.256-324), `ResultValidator` (`validate_tool_result`/`validate_phase_result`/`enforce_boundary`, l.326-536), `FragileParseFixer` (l.539-695), and the `TargetModel` (l.697) + `ReconBundle` (l.766) dataclasses with their `validate`/`from_dict`. This file is where "success" is *defined*, so it settles Pathology 2 at the definitional layer.

## RC-SUCCESS-DEF (the definitional root of Pathology 2 — this is where the Tier-1 fix belongs)
- **`ToolResult.success` is purely structural.** It is `status ∈ {SUCCESS, FALLBACK_SUCCESS, PARTIAL}` (l.135-143) — nothing more. And `validate()` (l.175-224) enforces only **structural** consistency:
  - `success ⟹ exit_code == 0` (l.213)
  - `success ⟹ stdout or stderr non-empty` (l.215)
  - `exit_code == 0 ⟹ status ∉ {FAILURE, VALIDATION_ERROR}` (l.218)
  There is **no semantic check** — nothing asks "did this SUCCESS actually produce the RESULT the tool exists to produce?" (open ports for a scanner, findings for a vuln scan, a differential for an exploit). So at the contract level, **success ≡ "exited cleanly and printed *something*."** This is exactly why the banner-only nmap (TOOLMGR-1) is a valid SUCCESS: it has ~exit-0 and non-empty stdout (the banner), so it passes `validate()` cleanly. The contract **cannot** distinguish it from a scan that found ports. Every downstream `if r.success:` finding-parse gate (exploitation l.2221, recon, etc.) inherits this blindness.
- **This is the precise seam for the Tier-1 fix.** `validate()` already has the *right shape* — it even encodes "SUCCESS but empty output" as an error (l.215). The fix is to add a **per-capability expected-result predicate**: a scanner's SUCCESS requires `parsed.open_ports`/`parsed.findings` non-empty; a fetch requires a body distinguishable from the WAF baseline (the differential recon now persists — Round 14); otherwise downgrade to `NO_FINDINGS`/`PARTIAL`. Landing it here (or in the tool_manager classifier that constructs `ToolResult`, TOOLMGR-1) fixes the signal for *every* consumer at once, because they all read this one `success` definition.

## Notes / smaller points
- **The PARTIAL-counts-as-success rule is correct and load-bearing (l.136-143).** The comment documents a real bug: if PARTIAL didn't count as success, the `if r.success` parse gate would silently DROP useful-but-WAF'd output (whatweb fingerprint behind a WAF) — a genuine "found nothing" cause. So the fix must **narrow** SUCCESS by semantic emptiness, NOT by tightening PARTIAL — the two are orthogonal.
- **Status normalization is good (l.98-126).** It maps tool_manager's ad-hoc strings (`"partial_success"` → `PARTIAL`, etc.) to canonical enums, so the ToolResult in tool_manager (Round 12) and this contract agree. `NO_FINDINGS` is correctly **excluded** from the success set — a tool that ran and found nothing is not "success" (good; the gap is only that TOOLMGR-1 never *assigns* NO_FINDINGS to the banner case).
- **`enforce_boundary` (l.488) is a real structural gate.** Phase-result invalidity raises (l.530); tool-result invalidity raises only on `CRITICAL` severity (l.515). This is the contract enforcement the orchestrator relies on (Round 17) — structural only, by design.
- **`ReconBundle.validate()` (l.790) checks TYPES only** (list/dict), not completeness; **`TargetModel` has no validate()** — both are defensively-defaulted `from_dict` contracts (no crash on malformed data). Fine for their role, but they provide no semantic guarantee that recon actually found anything — consistent with the structural-only theme.
- **`FragileParseFixer.safe_split_json_extraction` (l.545)** is the hardened JSON extractor used across the engine (tool_manager discover, ai repair, etc.) — markdown-fence-aware, never IndexErrors. A quiet correctness win that de-fangs PARSER-2 (fragile string round-trips) at the JSON layer.

**Verdict on result_contracts after full read:** a clean, well-normalized contract layer — and the **definitional home of Pathology 2**. `ToolResult.success` means "exited with output," never "produced the expected result," and `validate()` only checks structural coherence. This is not a bug in this file so much as the *place the semantic success-gate is missing*: the Tier-1 fix (a per-capability expected-result predicate, seeded by the now-working differential baseline) belongs either here in `validate()`/`success` or in the tool_manager classifier that sets `status` — landing it at this single definition corrects the signal for every `if r.success` consumer in the engine simultaneously.

---
---

# ROUND 19 — `state_store.py` FULL READ (737 LOC — the last finding-loss point in the data path; STATE-1 confirmed + 3 new)

Read: connection setup + background writer (`__init__`, `_writer_loop`, `_submit_write`, l.14-108), the full schema (`_init_schema`, l.112-233), the finding path (`add_finding`/`get_all_findings`/`has_findings`, l.276-338), the phase-data path (`set_phase_data`/`get_phase_data`, l.347-445), and `close()` (l.720). Query/graph/credential helpers skimmed (mechanical SELECTs). This is a **single-writer-thread + WAL** design — sound for SQLite concurrency — but it is the **final place the recon→exploitation data path loses findings**, and it confirms STATE-1 with a precise mechanism plus three adjacent bugs.

## Finding-loss and lost-update bugs (these produce the "found nothing" symptom)
- **STATE-DEDUP-120 (MED) — the authoritative finding dedup drops on a 120-char prefix.** `add_finding` pre-checks for duplicates using `SUBSTR(detail, 1, 120)` (l.290-296) and returns early on a hit — **stricter** than the table's `UNIQUE(engagement_id, finding_type, target, detail)` on the FULL detail (l.153) and than base_agent's 160-char in-memory dedup (NEW-4, Round 11). So two genuinely-distinct findings that share their first 120 chars but differ afterward (long endpoint URLs differing only in a late query string; verbose details with a common prefix; two records whose distinguishing token sits past char 120) → the **second is silently dropped at the store**. This is the *authoritative* loss point: a finding can pass base_agent's 160-char gate and still die here on 120. Two inconsistent dedup keys (160 in-memory, 120 at DB) for the same data is itself a smell; the tighter one wins and loses data.
- **STATE-MERGE-RACE (MED) — non-atomic read-modify-write loses phase_data updates.** `set_phase_data` (l.367-399) reads the existing row on the **read** connection (`self.conn`), merges in Python, then submits the write — the read and write are **not atomic**, and the read may not even see an in-flight write still sitting in the writer queue (WAL + separate write connection). Recon issues *several* `set_phase_data` calls for the same `(engagement, "recon")` key in quick succession — the immediate WAF persist (recon l.794), the bypass persist (l.841), and the final multi_bundle (l.1919) — so these race: each merges onto a possibly-stale snapshot, last-committed-writer wins, and intermediate keys are clobbered. Recon's verify-and-retry (Round 14) masks total loss, not this partial-merge loss.
- **STATE-1 confirmed — `_submit_write` 10 s timeout, with a subtle downstream effect.** `_submit_write` enqueues the task then waits `event.wait(timeout=10.0)`; on timeout it raises `RuntimeError("State store write operation timed out")` (l.107-108). The data is **not lost** (the task stays in the FIFO and the single writer executes it later), but two real consequences: (a) the caller raises — `add_finding` (l.301) does **not** catch it, so a slow write can abort the calling path; (b) a read issued right after a timed-out write sees **stale** data, so the momentum / idle-loop `produced_findings` signal (recon l.906, exploitation l.1697) **undercounts** and can declare a false "empty loop" → premature phase exit. The single-writer FIFO means **head-of-line blocking**: a large `set_phase_data` (the recon multi_bundle serialized to JSON can be MBs) delays every finding write queued behind it, making the 10 s timeout reachable exactly when the engine is busiest.
- **STATE-CLOSE-2S (MED) — end-of-run writes can be dropped.** `close()` enqueues the drain sentinel then `writer_thread.join(timeout=2.0)` (l.722-724). The writer processes the sentinel only after draining all prior writes (FIFO), so if the backlog at engagement end (final reporting-phase findings + large phase_data) takes >2 s to drain, `join` times out, `close()` closes the read conn and returns, and the daemon writer can be killed by process exit mid-drain → **the last writes are lost**. The most report-critical writes (final findings) are the ones at highest risk.

## Strengths (the design is sound for consistency)
1. **Single background writer + WAL** serializes all writes through one connection (l.68-97) — no writer-writer contention, atomic commits, and `_submit_write` blocks the caller until the write actually commits (`event.set()` after `commit`, l.89-94), so a *successful* submit is read-your-writes consistent. This is the right SQLite concurrency model; the bugs above are at the edges (timeout, non-atomic merge, close), not the core.
2. **Schema fixes with documented rationale.** `UNIQUE(engagement_id, phase)` on `phases` (l.127) and `PRIMARY KEY(engagement_id, phase)` on `phase_data` (l.167) — the comment (l.122-127) records the real prior bug: without the unique key, `INSERT OR REPLACE` duplicated rows and `get_phase_status` (no ORDER BY) returned a **stale** row. Fixed.
3. **Input hygiene + defensive reads.** `add_finding` drops empty-detail findings (l.278) and whitelists severity (l.286); `get_all_findings`/`get_phase_data` skip corrupted/empty rows (l.319, 425); `_wait_for_init` (l.60, FIX 3.5) blocks callers until the schema exists, preventing early-read races; `close()` does a `wal_checkpoint(TRUNCATE)` (l.729) to flush WAL into the main DB.

**Verdict on state_store after full read:** a consistency-correct single-writer/WAL store whose **edges leak findings** — the too-tight 120-char dedup (STATE-DEDUP-120) silently drops distinct findings, the non-atomic phase_data merge (STATE-MERGE-RACE) loses updates under recon's multi-write pattern, the 10 s write timeout (STATE-1) both aborts callers and feeds the idle-loop undercount, and the 2 s close-join (STATE-CLOSE-2S) risks the final report writes. Together with the four upstream loss points already mapped (SANITIZE-1 \r-deletion, PARSER-3 nmap regex, base_agent 160-char dedup, PARSER-2 round-trip), this makes the store the **fifth and last** place the data path can drop a finding — concretely explaining the "engine found nothing" symptom independent of the success-signal issue. Fixes: raise/normalize the dedup key to full-detail hashing (align base_agent 160 and store 120), make `set_phase_data` an atomic upsert-merge inside the writer thread (not a read-then-write on two connections), decouple the caller from the 10 s write wait for non-critical writes, and lengthen/flush-guarantee the `close()` drain.

---
---

# ROUND 20 — `waf_ghost_engine.py` FULL READ (728 LOC — the command-mutation engine; reactive-by-design, but its learning is defeated by stateless reuse)

Read: `transform()` (l.49-408, the mutation dispatcher — reactive gate, adaptive level calibration, per-tool header/protocol injection, origin-swap, TLS impersonation), `_mutate_payloads` (l.410-505), `_generate_stealth_headers` (l.565-597), `feedback`/`get_block_rate` (l.599-619), and `solve_challenge` (l.624-728). This is the engine tool_manager (TOOLMGR-3) and base_agent invoke on WAF blocks. Its design substantially **refutes** the original survey's "force-routes everything through evasion → 403 cascade" framing — but a state-lifetime bug cripples the very learning that makes it smart.

## The load-bearing correction (egress cascade at the mutation layer)
- **Evasion is REACTIVE and conservative — it does NOT mutate blindly (l.86-90).** `transform` looks up `get_block_rate(target, tool)` and, **if the block rate is 0.0 and the caller did not `force`, returns the command UNCHANGED** — the first request always goes clean, and mutation only happens after a real recorded block (via `feedback()`) or an explicit force (a block just happened). Raw-socket tools (nmap/masscan/sslscan/dig/naabu) are skipped entirely (l.108-112, HTTP header evasion is meaningless for them). The comment even names the exact failure the original survey feared: "Mutating a command with no WAF evidence is pure downside ... has repeatedly broken tools (e.g. comma-laden UA headers) while a false-positive WAF detection can fire it." So at the ghost-engine layer, the cascade concern is already mitigated by design: clean-first, mutate-on-evidence, escalate by observed block rate (l.91-104).

## The bug that undercuts it
- **WAFGHOST-STATELESS (MED — deepens TOOLMGR-3).** `_feedback_stats` is a plain **per-instance in-memory dict** (l.607-609), never persisted. The engine's entire adaptive value (reactive gate + block-rate level calibration) depends on that accumulated feedback — but tool_manager instantiates a **fresh** `WafGhostEngine` on every retry with `force=True` (Round 12, TOOLMGR-3). A fresh instance always has `block_rate == 0.0`, so on the tool_manager retry path the calibration can never observe history: it always falls to the forced-minimum level (l.91-93) and never learns which tactic actually cleared the block. Worse, `feedback()` that agents record on a long-lived base_agent instance is **invisible** to tool_manager's throwaway instances. Net: two disjoint usage patterns, and the retry path is memoryless. Fixing this (share ONE engine instance + persist `_feedback_stats` to the WAF DB) is the single highest-leverage WAF improvement — it makes the already-correct reactive design actually accumulate across retries and engagements.

## Smaller / dubious tactics (evidence-gated, so low blast radius)
- **WAFGHOST-KWBREAK (LOW):** level≥3 keyword-breaking inserts a URL-encoded null byte into SQL keywords (`SELECT` → `S%00ELECT`, l.446). A `%00` usually breaks the payload or is server-rejected rather than evading — a WAF-EVA-2-class broken tactic — but it only fires at level≥3 (heavy observed blocking).
- **WAFGHOST-EQLIKE (LOW):** if `=` is in `blocked_chars`, it replaces `=` across the whole command with ` LIKE ` (l.425) — which would corrupt flags/headers/URLs that contain `=`. Gated on the rare "equals explicitly blocked" signal.
- Path traversal `../`→`..\` (l.429) only helps on Windows targets; inert on Linux. Minor.
These are the "broken individual tactics" the WAF inventory (W4b) flagged — confirmed present, but here they are gated behind explicit block-evidence, so they rarely fire on a healthy run.

## Corrections to the dead-code list / capability inventory
- **`solve_challenge` (l.624-728) is a REAL, functional CAPTCHA/JS-wall solver** — it uploads and runs a Playwright headless-Chromium script on the remote host, waits out JS challenges, extracts clearance cookies, and injects them into the retry command (curl `-b`, wget/sqlmap/ffuf/gobuster cookie headers). It is anti-detection-hardened (`navigator.webdriver` spoof, `--disable-blink-features=AutomationControlled`) and uses `FragileParseFixer.safe_marker_extraction`. This means active challenge-solving **exists and is wired**, independent of the DEAD `browser_driver.py` — the capability is not missing, it lives here.
- **TLS/JA3 impersonation is real** (l.155-167): at level≥3 it rewrites curl onto a `curl-impersonate` binary when installed, defeating JA3 fingerprinting no header spoofing can — a genuine, modern evasion, safe no-op when absent.
- **Origin-IP swapping is wired** (l.121-141): it pulls the active bypass strategy from `WafBypassOrchestrator.get_active_strategy` and, when an origin is known, rewrites the URL to the origin IP + sets the `Host` header — the orchestrator (Round 9) and this engine are genuinely integrated.

**Verdict on waf_ghost_engine after full read:** a well-designed, reactive, evidence-gated mutation engine that is **much closer to "correct WAF handling" than the survey implied** — clean-first, raw-socket-aware, block-rate-calibrated, with real TLS-impersonation, origin-swap, and a functional Playwright challenge-solver. Its two genuine problems are (1) **WAFGHOST-STATELESS** — the feedback that powers all of the above is per-instance and thrown away on tool_manager's per-retry re-instantiation (TOOLMGR-3), so the learning never compounds; and (2) a few **evidence-gated dubious mutations** (null-byte keyword breaking, global `=`→`LIKE`) that can corrupt commands when they do fire. The WAF-improvement path is therefore not "add more evasion" but "**make the existing reactive engine remember**" (shared instance + persisted feedback) and prune/repair the two broken tactics — after which its already-correct escalation ladder becomes genuinely adaptive.

---
---

# ROUND 21 — `hypothesis_engine.py` FULL READ (478 LOC — the Tier-1 fix template, VERIFIED correct and more sophisticated than credited)

Read in full: `generate_hypotheses` (l.62-171), `validate_result` (l.177-333), `_build_evidence` (l.335), `_cap_severity_by_proof` (l.350), `_response_similarity` (l.384), plus the `Evidence` dataclass + `is_proven()` it depends on (`result_contracts.py` l.640-666). This is the "researcher brain" behind exploitation's `_test_hypotheses` (Round 13) and the concrete implementation of the differential/evidence gate this whole document nominates as the Tier-1 success-signal fix. Conclusion: **the gate exists, is correct end-to-end, and is more rigorous than earlier rounds credited** — so the Tier-1 work is "route the ungated paths through THIS," not "build a gate."

## The gate, verified end-to-end
1. **Generation is real research, not a CVE checklist.** `generate_hypotheses` (l.103-149) reasons over structured evidence and demands each hypothesis ship an explicit `expected_if_vulnerable` observable (status/body/diff/timing/OOB) — the signal `validate_result` later judges against. It asks for ≥half novel/target-specific logic flaws, ranks by confidence, dedups against `prior_results`. Clean.
2. **The MANDATORY EVIDENCE GATE (l.298-329) fails closed.** A "confirmed" verdict is only accepted if `Evidence.is_proven()` is true; otherwise it is **downgraded to "inconclusive" (a lead), confidence capped at 0.4, severity forced to info** (l.309-321). So an AI that says "confirmed" with no real proof cannot mint a vuln.
3. **`Evidence.is_proven()` is correctly defined (result_contracts l.660-666):**
   - `differential` proof → requires a **non-empty differential description AND** `similarity_to_baseline < 0.97` (or `< 0` = unmeasured). So a bypass that returned ~the same page as baseline is rejected.
   - `artifact` / `oob` → self-proving, accepted (a SQL error, leaked `/etc/passwd`, or an OOB callback that can sit inside an otherwise-identical page).
   - `none` → never proven.
4. **Severity is capped by demonstrated impact, not the vuln-class name (`_cap_severity_by_proof`, l.350-382).** A bare reflection/length-delta caps at **medium**; only strong impact markers (`extracted`/`rce`/`auth bypass`/`/etc/passwd`/…) or artifact/OOB proofs allow critical. This is the exact anti-inflation control that **EXPLOIT-EMIT-1 lacks** — the same agent has a rigorous path here and a raw-substring path there.

## Why recon's `waf_baseline_body` fix (Round 14) is load-bearing — now provable
`validate_result` computes `measured_sim = _response_similarity(stdout, baseline)` (l.304-305) and stores it in the `Evidence` object. `_response_similarity` (l.384-397) is a real `difflib` ratio over capped prefixes. So:
- **With a real baseline body** (recon's fix), a differential proof must measure `< 0.97` similarity to normal → the gate genuinely discriminates a true delta from "same page."
- **Without a baseline** (`similarity_to_baseline == -1`), `is_proven()` falls back to "the AI *described* a differential" (`similarity < 0` branch passes) — a weaker, trust-the-AI degrade. This is the **one residual soft spot**: on any target/tool where recon didn't capture a body, the differential gate cannot measure and leans on the AI's word. Acceptable fallback, but it means the baseline-body must be present for the gate to be strong — reinforcing that recon's fix is what upgraded this from advisory to enforcing.

## Documented prior bug this file already fixed (a real "0 proven" driver)
The comment at l.287-296 records a previous pre-filter that downgraded **any** confirmed whose response was ~identical to baseline **regardless of proof_type** — which silently discarded valid **artifact/OOB** proofs (a SQL error or leaked secret sitting inside an otherwise-identical page). That was "a real driver of '0 proven'." The current proof_type-aware gate fixes it: similarity only gates *differential* proofs, never artifact/OOB.

**Verdict on hypothesis_engine after full read:** this is the **strongest, most correct component in the engine** — a proof-mandatory, proof_type-aware, severity-capped, fail-closed evidence gate, fed by a genuine hypothesis-generation researcher brain. It settles the Tier-1 question definitively: **the success-signal fix is not new construction — it is routing the ungated finding paths (EXPLOIT-EMIT-1 substring→VULN_PROVEN, TOOLMGR-1 banner→SUCCESS at the classifier, recon SENSITIVE regex→critical, and the tool_manager result classifier generally) through this existing `validate_result`/`is_proven` gate (or a lightweight capability-level analogue of it).** The only thing that upgraded this gate from advisory to enforcing was recon persisting the real baseline body — so the two fixes are coupled: keep the baseline body flowing, and route everything that can mint a "confirmed"/"critical" through the proof gate.

---

# Round 22 — `utils/guardian.py` (347 LOC, FULL read) + `agents/base_agent.py` l.2430-2499 (call-site confirmation)

**Purpose of this round:** close the CAPREG-FRAG-2 question left open in Round 15 ("is the guardian allowlist derived from `capability_registry.ALL_TOOLS`, or is it a third independent list?"). **Answer: it is a THIRD, fully independent, hardcoded tool list — and it gates the *main* command path.** This is the definitive Pathology 4 (registry fragmentation) finding, and it is also a *direct contradiction of the stated autonomous design*.

## GUARDIAN-ALLOWLIST-1 (HIGH) — a hardcoded ~90-tool allowlist blocks any novel AI-discovered tool on the main path

**What the code does**
- `guardian.py` l.13-38 defines `ALLOWED_RECON_TOOLS` = a **hardcoded Python set** of ~90 tool binary names (nmap, ffuf, sqlmap, nuclei, …). The comment at l.33-37 literally says *"Keep this a superset of the registry"* — i.e. it is maintained **by hand**, not generated from `capability_registry.ALL_TOOLS` (44 defs) nor from `tool_manager.TOOL_REGISTRY`.
- l.195-196 builds `_ALLOWED_RECON_TOOLS_LOWER` and `validate_ai_command()` (l.67-332) **rejects any command whose leading binary is not in that lowered set**.
- `block_or_repair()` (l.335-347) wraps `validate_ai_command` and returns the block/repair verdict.

**Where it bites (call-site, confirmed in base_agent.py):**
- `agents/base_agent.py` l.2445 calls `guardian.block_or_repair(...)` **inside the main `safe_run_tool` path** — the path *every* phase agent (recon/exploitation/etc.) uses to run an AI-chosen raw command. So the allowlist is not advisory and not specialist-only; it is the front door for the primary autonomous loop.
- The destructive branch (l.2454-2492) additionally routes `REQUIRES_APPROVAL` verdicts to a human-in-the-loop `input()` gate (defaults to **reject on EOFError** — correct fail-safe for headless VPS runs).

**Why this is a root-cause-class defect (not a nitpick)**
The user's stated design is: *"the AI can decide any tool it wants, from anywhere, install it and use it."* `tool_manager` supports exactly that — `discover_tool` / dynamic install can bring in a binary the engine has never seen. **But the guardian allowlist is checked *before* execution and has no knowledge of anything `tool_manager` just installed.** So the autonomous path is:

```
AI reasons "use tool X" → tool_manager installs X successfully →
guardian.block_or_repair() sees X ∉ ALLOWED_RECON_TOOLS → BLOCKED →
agent records a tool "failure" that is actually a policy block →
feedback loop poisoned with a false "X doesn't work here"
```

This is a **fourth, independent contributor to the corrupted-feedback pathology** *and* the concrete mechanism by which "zero-hardcoding, go-anywhere autonomy" silently degrades to "you may only use the ~90 tools someone typed into a set in 2025." Every genuinely novel tool the model discovers is a guaranteed dead end, and the engine cannot tell a *policy block* apart from a *tool that failed on the target*.

**This is the THIRD registry — Pathology 4 is now fully enumerated:**
| Registry | Location | Shape | Consumed by |
|---|---|---|---|
| `ALLOWED_RECON_TOOLS` | guardian.py l.13-38 | hardcoded `set[str]` (~90) | **main path** gate (base_agent l.2445) |
| `ALL_TOOLS` | capability_registry.py | 44 `ToolCapability` dataclasses | specialist/mentor sub-agents (`cap_reg.resolve`) |
| `TOOL_REGISTRY` | tool_manager.py | dict of exec metadata | raw-command execution/install |
These three are maintained separately and **can disagree**: a tool can be installable (`TOOL_REGISTRY`) and capability-modeled (`ALL_TOOLS`) yet still blocked (`ALLOWED_RECON_TOOLS`), or allowed by the guardian but absent from the capability registry. Nothing reconciles them at startup.

**Fix direction (documentation only — no code change here):** the guardian allowlist should be *derived*, not *authored* — union of `TOOL_REGISTRY` keys + `ALL_TOOLS` binaries + any tool `tool_manager` has successfully installed this run (a live set the guardian consults), with the *hardcoded* set kept only as an explicit deny/danger list. The security control that actually matters (BLOCKED_PATTERNS / DESTRUCTIVE_PATTERNS below) is orthogonal to the allowlist and should stay. In other words: **keep the danger-pattern gate, drop the tool-identity allowlist as the autonomy-limiter** — that is the single change that most restores the "go-anywhere" design without weakening the real safety rails.

## What the guardian gets RIGHT (keep — these are the real safety rails, and they are pattern-based, not identity-based)
- **`BLOCKED_PATTERNS` (l.48-53):** hard-deny for `rm -rf /`, `mkfs`, `systemctl stop`, fork bombs, etc. — unconditional, correct, and *tool-agnostic* (works no matter what novel binary the AI picks). This is the control that should carry the safety weight.
- **`DESTRUCTIVE_PATTERNS` (l.56-64):** `drop database`, `delete from`, bare `rm`, etc. → downgraded to `REQUIRES_APPROVAL`, routed to the base_agent HITL gate (l.2454-2492) that fails closed on EOF. Good design: destructive ≠ blocked, it's *escalated*.
- **Fail-closed HITL default** (base_agent l.2466 area): on headless VPS (`input()` → EOFError) the destructive command is rejected, not silently run. Correct posture for autonomous ops.

**Net verdict:** the guardian's *danger detection* is a strength and load-bearing; its *tool-identity allowlist* is the defect. They are separable — which is exactly why the fix ("derive the allowlist, keep the pattern gate") is low-risk. GUARDIAN-ALLOWLIST-1 promotes Pathology 4 from "provisioning/registry fragmentation" to a **named, three-registry, main-path-blocking** finding and resolves the last open question from Round 15.

---

# Round 23 — `intelligence/waf_learner.py` (517 LOC, FULL read) + both call-sites in `base_agent.py` + the reporting-agent batch path

**Purpose:** verify LEARN-1 / WAF-LEARN-1 against the actual wiring. Result: the WAF-tactic-effectiveness subsystem — the entire reason `WafLearner` exists — is **structurally incapable of producing a correct per-tactic success rate**, for THREE independent reasons that compound. This supersedes and expands the earlier WAF-LEARN-1 note (which only caught the `str(tactic)` key on the block path).

## Wiring (confirmed, not assumed)
- `base_agent.py:281` instantiates `self._waf_learner = WafLearner()`. Two live writers:
  - **Success writer** — l.3023-3045, fires for any HTTP tool when `waf_present or waf_fingerprint`, after a returned `result`.
  - **Block writer** — l.3215-3250, fires when a WAF block is detected and an evasion tactic is selected.
- `reporting_agent.py:400-442` instantiates a *second* `WafLearner` at engagement end and calls `learn_from_engagement(...)` (batch path).
- `intelligence/engagement_analyzer.py:97/268` is the *correct* consumer of tool-run data — it reads via `store.get_tool_runs()` (the SQL table) and keys off `run.get("evasion_applied")`.

## WAFLEARN-KEYSPLIT (HIGH) — successes and failures are filed under DIFFERENT keys, so no tactic can ever have a real success_rate
- **Success path (base_agent l.3044-3045):** `update_tactic_effectiveness("header_mutation", True, waf_id=…)` — the tactic key is the **hardcoded string literal `"header_mutation"`**, regardless of which evasion tactic (if any) was actually applied. Every WAF-context HTTP success credits the literal `"header_mutation"`.
- **Block path (base_agent l.3249-3250):** `update_tactic_effectiveness(str(tactic), False, waf_id=…)` where `tactic` is a **dict** (`{"name": "header_mutation", …}`, l.3215-3216). So the key becomes the stringified dict `"{'name': 'header_mutation', ...}"`. The correctly-extracted `tactic_name` (l.3217-3218) is sitting *right there*, used for logging (l.3221/3227/3231), but **the wrong variable is passed to the learner.**
- **Consequence:** in `db["tactics"]`, the key `"header_mutation"` accumulates **successes only** (→ `success_rate` trends to 1.0) while the key `"{'name': 'header_mutation'...}"` accumulates **failures only** (→ `success_rate` fixed at 0.0). The two never meet. `_update_tactic_effectiveness` (l.412-428) computes `success_rate = successes/total_runs` **per key**, so every tactic's rate is either ~1.0 (success-only key) or 0.0 (failure-only key) — **never a blended, meaningful number.** The core metric the learner exports is noise. The downstream `_rate_tactic` (l.276-287) and `_generate_recommendations` "highly effective (≥0.8)" logic (l.220-227) therefore fire on the success-only key unconditionally: **it will always "learn" that header_mutation is highly effective, and always "learn" that every real tactic is ineffective.**

## WAFLEARN-BATCH-DEAD (MED-HIGH) — the engagement-end path that WOULD compute proper rates is fed an empty list
- `reporting_agent.py:430-435` builds `engagement_data["tool_runs"]` by reading `phase_data["tool_runs"]` for each phase (`if "tool_runs" in phase_data`).
- **But nothing ever writes `"tool_runs"` into phase_data.** Tool runs are persisted only to the **SQLite `tool_runs` TABLE** (`state_store.py:129-140`, written by `record_tool_run` l.251, read by `get_tool_runs` l.262). A repo-wide grep for `tool_runs` shows the *only* readers of `phase_data["tool_runs"]` are these reporting-agent lines; there is **no corresponding writer.**
- **Consequence:** `engagement_data["tool_runs"]` is **always `[]`** → `learn_from_engagement` calls `_analyze_tactic_effectiveness([], fp)` → returns `[]` → `updated_tactics` empty. The batch path can still discover a *new fingerprint* (from `waf_fingerprint`), but it **learns zero tactic effectiveness, ever.** The only reason the base_agent per-event writers (with the KEYSPLIT bug above) are the sole live source of tactic scores is that this batch path — the one that reads a real `success`/`evasion_applied` per run — is silently wired to the wrong store. Fix is one line of intent: read `store.get_tool_runs(engagement_id)` (like engagement_analyzer already does) instead of `phase_data["tool_runs"]`.

## LEARN-1 confirmed at source (the corrupted success signal reaches here too)
- The success writer (l.3033-3045) fires whenever `result` came back "successful" for an HTTP tool with a WAF present. That success verdict is `ToolResult.success` — the **structural** signal that TOOLMGR-1 / result_contracts (Pathology 2) already showed can be a banner-only false positive. So even after WAFLEARN-KEYSPLIT is fixed, the success counts folded into `"header_mutation"` are only as trustworthy as the success signal feeding them. **WafLearner sits downstream of Pathology 2** — it cannot be made correct without the Tier-1 success-gate, exactly as the MD's remediation §754 states ("gate WafLearner on validated blocks only").

## What waf_learner.py gets RIGHT (keep — these are real, already-fixed robustness wins)
- **Atomic DB writes (l.449-465):** temp-file + `os.fsync` + `os.replace`. The docstring documents the prior bug (truncate-and-write left invalid JSON → `_load_database` swallows the decode error → **every learned fingerprint wiped**). Correctly fixed.
- **Read-modify-write fully inside the lock (l.328-347, l.389-431):** the docstrings document that the lock previously released right after the read, so concurrent block/success updates clobbered each other. Now the whole RMW is inside `_database_lock`. Correct.
- **`_database_lock` parent-dir guard (l.293-299):** documents that on first run the parent dir may not exist, making `os.mkdir(lock_dir)` raise `FileNotFoundError` (not `FileExistsError`) and silently fail *every* write. Fixed by `os.makedirs(parent)` first. Good defensive catch.
- **`update_tactic_effectiveness` public wrapper (l.352-380):** correctly reads prior per-(tactic,waf) counts and folds in one outcome before persisting totals — the aggregation math is right. The bug is **not** here; it's in the *keys* the callers pass.
- **Retry-After / rate-limit capture (l.58-70, l.255-260):** genuinely useful — turns a 429 header into a learned per-WAF delay recommendation.

**Net verdict:** `waf_learner.py` itself is well-engineered (atomic, locked, self-healing DB). The failure is entirely at the **wiring seam**: the two base_agent writers pass mismatched keys (KEYSPLIT), and the one batch path that reads real per-run outcomes reads from the wrong store (BATCH-DEAD) so it's a no-op. The subsystem *looks* like it learns tactic effectiveness across engagements; in practice it records "header_mutation always wins, everything else always loses," and its cross-engagement batch learner is inert. This is a concrete, high-value instance of Pathology 3 (permanent corrupted feedback) — the "learning" is not just poisoned by the success signal, it is **mis-keyed at the call site so it can never converge regardless of signal quality.**

## Ties into the user's WAF-improvement sub-request
This is the second half of the "make the WAF engine actually remember" note (first half: TOOLMGR-3 + WAFGHOST-STATELESS = the ghost engine forgets per-retry). Here the *learner* persists fine but records garbage. The combined WAF-memory fix is three coupled changes, all diagnosis-only for now:
1. **Share one `WafGhostEngine`** across retries + persist its `_feedback_stats` (Round 20).
2. **Pass `tactic_name`, not `str(tactic)`, on the block path (l.3250); pass the actually-applied tactic name, not the literal `"header_mutation"`, on the success path (l.3045)** — so successes and failures land on the same key.
3. **Point the reporting-agent batch learner at `store.get_tool_runs()`** (l.433) so cross-engagement tactic effectiveness is computed from real per-run `success`/`evasion_applied`, and **gate it on validated blocks** (Tier-1 success-signal fix) so the counts mean "beat a real WAF," not "exited."

---

# Round 24 — `intelligence/waf_fingerprinter.py` (663 LOC, FULL read) + recon call-site (recon_agent l.700-799)

**Purpose:** this file produces the `waf_fingerprint` / `waf_present` / `waf_type` that drive the *entire* WAF machinery (evasion engine, orchestrator, and the learner analyzed in Round 23). Verify (a) whether it can misread Tor-403s as a WAF — the original egress-cascade hypothesis — and (b) whether the `waf_type` it yields is sound, since the learner keys per-WAF on it.

## MAJOR CORROBORATION — the fingerprinter CANNOT misread Tor-403s as a WAF (egress-cascade refuted a third time)
- The fingerprinter fires ~40-50 **direct `requests` probes** (payload/header/path/method/rate-limit/timing). Under stealth/Tor, **recon skips the entire probe** (`recon_agent.py:711-719`): `_tor_active` ⇒ it substitutes an empty `{"confidence": 0.0, "skipped_for_stealth": True}` fingerprint and lets WAF detection come only from the proxied tool path. Rationale in the comment: a Windows-side `requests` session can't be cleanly routed through WSL's Tor, so probing would **leak the real IP** — so it doesn't probe at all.
- **Therefore, under Tor the fingerprinter never runs, `confidence` stays 0.0, and `waf_present` stays False** — it is *physically incapable* of turning Tor exit-node 403s into a WAF assertion. This is the third independent refutation of the "Tor-403 → misread WAF → evasion loops" cascade (Round 14 recon baseline, Round 20 reactive ghost engine, now the fingerprinter is bypassed entirely under Tor).
- **And the confidence gate is genuinely good (l.571-594):** WAF presence requires a **strong** signal — `payload_detection` OR `header_signature`. Path-level 403s (`/admin`→403 is normal server behavior), timing noise, and method blocking are capped at `min(raw, 0.2)` — **below the 0.5 assertion threshold**. The docstring explicitly documents this as the fix for path-403 false positives. This is the correctly-built anti-false-positive control and it is load-bearing.

## WAFFP-PLANNING-OVERRIDE (MED-HIGH) — an LLM planning recommendation manufactures `confidence: 0.8`, bypassing the strong-signal gate
- `recon_agent.py:736-747`: if the planning phase persisted a `waf_bypass_analysis` with a `recommended_bypass`, **and** the real behavioral fingerprint's confidence is `<= 0.3` (i.e. no strong signal — *exactly the case the gate is designed to reject*), recon **synthesizes a fake fingerprint** with a **hardcoded `"confidence": 0.8`** and `detected_patterns = [recommended_bypass]`.
- Then l.765 (`confidence >= 0.5`) passes on that fabricated 0.8 → `waf_present = True`, a `waf_detected` finding is emitted (l.770-772), and the full evasion/orchestrator/learner stack engages.
- **Net:** the LLM planner's *opinion* that a bypass might be needed is laundered into `confidence 0.8` and overrides `_calculate_confidence`'s carefully-built strong-signal requirement. A target with **no measurable WAF behavior** can be marked `waf_present=True` purely because the planning LLM guessed one. This is a Pathology-1 instance (AI self-assessment treated as ground truth instead of being gated by evidence) crossed with a WAF false-positive: it re-opens, at the planning seam, exactly the false-WAF door the confidence gate closes at the probe seam. Every downstream consumer (evasion tactics, WafLearner tactic scoring, tool deprioritization in constraint_engine l.164) then runs against a WAF that may not exist.
- **Fix direction (diagnosis only):** the planning recommendation should *raise a hypothesis to be tested by a real probe*, not overwrite `confidence` with a literal. If the behavioral probe found no strong signal, a planner guess should cap at the same ≤0.2 the gate imposes — or trigger one confirmatory payload/header probe — never assert 0.8.

## WAFFP-TYPE-MISNOMER (LOW-MED) — `waf_type` is never set, so it's always a pattern name; that pattern name becomes the learner's `waf_id`
- The fingerprinter **never writes a `"waf_type"` key** anywhere (it emits `behaviors`, `detected_patterns`, `similar_to_known`, `evasion_candidates`, `confidence`). So `recon_agent.py:768` — `fingerprint.get("waf_type") or fingerprint.get("detected_patterns", ["unknown"])[0]` — **always falls through** to `detected_patterns[0]`, which is a *behavior-pattern* string like `"payload_detection"` / `"rate_limiting"` (or, under WAFFP-PLANNING-OVERRIDE, a bypass name), **never** a WAF product like "Cloudflare".
- That mislabeled `waf_type` is then used as the per-WAF identity `waf_id` in the learner writers (`base_agent.py:3042-3043` and `3247-3248`: `waf_fingerprint.get("waf_type")`). So Round 23's WAFLEARN-KEYSPLIT is compounded on the *other* axis too: not only is the **tactic** key mis-formed, the **waf_id** key is a pattern name rather than a WAF identity. Tactic effectiveness is therefore bucketed by "which pattern we happened to detect first," fragmenting learning further.
- **Fix direction:** derive `waf_type` from `similar_to_known` (which *does* carry the matched known-WAF name, e.g. `"cloudflare (match: 80%)"`) when present, else a stable `"unknown_<hash>"`, and use that — not a pattern name — as `waf_id`.

## Minor / low-severity
- **WAFFP-PROXY-UNUSED (LOW):** the class accepts a `proxies` map and `_create_session` (l.596-607) will honor it — a genuinely useful capability to probe *through* Tor without leaking IP. But the only caller (`recon_agent.py:723-724`) constructs `WafFingerprinter(time_budget=40.0, progress_cb=…)` with **no `proxies`**, and instead *skips* the probe under Tor. So the proxy plumbing is dead at the sole call-site. A cleaner design would pass the SOCKS proxy and actually probe through Tor (behavioral WAF detection under stealth) rather than going blind — but that's an enhancement, not a bug.
- **WAFFP-SIM-PARTIAL (LOW):** `_calculate_fingerprint_similarity` (l.548-569) only compares **bool** and **list** behavior values; int (`rate_limit_threshold`), float (`response_delay`), and str (`timing_pattern`) values are ignored in the numerator but **still counted in the denominator** (`total = max(len(b1), len(b2))`). So similarity is systematically deflated whenever numeric/str behaviors are present, making the `> 0.6` known-match threshold (l.543) hard to ever cross — known-WAF matching under-fires. Low impact (matching is advisory), but it's why `similar_to_known` is often empty and `match_confidence` defaults to 0.3.

## What the file gets RIGHT (keep)
- Strong-signal confidence gate (l.571-594) — the core anti-false-positive control.
- Hard wall-clock `time_budget` + progress heartbeat (l.112-126) with the two strong-signal tests ordered **first** (l.100-102) so a budget cutoff still keeps the decisive signals — thoughtful.
- Atomic `save_fingerprint` (temp + `os.replace`, l.654-661) — same corruption-class fix as waf_learner.
- Bounded class-level LRU cache (l.32-33, l.146-149) — avoids re-probing the same target.
- Connection-error ≠ block discipline (every probe treats `RequestException` as "not evidence," l.314/387 etc.) — avoids inflating WAF signals from transport failures.

**Net verdict:** `waf_fingerprinter.py` is a well-built behavioral prober with a correct evidence gate — and it is *not* a source of the false-WAF/egress problem (under Tor it doesn't even run). The two real defects live at the **recon seam that consumes it**: (1) the planning-override that manufactures 0.8 confidence past the gate, and (2) `waf_type` never being set so a pattern name masquerades as the WAF identity feeding the learner. Both are Pathology-1/Pathology-3 flavored (AI opinion un-gated; feedback keyed on a mislabeled identity) and both are fixable at the recon call-site without touching this file.

---

# Round 25 — `intelligence/strategic_advisor.py` (610 LOC, FULL read)

**Context already established (MD Rounds 5/DEEP-2, l.818):** the advisor is *not* write-only — `advise_tool_selection`/`advise_discovery_order` feed `_strategic_advice_note` → soft prompt text; `should_continue_trying` and `advise_waf_evasion` are the two genuinely **dead** methods. Wiring confirmed by this read: `record_tool_outcome` fires at base_agent l.3011 (success) / l.3063 (failure); `record_finding` at l.1387; `record_engagement_outcome` via engagement_recorder l.109. This round adds the **code-level defects** that only a line-by-line read surfaces — the persistence layer, not the wiring.

## ADVISOR-NONATOMIC-SAVE (MED-HIGH) — the one learning store that writes on every tool outcome is the one that was NOT given the atomic-write fix
- `_save_knowledge_base` (l.60-73) ends in `kb_file.write_text(json.dumps(...))` — a **direct truncate-and-rewrite**, no temp-file + `os.replace`, no lock.
- `_load_knowledge_base` (l.42-48) wraps the read in `try/except` that **swallows any decode error and returns a fresh empty KB** (l.50-58).
- **Combined failure mode:** if the process dies (or two agents write concurrently — base_agent runs multiple phase agents each holding their own `StrategicAdvisor`? no — one advisor per agent instance, but they share the same `strategic_knowledge.json` path via `INTEL_DIR`) mid-`write_text`, the file is left as truncated/invalid JSON → next load silently discards it → **all accumulated tool-effectiveness, tech-stack, WAF, and engagement-summary knowledge is wiped.** This is the **exact corruption class** that `waf_learner.py` (Round 23, l.449-465) and `waf_fingerprinter.py` (Round 24, l.654-661) document and fix with temp-file + `os.replace`. Strategic_advisor was **left unfixed** — and it is the *highest-frequency writer of the three*.
- **Write amplification:** `_save_knowledge_base()` rewrites the **entire** JSON on *every* `record_tool_outcome` (l.115), *every* `record_finding` (l.130), *every* `record_waf_detection` (l.145), *every* `record_tech_discovery` (l.163). Under the autonomous loop (hundreds of tool calls per engagement), that is hundreds of full-file serialize+rewrite cycles of a monotonically growing file — O(n²) IO over an engagement, each one a corruption window. This is a real contributor to the "engine goes sluggish / disk-bound over a long run" symptom, orthogonal to the AIBACKEND-SLEEP hang.
- **Fix direction:** same temp+`os.replace` the two learners already use, plus a dirty-flag/debounced batch write (persist every N records or at phase end) instead of per-record.

## ADVISOR-WAF-ALLTRUE (MED) — every WAF tactic "used" is recorded as `success: True` unconditionally
- `record_engagement_outcome` l.473-479: for every tactic in `waf_tactics_used`, it appends `{"tactic": …, "success": True, …}` — **hardcoded True**, with no check that the tactic actually beat the WAF.
- `record_waf_detection` l.140-144 records tactics as `"success": None` (attempted, unknown) and **nothing ever resolves None→real outcome**; the only writer that sets a boolean is the all-True path above.
- **Net:** the advisor's `waf_bypass_tactics[waf]` knowledge is "every tactic we ever tried worked." `advise_waf_evasion`'s `known_tactics` (l.257) and `_default_waf_advice` (l.571-581) therefore draw from an all-success list — pure Pathology 3 (poisoned feedback), and it mirrors WAFLEARN-KEYSPLIT/WafLearner's "header_mutation always wins." Two independent stores, same lie. (Mitigated only by `advise_waf_evasion` being dead — but `_default_waf_advice` still surfaces `known_tactics[0]` when AI is down, and the report at l.531-533 counts them as "known tactics.")

## ADVISOR-SIGNAL (confirms Pathology 2 reaches this store) — historical success rates are built on the structural success flag
- `record_tool_outcome` (l.90-97) increments `success`/`failure` straight from the `success: bool` param passed by base_agent — which is `ToolResult.success`, the **structural** signal (banner-nmap = success; Round 12 TOOLMGR-1, Round 18 result_contracts). So `tool_effectiveness[tool]` success rates, the `get_confidence_report` HIGH/MEDIUM/LOW ratings (l.514), and `should_continue_trying`'s `historical_success_rate` (l.394) are all computed over a corrupted success count. Even where the advisor's guidance *does* reach the LLM (the advice note), it is advising from poisoned history. This is the same Tier-1 root: fix the success signal upstream and this store becomes trustworthy for free.

## ADVISOR-STORE-FRAG (Pathology 4, learning layer) — a FOURTH parallel learning store, unreconciled
- `strategic_knowledge.json` holds `tool_effectiveness` and `waf_bypass_tactics` that **overlap** with `waf_learner`'s `waf_database.json` (`tactics`) and `tool_success_tracker`'s store — three+ learning stores, each keyed differently (advisor keys WAF by `waf_type.lower()`; waf_learner keys by the mis-derived `waf_type`=pattern-name from Round 24; tool_success_tracker by tool), all fed the same corrupted signal, **none reconciled at read time**. So "what has worked" has three disagreeing sources and no single authority. This is Pathology 4 (fragmentation) applied to the *learning* layer, not just the tool registries (guardian/cap_reg/tool_manager, Round 22). The knowledge fragmentation is as real as the registry fragmentation.

## Minor
- **ADVISOR-PIVOT-LOGIC (LOW, and the method is dead):** `should_continue_trying` l.402 compares a **failure** rate against `historical_success_rate * 2` — mixing two different metrics. With the no-history default `historical_success_rate = 0.5`, the threshold is `1.0`, so `failure_rate > 1.0` can never fire; the branch only ever triggers for tools with a *low* historical success rate. The intent (pivot when current failure exceeds historical failure by a margin) is muddled by comparing failure-vs-success and the `*2`. Since the method is never called, this is documentation-only, but if it is ever wired (as the MD's remediation §252 proposes), the comparison must be fixed first.
- **Defaultdict-on-reload (NON-bug, note):** the fresh KB uses `defaultdict(lambda: …)` for `tool_effectiveness` (l.51), but a reloaded KB (l.44) is a plain dict. All access sites guard with explicit `if key not in` (l.85, l.431) / `.get` (l.389), so no KeyError — but the `defaultdict` is decorative after the first save/reload.

## What it gets right (keep)
- `record_engagement_outcome` caps `engagement_summaries` to the last 100 (l.494-498) — bounded growth for that list (though the per-record write amplification above dwarfs it).
- The AI-advice methods degrade to knowledge-base-only fallbacks (`_default_*`) when `self.ai` is None — no hard dependency on the LLM.
- Zero-hardcoding intent is genuine: recommendations are drawn from accumulated history, not static rules (consistent with the design philosophy) — the problem is the *history* is poisoned and *non-durably persisted*, not the approach.

**Net verdict:** strategic_advisor's *design* is sound (learn-from-history, AI-with-fallback, zero-hardcoding) and its *guidance path* is wired (advice note). The full read exposes that its **persistence is fragile in the exact way two sibling learners already fixed** (non-atomic rewrite + swallowed-load = silent total wipe), its **WAF learning is hardcoded to all-success**, and it is a **fourth unreconciled learning store** over the same corrupted signal. None of these change the four-pathology diagnosis — they are additional, concrete instances of Pathology 2 (signal), 3 (poisoned/lost feedback), and 4 (fragmentation) in the strategic-learning layer. The single highest-value fix here is the atomic-write (stop the silent KB wipe); the rest ride on the Tier-1 success-signal fix.

---

# Round 26 — `intelligence/evidence_router.py` (444 LOC, FULL read)

**Why this file matters to the diagnosis:** it is the single largest block of **hardcoded exploitation knowledge** in the tree — a static `ROUTING_RULES` table (tech → fixed approaches/tools) plus a static `exploit_type → shell command` table. Given the user's "zero-hardcoding, AI-decides-everything" design, the key question is whether this hardcoding is *live* (a constraint on autonomy, like the guardian allowlist) or *neutralized*. **Answer: it is almost entirely dead or demoted — the engine has already reconciled it with the autonomous design.** Good news for the diagnosis; it is NOT a second guardian-style hardcoding violation.

## ROUTER-DEAD-EVIDENCEROUTER (dead code, ~264 LOC) — the entire `EvidenceRouter` class is never called
- `EvidenceRouter` (l.9-272) — the class holding the big `ROUTING_RULES` dict (l.16-175, 16 tech profiles × fixed approaches) plus `route_finding` / `route_findings_batch` / `get_recommended_commands` — has **no external caller anywhere in the codebase**. A repo-wide grep shows `EvidenceRouter` referenced only inside `evidence_router.py` itself; the only thing any agent imports is `TechStackRouter` (exploitation_agent l.847). So ~264 LOC — including the entire hardcoded IF-evidence-THEN-approach table — is **dead**. Add to the dead-code census (Pathology 4 / dead-code fragmentation): the earlier survey did not flag this because the file *is* imported (for the sibling class), so a module-level import census marks the whole file "live." Only a symbol-level check reveals half of it is dead.

## ROUTER-CMD-DEMOTED (partial dead code — but a CORRECT autonomy-preserving demotion) — even in the live class, the hardcoded commands are discarded
- `TechStackRouter.route_tech_stack` (l.282-355) is live, but it builds full nuclei/curl **command strings** (l.328, l.342, and the whole `_exploit_type_to_command` table l.357-444, ~90 LOC of hardcoded `curl .../etc/passwd` / Drupalgeddon / xmlrpc probes).
- At the **only** call-site — `exploitation_agent._gather_cve_seeds` (l.847-854) — the returned dicts keep only `tech` / `version` / `description` (→ `known_lead`) / `priority`. **The `command` field is thrown away.** The docstring (l.842-844) is explicit: *"intentionally a minor seed — the hypothesis engine is told not to let it dominate."*
- **Consequence & why it's GOOD:** the hardcoded exploit commands are **never executed**. The static CVE knowledge is demoted to a *description-only hint* that the hypothesis engine (Round 21) must turn into its own testable hypothesis and prove through the differential/evidence gate. This is exactly the right reconciliation of a hardcoded knowledge table with the autonomous, evidence-gated design — the opposite of the guardian allowlist (Round 22), which *actively blocks*. So the ~90 LOC of `_exploit_type_to_command` is dead *output* (maintenance burden, and misleading to a reader who assumes those commands run), but its presence does **not** violate the autonomy design or feed the false-positive path.
  - Corollary: the `{target}` / `{host}` placeholder-substitution question is moot — since the command strings are discarded, there is no malformed-command or unsubstituted-placeholder risk, and these aggressive `/etc/passwd`/traversal probes do **not** feed EXPLOIT-EMIT-1's substring→VULN_PROVEN path (Round 13), because they are never run.

## ROUTER-SUBSTR-LOOSE (LOW — and it's in the dead class) — first-match-wins loose substring routing
- `route_finding` (l.192-209) matches with `if route_key in finding_type or route_key in detail` — a loose substring test, first-match-wins over dict insertion order. `"php"` matches any detail containing the substring "php"; `"ftp"` matches "sftp"; `"jwt"`/`"cors"`/`"ssh"` are short enough to hit unintended substrings. It would misroute in real use — but since `EvidenceRouter` is dead (above), this never executes. Documentation-only; if `EvidenceRouter` is ever revived, tighten to word-boundary/token matching and order rules most-specific-first.

## What this file tells the diagnosis (the useful conclusion)
Unlike the guardian allowlist, the hardcoded knowledge here is **not a live constraint on the autonomous engine**: half the file is dead, and the live half's commands are deliberately downgraded to non-binding description seeds routed through the hypothesis→validate gate. So evidence_router.py is **evidence FOR** the claim that the engine's *exploitation* path leans genuinely autonomous (consistent with Round 13's finding that `_test_hypotheses` + the confirmed-vuln gate are the best-gated logic in the engine). The only actionable items are cleanup (delete/retire the dead `EvidenceRouter` class and the unused command-builder) — no behavioral fix, no autonomy-limiting hardcoding to remove. Net: ~264 LOC to the dead-code total, and a data-point that the hardcoding scattered through `intelligence/` is largely inert rather than actively wrong.

---

# Round 27 — `intelligence/rule_generator.py` (436 LOC, FULL read) + auto_upgrader apply path

**Why it matters:** `RuleGenerator` is the "system rewrites its own rules from what it learned" component — the scariest shape of Pathology 3 (permanent corrupted feedback). If generated rules (built from `insights` derived from the corrupted success signal) get merged into the **live** `rules/*.json` the engine loads at runtime, then one poisoned engagement permanently degrades all future runs. This round establishes whether that loop is actually **closed** (dangerous) or **open** (inert).

## RULEGEN-MERGE-DEAD (the key finding) — the rule-application half is never wired; the feedback loop is OPEN
- `merge_rules_to_system` (l.361-388), `_append_to_rule_file` (l.390-436), and `save_rules` (l.345-359) — the only methods that write into the **live** `rules/{exploitation,infrastructure,recon,weaponization}.json` — have **no caller anywhere** (repo-wide grep: `merge_rules_to_system`/`save_rules` appear only as their own definitions).
- The one live consumer, `auto_upgrader._apply_changes` (l.253-315, reached at engagement end via reporting_agent l.359-365 with `dry_run=False`), **generates** the rules_package (Phase 3, l.140) but only **persists it to a rollback-backup file** — `<backup_dir>/<engagement>/generated_rules.json` (l.282-286) — which nothing ever reads back. Its only *live* system mutation is `_update_tool_metrics` → `tool_metrics.json` (l.289/317); the rules themselves and the "recommendations" are explicitly saved as *advisory, not applied directly* (comment l.292).
- **Consequence — this MITIGATES Pathology 3 on the rule axis:** even though `generate_rules_from_insights` runs live on every engagement and is fed `insights` built from the corrupted signal (`findings_confirmed`, `tool_rates`), the resulting (potentially garbage) rules **cannot poison runtime** because they are never merged into the loaded rule set. The dangerous self-rewriting loop is *open* — it computes and discards. So the Pathology-3 concern for auto_upgrader narrows to the **`tool_metrics.json`** path (the only thing actually applied), not rule rewriting. That is a materially smaller blast radius than the MD's Pathology-3 framing implies for this component — worth recording as a scoping correction.
- **Downside:** it's wasted compute + a misleading log. Phase 3 prints `exploitation_rules: N / infrastructure_rules: M` (auto_upgrader l.142-146) as if the system learned new rules, when none are applied. A reader (or the user) watching the run would reasonably believe the engine is self-improving its rulebook; it is not.

## RULEGEN-APPEND-LATENT (latent HIGH — bites only if the dead merge is ever wired) — the merge code is unsafe as written
If someone wires `merge_rules_to_system` (a natural "finish the feature" step), three bugs fire immediately:
1. **No dedup, unbounded growth:** `_append_to_rule_file` does `updated_rules = existing_rules + rules` (l.426) with no identity check. Rule ids are deterministic (`exploit_{tech}_identified`, `waf_{waf_type}_handling`, …), so every re-run appends duplicates of the same ids forever — the rule files grow without bound and the engine sees N copies of each rule.
2. **Format flip dict→list corrupts the file:** it reads `content.get("rules", [])` when the existing file is a **dict** (l.418-419) but always writes back a **bare list** (l.429-430). So the first merge silently converts a `{"rules": [...]}` rule file into a top-level `[...]`, discarding any sibling keys and breaking any loader that expects the dict shape.
3. **Confidence gate is toothless:** generated infrastructure rules are minted at `confidence: 0.9` (l.143) and exploitation rules up to `0.95` (l.218), both above the `0.8` merge threshold (l.362/380) — so essentially everything generated would merge. Combined with the corrupted-signal-derived inputs, wiring this as-is would be the *actual* permanent-poisoning loop the MD warns about. **Recommendation: if the rule-merge feature is ever completed, add id-based dedup, preserve the dict shape, and gate on the Tier-1 validated success signal — not on these hardcoded 0.9/0.95 confidences.**

## Hardcoding note (consistent with evidence_router, and equally inert)
`_get_tech_specific_endpoints` (l.235-273), `_get_exploit_commands_for_tech` (l.275-294), and `_get_tools_for_vuln_type` (l.296-307) are static maps embedded into generated rules — more hardcoded knowledge in a "zero-hardcoding" engine. But like evidence_router (Round 26), it is **inert**: it only shapes rules that are never applied. Not an autonomy violation in effect; cleanup-only.

## Locking (minor)
`_append_to_rule_file` uses the same `os.mkdir(lock_dir)` advisory lock as waf_learner, but — unlike waf_learner (Round 23) — it does **not** ensure the parent dir exists first and does **not** use atomic temp+replace on the write (l.429-430 is a direct truncate-write). Same corruption-class exposure as ADVISOR-NONATOMIC-SAVE, but moot while the method is dead.

**Net verdict:** `rule_generator.py` is a **built-but-not-wired** self-improvement feature. The good news dominates: the rule-rewriting feedback loop is **open** (generate-and-discard), so a poisoned engagement cannot permanently corrupt the live rulebook through this path — a real narrowing of Pathology 3's scope (only `tool_metrics.json` is actually applied by auto_upgrader). The bad news is latent: the merge code, if ever completed, is unsafe (no dedup, dict→list corruption, toothless confidence gate) and *would* become the permanent-poisoning loop — so it must be fixed **before** being wired, not after. Add `merge_rules_to_system`/`_append_to_rule_file`/`save_rules` (~90 LOC) to the dead-code census, and flag the misleading "Phase 3: rules generated" log as reporting learning that doesn't happen.

---

# Round 28 — `intelligence/heuristic_optimizer.py` (380 LOC) + `intelligence/tool_success_tracker.py` (269 LOC), FULL reads + the auto_upgrade write/read path

**Headline (the most consequential correction of the full-read pass):** the **entire `auto_upgrader` self-improvement pipeline is an inert no-op** — it computes insights → optimizations → rules at every engagement end and writes them **only to rollback/backup files that nothing reads back**. Neither half closes a runtime feedback loop. This materially narrows Pathology 3: `auto_upgrader`, cited throughout the MD as a permanent-corrupted-feedback driver, does **not** actually feed anything into future runs.

## The proof — trace both live write paths to their (dead) ends

**Path A — generated rules (Round 27):** `auto_upgrader._apply_changes` never calls `RuleGenerator.merge_rules_to_system`; it writes the rules_package only to `<backup>/generated_rules.json`. Dead.

**Path B — tool metrics (this round):** `auto_upgrader._update_tool_metrics` (auto_upgrader l.317-321) writes to `os.path.join(dirname(__file__), "..", "tool_metrics.json")` = **`<repo_root>/tool_metrics.json`**, under the top-level key **`tool_effectiveness`**. The only live reader/decider is `ToolSuccessTracker`, constructed by base_agent (l.243-251) with `db_path = session.results_dir / "tool_metrics.json"` (falling back to `config_paths.TOOL_METRICS_FILE = RESULTS_DIR/tool_metrics.json`). So Path B is inert on **two independent axes**:
1. **Path mismatch:** writer = `<repo_root>/tool_metrics.json`; reader = `<session.results_dir>/tool_metrics.json`. Different files.
2. **Schema mismatch:** `ToolSuccessTracker` reads only `metrics["tool_stats"][tool][target_type]` (tool_success_tracker l.30, l.114-130). auto_upgrader writes `metrics["tool_effectiveness"][tool]` (auto_upgrader l.340-345) — a key the tracker's `_load_metrics` copies in but **no method ever reads**. Even if the paths matched, the tracker's decisions would ignore auto_upgrader's data.

**Path C — optimizations/recommendations:** `HeuristicOptimizer.apply_optimizations` (heuristic_optimizer l.329-362) writes **only** a rollback record (`optimization_<id>.json`), applying nothing to live config (its docstring: "saved for rollback capability"). And auto_upgrader doesn't even call it — it does its own inert `_update_tool_metrics`. The "recommendations" are explicitly `advisory, not applied directly` (auto_upgrader l.292).

**Conclusion:** every exit of the auto_upgrade pipeline lands in a backup/rollback artifact. Nothing it computes re-enters runtime. The `[AUTO-UPGRADE] Phase N` logs report a self-improvement that does not occur. **AUTOUPGRADE-FULLY-INERT** — add `heuristic_optimizer` (all of `optimize_from_insights`'s output is consumed only by the inert paths) + the tool-metrics writer to the "computes-but-discards" list, alongside Round 27's rule merger.

## What this does and does NOT do to Pathology 3
- **Removes** auto_upgrader/heuristic_optimizer/rule_generator as permanent-cross-run poisoning drivers. A single poisoned engagement **cannot** durably degrade future runs through auto_upgrade — the loop is open at every exit. This is the correct, narrower scope.
- **Leaves intact** the *genuinely live* learning loops, which remain fed by the corrupted signal: `ToolSuccessTracker.log_tool_result` (below), `WafLearner` (Round 23, mis-keyed), `StrategicAdvisor` (Round 25, non-atomic + all-true WAF), and `syntax_learner` (pending). These — not auto_upgrader — are where Pathology 3 actually lives.

## `tool_success_tracker.py` — the live recorder whose DECISIONS are dead (Pathology 1 shape)
- **Live record:** `log_tool_result` is called from base_agent l.1036 on every tool outcome. Its `success` is derived from `result.success` OR status ∈ {success, partial, partial_success} (base_agent l.1032-1034) — the **structural** signal (Pathology 2). So `tool_stats` success counts inherit the banner-nmap false-positive.
- **Dead decisions:** the *decision* methods — `rank_tools_for_target` (l.157), `get_tool_effectiveness` (l.102), `profile_target` (l.184) — have **no caller anywhere** (grep: only `log_tool_result` l.1036 and `summarize_effectiveness` l.5190 are wired). So the tracker's learning reaches the engine **only** as `summarize_effectiveness()` → a "TOOL EFFECTIVENESS (this session)" **prompt summary** (base_agent l.5190), advisory text the LLM may ignore. Same META-RC-0/Pathology-1 shape as strategic_advisor: self-knowledge is computed and *shown*, never *enforced* as a selection gate. The intelligent ranking (`rank_tools_for_target`, l.172-178 — success×0.6 + speed×0.3 + reliability×0.1) that *would* deterministically prefer proven tools is built and unused.
- **Two genuine STRENGTHS (credit where due):**
  1. **Atomic save** (l.55-58, temp + `.replace`) — the corruption-class fix strategic_advisor lacks (Round 25). Good.
  2. **WAF-block exclusion from the denominator** (l.132-135): `valid_runs = total - waf_blocked_count`, and `log_tool_result` buckets `waf_blocked` separately from `fail_count` (l.92-98). This is a real, deliberate **signal-cleaning** move — a WAF block is not counted as a tool failure, so the tracker's success_rate is *less* poisoned than the raw signal. It's the closest thing in the engine to the Tier-1 idea applied at a learning input. (It still trusts the structural `success` inside valid_runs, so it's partial — but it's the right instinct, and worth replicating.)
- **Minor hardcoding (inert):** `_get_recommended_tools_for_target` (l.234-251) and `_classify_target` (l.214-232) hold static per-target-type tool lists, but they feed only `profile_target`/`_get_recommended_tools_for_target` which are dead — so, like evidence_router/rule_generator, inert hardcoding, cleanup-only.
- **Cross-run persistence caveat:** the tracker's `db_path` is `session.results_dir/tool_metrics.json`. If `results_dir` is per-engagement (fresh per run), the tracker's learning is **within-run only** and does not accumulate across engagements — which, combined with the dead decision methods, means "learns which tools work across engagements" (the class docstring) is aspirational, not realized. (Flag to confirm when session/results_dir wiring is read.)

## `heuristic_optimizer.py` — pure compute, entirely downstream of the inert path
- `optimize_from_insights` (l.27-66) computes tool-priority adjustments (`new_priority = success_rate`, with duration penalties l.96-99), confidence bumps (occurrences≥3 → 0.95, l.140-141), timeout suggestions (1.5×observed +30s, l.178), and WAF tool-avoid lists — all from `insights` derived from the corrupted signal, and all consumed **only** by the inert Path B/C above. Its own `apply_optimizations` is backup-only (l.329-362). So the file is correct-enough heuristics wired to nothing live. **HEUR-INERT + HEUR-SIGNAL** (would matter *if* the optimizer output were ever applied to live tool ordering — it isn't).

**Net verdict:** these two files + auto_upgrader/rule_generator form a large "self-improvement" subsystem (~1,600 LOC across four files) that is **computed every engagement and discarded** — the single biggest *inert* mechanism in the tree. The correct diagnosis update: **strike auto_upgrader from Pathology 3's permanent-poisoning story** (its loop never closes), and concentrate the feedback-corruption fixes on the four *actually-live* learners (ToolSuccessTracker record-side, WafLearner, StrategicAdvisor, syntax_learner). The one bright spot is `ToolSuccessTracker`'s WAF-block-exclusion — the engine already contains a working template for cleaning a learning input of WAF noise; the Tier-1 fix should generalize that pattern (exclude non-evidence "successes"), and the dead `rank_tools_for_target` should be wired as the deterministic selection gate the prompt-summary currently only hints at.

---

# Round 29 — `intelligence/engagement_analyzer.py` (564 LOC, FULL read) + the learning-layer synthesis it enables

**Role:** this is the *source* of the `insights` object that feeds the entire auto_upgrade pipeline (Rounds 27-28). It reads the `tool_runs` SQL table + findings and computes tool effectiveness, WAF patterns, tech patterns, and optimization opportunities. Reading it (a) pins LEARN-1 at its origin and (b) lets me close the trace on where engagement learning actually goes.

## LEARN-1 confirmed at the origin — insights' tool effectiveness IS the structural signal
- `_analyze_tool_effectiveness` (l.104-142): `success = (status == "success")` (l.107), and `tool_rates[tool]["success_rate"]` is built from that boolean. `status` is the tool_manager classifier verdict — the exact signal TOOLMGR-1 (Round 12) showed marks banner-only nmap as `success`. So every `success_rate` in `insights` is corrupted at birth. Same in `_analyze_waf_patterns` (l.276) and the `_identify_optimizations`/`_discover_patterns` consumers (l.391/399/447/459). This is the definitive origin of LEARN-1: the "what worked" analysis is "what the classifier called success," not "what produced a real result."
- **But (Round 28) it goes nowhere runtime-affecting** — see the trace below. The poison is real; its blast radius is not.

## engagement_analyzer is the CORRECT reader of tool_runs — corroborates Round 23
- It reads run data via `self.store.get_tool_runs(engagement_id)` (l.97, l.268) — the **SQLite `tool_runs` table** — and keys WAF-evasion stats off `run.get("evasion_applied")` (l.274, l.283-285). This is exactly the store the WafLearner reporting path (Round 23, WAFLEARN-BATCH-DEAD) *should* have read but didn't (it read the never-populated `phase_data["tool_runs"]`). So engagement_analyzer is the reference implementation for "read tool runs correctly"; the fix for WAFLEARN-BATCH-DEAD is to make reporting_agent's WafLearner call read `get_tool_runs()` the same way this file does.

## Where the insights actually go (trace closed) — analysis-and-archive, not closed-loop
`analyze_engagement` has exactly two callers:
1. **`auto_upgrader.py:122`** → optimizer + rule_generator → **all outputs discarded to backup/rollback** (Round 28: AUTOUPGRADE-FULLY-INERT).
2. **`reporting_agent.py:185-188`** → `save_insights()` → writes `engagement_insights_<id>.json` to `LOCAL_RESULTS_DIR` (l.549-564) — a **report artifact on disk**. Nothing reads it back into a decision.
So the entire engagement-learning subsystem is **compute → discard-or-archive**. Its corrupted `success_rate` never re-enters a runtime tool-selection or gating decision. (The `.analyzer` references at base_agent:284 and recon_agent:1581 are a *different* class — `StructuredAnalyzer` — not this one; don't conflate.)

## Loose/fragile bits in the analysis (all inert, documentation-only)
- **WAF-type from substring (l.254-257):** any finding `detail` containing `"403"` sets `waf_type = "generic_waf"`; `"cloudflare"` anywhere sets cloudflare. A finding that merely mentions a 403 status manufactures a WAF type in the insights. Loose, but inert.
- **Difficulty from vuln count (l.338-346):** more `vulnerabilities_found` ⇒ "easy". Reasonable, inert.
- **Hardcoded tech keyword map (l.505-520) + tool list (l.534-542):** more embedded hardcoding in a "zero-hardcoding" engine — but for classification only, and inert. Cleanup-only, consistent with evidence_router/rule_generator.

## SYNTHESIS — the intelligence layer's learning is overwhelmingly INERT-or-ADVISORY, almost never ENFORCED
Putting Rounds 21-29 together, a clear structural pattern emerges across the whole `intelligence/` learning layer:

| Learner | Live? | How its learning reaches runtime | Enforced? |
|---|---|---|---|
| `hypothesis_engine` (R21) | **yes** | `validate_result` **gates** which findings become confirmed vulns | **ENFORCED** (the one real gate) |
| `EngagementAnalyzer` (R29) | yes (compute) | → auto_upgrader (inert) + saved report JSON | **no — discarded/archived** |
| `HeuristicOptimizer` (R28) | yes (compute) | → auto_upgrader inert paths | **no — inert** |
| `RuleGenerator` (R27) | yes (compute) | → backup file, never merged | **no — inert** |
| `ToolSuccessTracker` (R28) | yes (record) | → `summarize_effectiveness` **prompt text**; decision methods dead | advisory only |
| `StrategicAdvisor` (R25) | yes | → `_strategic_advice_note` **prompt text**; `should_continue_trying` dead | advisory only |
| `WafLearner` (R23) | yes (record) | mis-keyed writes; batch reader dead; consumers (`advise_waf_evasion`) dead | advisory/broken |

**The pattern:** exactly **one** learner (`hypothesis_engine`) *enforces* anything. Every other learning signal is either **thrown away** (analyzer/optimizer/rule_generator/auto_upgrader) or **injected as advisory prompt text the LLM may ignore** (tracker/advisor/waf_learner). This is META-RC-0 (Pathology 1: self-knowledge computed but applied as advice, not as a gate) generalized to the *entire intelligence layer* — the engine spends ~4,000+ LOC computing "what it learned" and then either discards it or hopes the model reads the note.

**Two consequences for the diagnosis:**
1. **Pathology 3 (permanent corrupted feedback) is smaller than the MD's original framing.** The scary "poisoned learning permanently degrades future runs" mostly cannot happen because the loops don't close — the corrupted `success_rate` is computed and discarded. The genuine cross-run poison is limited to `StrategicAdvisor`'s persisted `strategic_knowledge.json` (advisory) and `WafLearner`'s `waf_database.json` (mostly-dead consumers). The dominant real-time failure is **Pathology 1+2** (unenforced self-knowledge + the model reasoning from a poisoned *context window*), not durable state corruption.
2. **The highest-leverage fix is not "clean every learning store" — it's "make the ONE gate that works (hypothesis_engine) the template, and either wire or delete the advisory learners."** Wiring `ToolSuccessTracker.rank_tools_for_target` (a real, built ranking function) as a deterministic selection gate, and routing the ungated finding paths (EXPLOIT-EMIT-1 / TOOLMGR-1 / recon-SENSITIVE) through `validate_result`, converts the layer from "compute-and-hope" to "compute-and-enforce" — which is exactly the Tier-1 direction the MD already identifies, now with evidence that most of the learning code is *inert scaffolding* that can be wired-or-cut rather than carefully de-poisoned.

**Net verdict:** engagement_analyzer is competent analysis code fed a corrupted signal, feeding an inert/archival sink. It pins LEARN-1's origin, corroborates the WAFLEARN-BATCH-DEAD fix direction, and — most valuably — completes the evidence for the synthesis: the GhostWire "learning brain" is almost entirely **inert or advisory**, with a single enforcing gate (`hypothesis_engine`). Fix the success signal at the source (tool_manager classifier / result_contracts) and make learning *enforced* rather than *advisory*; do not spend effort de-poisoning stores whose outputs are discarded.

---

# Round 30 — `intelligence/reasoning_engine.py` (368 LOC, FULL read) + its four (all wired) call-sites

**Significance:** `ReasoningEngine` is the **most-wired intelligence module in the tree** — a genuinely *closed* learning loop, and (with `hypothesis_engine`) one of only two learners fed a **clean** signal. It is the counter-example that sharpens the Round 29 synthesis: even the engine's best-instrumented feedback is delivered as **advice, not enforcement**.

## Wiring (all four entry points are live — verified)
1. `analyze_tool_failure` → base_agent l.1075 (repair loop, fires once at the 3rd failure on a host).
2. `reason_about_findings` → recon_agent l.1595 (end of recon) → carried into exploitation as an "AI PRE-ANALYSIS" prompt section (exploitation l.1332-1346, l.1929-1932).
3. `assess_confidence_calibration` → exploitation_agent l.969 (feeds outcomes back).
4. `calibration_summary_for_prompt` → base_agent l.5377-5379 (injects the learned calibration note into `think()`).
So this is a real predict → act → measure → adjust cycle, and the calibration is **persisted across engagements** (`calibration_memory.json`, l.41-69) so it accumulates enough samples to matter.

## REASON-CALIBRATION-CLEAN (a genuine strength — and a correction to the "all learning is poisoned" prior)
- The outcome fed to `assess_confidence_calibration` is `{"success": (h.get("status") == "confirmed")}` (exploitation l.972). `h["status"] == "confirmed"` is the **validated hypothesis verdict** from `hypothesis_engine.validate_result` / `Evidence.is_proven` (Rounds 13/21) — the differential/evidence-gated signal, **NOT** the structural `ToolResult.success`.
- **Therefore ReasoningEngine's confidence calibration is fed a CLEAN signal.** It learns, per vuln class, "when I predicted X% success, how often did the claim actually get PROVEN," and surfaces mis-calibration back into the loop ("OVERCONFIDENT — predicted 70% but only 20% actually succeed; demand stronger proof", l.87-89). This is exactly the self-correcting mechanism the rest of the engine lacks, and it is **immune to Pathology 2** because it sits downstream of the one real gate. Credit: this is the second-best component after `hypothesis_engine`, and the two are coupled (calibration is only as good as the proof gate that scores it — keep the gate strong).
- Memory is bounded (last 50 samples/tactic, l.254-258) and the prompt note stays silent until ≥3 outcomes (l.80) — disciplined.

## REASON-ADVISORY (the Pathology-1 point — even the best feedback is not enforced)
Despite being well-instrumented and clean-signalled, **all three of ReasoningEngine's decision outputs are delivered as advisory prompt text, never as a deterministic gate:**
- **`analyze_tool_failure`** (the live counterpart to the *dead* `StrategicAdvisor.should_continue_trying`): its verdict — including `is_approach_wrong=true` with a `suggested_pivot` — is **appended to `self._recent_failures` as a string** (base_agent l.1083-1089: `"[ANALYSIS] … Flag changes will NOT help — PIVOT: …"`) which is injected into the next decision prompt. It does **not** deterministically abandon the tool, decrement a budget, or block further attempts. So the "stop retrying a dead end" signal exists and is computed by AI reasoning — but the LLM can still ignore the note and keep trying. The retry-forever loop is *mitigated by suggestion*, not *closed by a gate*.
- **`calibration_summary_for_prompt`** → prompt note (base_agent l.5379), not a hard confidence cap on tactics.
- **`reason_about_findings`** → an "AI PRE-ANALYSIS" section prepended to exploitation's prompt (exploitation l.1929-1932); exploitation still runs its own hypothesis loop, free to disregard it.

This is META-RC-0 exactly: the engine *reasons correctly about its own failure/confidence* and then *hopes the model acts on it*. ReasoningEngine is the strongest evidence for the Round 29 synthesis precisely because it is the case where the learning is genuinely good — closed loop, clean signal, cross-run memory — and **still** only advises. If even this feedback isn't enforced, the fix theme is confirmed: convert the highest-value advisory signals (pivot-on-dead-end, proven-calibration) into gates/budgets, not just prompt notes.

## Minor
- **REASON-TRIGGER-EXACT3 (LOW):** the failure analysis fires on `self._tool_failure_counts[fail_key] == 3` (base_agent l.1072) — an exact equality. If the counter ever advances past 3 without hitting it exactly (it increments by 1 so normally safe, but any reset/merge path could skip it), the analysis never runs; and it deliberately fires only once (no re-analysis at 6, 9…). Intentional "once at threshold," but `>=3` guarded by a per-key "analyzed" flag would be less brittle.
- **No-AI fallbacks are sound:** `_default_reasoning` (l.196-229) and the `analyze_tool_failure` heuristic (l.351-368) are reasonable substring fallbacks explicitly scoped to "AI unavailable," so the module never silently degrades to hardcoded signature matching when the AI could reason (docstring l.305-307). Consistent with the zero-hardcoding intent.

**Net verdict:** `ReasoningEngine` is the best-engineered feedback component in the engine after `hypothesis_engine` — fully wired, closed-loop, cross-run-persistent, and (crucially) fed the **clean, proof-gated** outcome signal rather than the corrupted structural one. Its single limitation is the pervasive one: its outputs are **advisory prompt injections, not enforcement**. So it does not by itself break the retry-forever / over-confidence loops — it *tells the model* to break them. This both (a) corrects any assumption that every learner is poisoned (this one isn't) and (b) cements the Tier-1/META-RC-0 fix direction: the missing piece across the whole layer is not better *learning* but *enforcement* — turn `analyze_tool_failure`'s "PIVOT" verdict and the proven-calibration into a deterministic loop-control gate/budget, reusing this module's already-correct, already-clean reasoning.

---

# Round 31 — `intelligence/target_profiler.py` (365 LOC) + `intelligence/self_awareness_module.py` (387 LOC), FULL reads

These two form the "target-comprehension + self-check" layer that sits between recon and exploitation. One (target_profiler) is advisory like the rest of the intelligence layer; the other (self_awareness) contains the **rare enforced anti-self-deception gate** — with a hole.

## `target_profiler.py` — competent evidence-driven synthesis, advisory output
- **What it does:** `build()` (l.65-91) gathers real evidence (headers, tech stack, endpoints, JS-bundle-mined API routes, ports, subdomains) and asks the AI to synthesize a `TargetModel` — target_type, value_map, and crucially `plausible_vuln_classes` vs `implausible_vuln_classes` ("a static SPA on a CDN has no server-side SQL/forms"). Honors zero-hardcoding: it does **not** encode "if SPA skip SQLi"; it gathers evidence and lets the AI reason (docstring l.10-14).
- **Genuine strengths:** JS-bundle route mining (`_extract_api_routes`, l.181-212) pulls the real SPA attack surface from script bundles, not just HTML; `_ensure_web_evidence` (l.93-116) self-fetches the homepage when recon left thin evidence so it never defaults to "unknown"; the synthesis prompt explicitly treats the **port scan as low-trust** ("a connect/Tor scan listing many ports is a SCAN ARTIFACT — do NOT conclude honeypot", l.254-258), consistent with recon's tripwire pruning (Round 14); safe `_fallback_model` on AI failure (l.311-329) never blocks recon.
- **Wiring / verdict:** built at recon end (recon_agent l.1898); consumed by exploitation via `TargetProfiler.format_for_prompt(model)` (exploitation_agent l.2016-2017), which renders "IMPOSSIBLE on this target — DO NOT ATTEMPT: …" as a **prompt section**. So the high-value "don't waste hours on impossible vuln classes" guidance is **advisory prompt text, not an enforced skip** — the exploitation agent can still attempt an implausible class. Same META-RC-0/Pathology-1 shape. (Note: `objective_ledger.py:77` also reads `implausible_vuln_classes` — checked when P4 objective_ledger is read; may add a second, possibly-gating consumer.) **TARGETPROFILER-ADVISORY (LOW-MED):** the strategic thesis is a suggestion, not a constraint. No own-logic defects; limited only by (a) advisory delivery and (b) the corrupted findings it reasons over.

## `self_awareness_module.py` — the RARE enforced gate (ops-sanity), plus a bypass hole
- **The recording side is advisory** (Pathology 1): `register_finding` (l.61-82, confidence-bucketing + naive `"not"`-substring contradiction detection l.97), `register_tool_outcome` (l.162-178, success = structural signal = Pathology 2), `register_assumption`/`validate_assumption`, and `get_confidence_report` → all feed only `get_current_knowledge_state()` / a prompt summary. Nice touch: the "empty = silent" fix (l.271-282) suppresses a misleading "0 facts / INSUFFICIENT_DATA" report in exploitation (each agent owns its own awareness instance; exploitation's is unpopulated) so the brain isn't nudged to over-cautiously re-recon.
- **SELFAWARE-OPSSANITY-ENFORCED (a genuine enforced gate — corrects "everything is advisory"):** `ops_sanity_check` (l.316-387) reality-checks exotic conclusions against ops context and returns `{plausible, confidence_cap, reasons}`. Its docstring claims "advisory, not a hard block" — **but the actual call-site enforces it.** `_ops_sanity_backstop` (base_agent l.1290-1298), invoked inside `add_finding`, does: `if not verdict["plausible"]: return "info", "[UNVERIFIED LEAD — ops-sanity: …] " + detail` (l.1280-1285). That is a **deterministic severity downgrade applied before the finding is stored** — a real gate, not a prompt note. It catches exactly the three self-fooling artifacts the MD cites: 1000+ "open" ports via proxy/connect-scan (l.343-349), a "bypass/vuln/confirmed" whose response is ≥97% identical to baseline (l.352-360), and host-level claims (crontab/root/foothold) when there's no target foothold (l.362-372). **This is one of the very few places self-knowledge is ENFORCED rather than merely shown** — it belongs in the "what's working" column with hypothesis_engine and the confirmed-vuln gate.
- **SELFAWARE-OPSSANITY-BYPASS (MED — connects to EXPLOIT-EMIT-1):** the backstop **early-returns and skips the check** when the detail already contains `"VULN_PROVEN"` or `"Proof["` (base_agent l.1265: `... or "VULN_PROVEN" in _d or "Proof[" in _d): return severity, detail`). The intent is "don't downgrade something already proven." But `VULN_PROVEN` is exactly the token **EXPLOIT-EMIT-1 (Round 13) fabricates from raw-output substrings without differential proof**, and recon's SENSITIVE regex mints similar critical tags. So a *fabricated* `VULN_PROVEN` **bypasses the one enforced anti-self-deception gate** — the ops-sanity net is blind precisely to the false positives that most need catching. This is the concrete coupling between two prior findings: EXPLOIT-EMIT-1 mints unproven `VULN_PROVEN` → that string exempts it from `_ops_sanity_backstop` → it advances to `confirmed_vulns` with neither the differential gate nor the ops-sanity gate ever applied. **Fix direction:** the exemption should key on a *trusted* proof marker (an `Evidence.is_proven()` object / hypothesis_engine verdict), not the literal substring `"VULN_PROVEN"` that any emitter can write.
- Minor: `confidence_cap` is computed as a graduated 0.1 ceiling but the caller only uses the binary `plausible` (cap ≥ 0.5), so the graduation is unused — a future enforced-cap could use the numeric value to *scale* severity instead of the all-or-nothing downgrade.

**Net verdict:** target_profiler is another competent, evidence-driven, zero-hardcoding module whose valuable strategic output (plausible/impossible vuln classes) is delivered as advice. self_awareness_module is more important: it houses the engine's **one enforced anti-self-deception gate** (`ops_sanity_check` → `add_finding` downgrade), which is genuinely load-bearing against the honeypot/baseline-identical/local-host self-fooling failures — **but** that gate is **exempted for `VULN_PROVEN`-tagged findings**, which is exactly the label EXPLOIT-EMIT-1 forges. So the highest-value fix here is not new logic but closing the bypass: make the ops-sanity exemption (and the confirmed-vuln gate) trust a *proof object*, not a *substring* — the same Tier-1 theme (route trust through `Evidence.is_proven`, never through emitter-writable text).

---

# Round 32 — `intelligence/syntax_learner.py` (201 LOC, FULL read)

**Why it matters:** this is one of the two "permanent learning loops" the MD's original synthesis (l.442) blames for making corruption permanent — RC-5: *"syntax_learner persists garbage (`nmap … --privileged`) across engagements."* The full read shows RC-5 has been **substantially remediated**; syntax_learner is now one of the **better-defended** learners, not a live poison source. Combined with Round 28 (auto_upgrader is INERT), **both** of the MD's "permanent corruption" loops are now downgraded.

## RC-5 is largely FIXED — three defenses added since the original diagnosis
1. **Input signal-cleaning (`_looks_like_failure`, l.131-134 + `_HARD_FAIL_MARKERS`, l.19-25):** `learn_syntax` refuses to store a command whose captured output contains any hard-failure marker — `"quitting"`, `"operation not permitted"`, `"requires root"`, `"usage:"`, `"invalid option"`, `"could not resolve"`, etc. — **even when the caller scored it a success** (l.143-149). The code comment (l.16-18) explicitly names the RC-5 case: *"nmap's raw-socket 'QUITTING!' once got stored as good syntax."* So the exact garbage RC-5 cited is now refused at the door. This is the **Tier-1 instinct applied at a learning input** (like tool_success_tracker's WAF-block exclusion, Round 28) — a defense-in-depth re-check that the structural success signal was real.
2. **Portable abstraction (`_abstract`/`_rehydrate`, l.96-129):** the stored pattern is target-/workdir-/wordlist-agnostic — the concrete host → `<TARGET>`, per-engagement `…/eng_<hex>/…` paths → `<WORKDIR>`, and any `-w <path>` wordlist → `{WORDLIST}` (l.81-94). This directly kills the documented "hallucinated `-l <file>` / stale-wordlist replay" failure: a pattern learned on one engagement can't re-suggest a dead host or a wordlist file that isn't installed on the next box. `_strip_workspace_wordlist` even **heals already-poisoned entries on reuse** (l.117-121). Genuinely good design.
3. **Atomic save (l.65-74):** temp-file + `.replace` — the corruption-class fix (unlike strategic_advisor, Round 25). Bounded to 10 patterns/tool (l.168-169). Host-agnostic dedup on the abstracted form (l.159-161).

## Residual gaps (small)
- **SYNTAXLEARN-BANNER-SLIP (LOW, Pathology 2 residue):** the hard-fail markers catch *explicit* failures but not the **banner-only nmap false-success** (TOOLMGR-1) — a host-discovery banner is real output with no failure marker, so a banner-only "success" command *shape* would still be learned. Low harm: what's stored is only the abstracted **shape** (a reference hint the AI re-points and adapts, l.175-201), not a result — a slightly-off shape is a weak nudge, not a poisoned fact. Still, closing the upstream signal (Tier-1) would remove even this.
- **Advisory delivery (appropriate here):** `get_syntax_hints` returns a "### LEARNED SYNTAX MEMORY (reference patterns — adapt…)" prompt section (wired at base_agent l.3795/3896/4153). This is Pathology-1 *shape* (advice, not enforcement) — but for command **syntax**, advisory is the *correct* design: you can't enforce a command shape, and the hint explicitly says "adapt the target/paths; only pass an input file if it exists right now." So this is advisory-by-necessity, not advisory-as-flaw.

## Consequence for the diagnosis — Pathology 3 shrinks again
The MD's one-line synthesis (l.442) rests on *"two 'learning' loops (syntax_learner, auto_upgrader) make the corruption permanent."* After the full reads:
- **auto_upgrader** → **INERT** (Round 28: computes and discards; no runtime loop closes).
- **syntax_learner** → **DEFENDED** (this round: input signal-cleaning + portable abstraction + atomic save; RC-5's exact garbage is refused).
So neither of the two named "permanent corruption" loops actually functions as originally described. **Pathology 3's "permanent, compounding corruption" is much smaller than framed** — the durable-poison surface is now essentially just `StrategicAdvisor`'s non-atomic `strategic_knowledge.json` (Round 25, advisory) and `WafLearner`'s mis-keyed `waf_database.json` (Round 23, mostly-dead consumers). This reinforces the Round 29 conclusion: the dominant real failure is **Pathology 1 (unenforced self-knowledge) + Pathology 2 (corrupted success signal poisoning the live *context window*)**, not durable state corruption. The engine's learners are, on the whole, either inert, advisory, or already defended — the fix energy belongs on **enforcement + the success signal at source**, not on de-poisoning persisted stores.

**Net verdict:** syntax_learner is a well-engineered, self-healing, signal-cleaning, atomically-persisted syntax memory — a model for how a learning input *should* be defended, and clear evidence that RC-5 was already addressed. Its only residue is the upstream banner-false-success (Tier-1 territory) and an advisory delivery that is correct for its purpose. Downgrade RC-5 from "permanent poison" to "remediated, minor residue."

---

# Round 33 — `structured_analyzer.py` (241) + `attack_frontier.py` (214) + `authz_tester.py` (179), FULL reads

Three recon→exploitation support modules. Two are competent-but-advisory; one (`authz_tester`) is a gold-standard proof-first capability that sharpens the "trust a proof object, not a substring" fix.

## `structured_analyzer.py` — AI-structures raw output; contains a LATENT better success signal
- `analyze_raw_output` (l.35-119) asks the AI to turn messy tool stdout into structured findings with per-finding `confidence`, `evidence` (quote from output), `severity`, `actionable`, and a `false_positives` list (WAF-block/404 page). `structure_recon_phase_output` (l.134-199) aggregates across recon tools; `_build_tactical_context` (l.201-241) derives attack vectors. Wired at recon_agent l.1581 → feeds `reason_about_findings` (Round 30) → advisory pre-analysis.
- **STRUCTURED-BETTER-SIGNAL (a useful observation, not a defect):** the AI here judges `"success": <did the tool successfully run and find anything?>` (l.75) **by reading the actual output**, and is told to mark WAF-block/error-page output low-confidence (l.98-99). This is a *semantically grounded* success/quality judgment — strictly closer to "real result" than the structural `ToolResult.success` classifier (TOOLMGR-1) that only checks exit-code + a signature list. So the engine **already computes a better success signal in this module** and then… doesn't use it to gate anything (it flows into the advisory reasoning pre-analysis). The Tier-1 fix could harvest exactly this: the structured-analysis `success`/`confidence`/`false_positives` are an available, output-grounded input to a real success gate. Fallback `_basic_structure` (l.121-132) uses the structural `bool(stdout and not error)` only when AI is down. No own-logic defect; non-deterministic and advisory.

## `attack_frontier.py` — a well-designed scored queue whose adaptive loop is NOT wired
- **Design (good):** an inspectable priority queue where each `FrontierItem` carries `attack_priority` (AI-set, or a structural `signal_score` fallback that deliberately makes **no** hardcoded "admin is valuable" judgment — l.29-45), `novelty` (untried-first), and `momentum` (boosted near productive work). `effective()` (l.62-67) is a deterministic rank. `pop`/`record_outcome`/`expand`/`_boost_neighbors` implement a self-expanding pop→act→learn loop that directly targets the documented "subdomains-discovered-then-forgotten" dead-priority bug.
- **FRONTIER-POPLOOP-DEAD (MED):** in the live agents, **only `push_many` + `snapshot_for_prompt(top=15)` are called** (exploitation_agent l.1960-1997). `pop()`, `record_outcome()`, `expand()`, `boost_for_objective()`, `_boost_neighbors()` — the entire **adaptive** half — are exercised **only in tests**, never by an agent (repo grep: `.pop()`/`record_outcome` appear only in `tests/`). So the frontier degrades to a **one-shot static ranked list injected as prompt text**: the AI is shown "work these top-down," but nothing pops items to drive iteration and no momentum/novelty is ever learned (novelty stays 1.0, momentum stays 0). The "discovered-then-forgotten" fix is therefore only **half-realized** — items are scored and displayed once, but the queue never actually sequences the work or rewards productive neighborhoods. This is the same META-RC-0 pattern one level up: a genuine enforcement *mechanism* exists (a real work queue) but is consumed *advisorily* (snapshot into a prompt). **Fix direction:** drive the exploitation/recon iteration off `pop()` + `record_outcome()` instead of dumping a snapshot — that turns the frontier from a suggestion into the loop's actual spine (its stated purpose).

## `authz_tester.py` — GOLD-STANDARD differential proof, correctly wired (the model to copy)
- **AUTHZ-WIRED-CLEAN (strength):** IDOR/BOLA are tested as **inherent differentials** — `test_bola` (l.78-116): control = authenticated owner fetches the object; test = a *different* identity fetches the SAME URL; confirmed only if the other identity gets the **same protected object** (2xx, body ≥40B, `sim ≥ 0.9`). `test_idor` (l.120-162): confirmed only if a neighbour id returns a **different valid** object (`sim < 0.97`). A lone 200 can **never** confirm (docstring l.5-8). `proof_type="differential"` and `severity="high"` are set **only** on a proven delta.
- **Wired and emits real proof:** exploitation_agent l.1019-1037 runs `test_bola`/`test_idor` per route and, on `res.confirmed`, builds a real `Evidence(proof_type="differential", differential=…)` object, `_persist_evidence`s it, and emits `VULN_PROVEN [BOLA/IDOR] … Proof[differential]: …`. This VULN_PROVEN is **legitimate** — backed by a genuine control/test differential.
- **Why this matters for the diagnosis (sharpens SELFAWARE-OPSSANITY-BYPASS / EXPLOIT-EMIT-1):** the *same* `VULN_PROVEN` token is written by BOTH (a) this correct, differential-backed path and (b) EXPLOIT-EMIT-1's substring fabrication (Round 13) and cannot be told apart downstream. That is precisely why the ops-sanity gate exemption keyed on the literal `"VULN_PROVEN"` substring (Round 31) is unsafe, and why the confirmed-vuln state should key on the presence of a valid `Evidence.is_proven()` object (which AuthzTester produces and EXPLOIT-EMIT-1 does not). AuthzTester is the **template**: every "confirmed" path should carry an Evidence object like this, and every consumer (ops-sanity, confirmed-vuln gate) should trust the object, not the string. Immune to Pathology 2 by construction — no own-logic defect.

**Net verdict:** `structured_analyzer` quietly computes a better-than-structural success signal that the engine leaves unused (a Tier-1 opportunity). `attack_frontier` is a real work-queue reduced to an advisory prompt snapshot — its adaptive loop is dead (FRONTIER-POPLOOP-DEAD), a concrete instance of "enforcement mechanism built, consumed advisorily." `authz_tester` is the one unambiguously correct, wired, proof-first capability in the exploitation set — the concrete template for the Tier-1/"trust the Evidence object" fix, and the clean counter-example to EXPLOIT-EMIT-1's forged VULN_PROVEN. None changes the four-pathology model; together they reinforce it: good mechanisms exist, but are consumed as advice (frontier), left unused (structured signal), or bypassed by substring-trust (authz's legit proof vs the forged one).

---

# Round 34 — `waf_bypass/origin_discovery.py` (496) + `cache_deception.py` (186) + `tls_fingerprint.py` (143), FULL reads — **Priority 2 COMPLETE**

The three "bypass-around" WAF modules. All wired; two are clean proof-first/graceful-degrade capabilities, one (origin_discovery) is functional-but-partially-stubbed (expands the existing ORIGIN-1 note).

## `origin_discovery.py` — real and wired, but ~4/9 techniques are stubs (expands ORIGIN-1)
- **Wired at multiple sites:** recon_agent l.1484-1485 (`discover_origin_ips(host, aggressive=False)`) and waf_bypass_orchestrator l.56/110/512/520 (discover + `test_origin_connection`). So origin-IP-behind-CDN discovery genuinely runs.
- **LIVE techniques (functional):** current DNS (`_resolve_dns`, getaddrinfo A/AAAA), SSL-cert SAN IP extraction (l.158-184), subdomain enumeration (l.186-212, a standard common-subs list), reverse DNS (l.235-262), MX-record IPs (l.286-306, needs `dnspython`), port testing (l.404-425), and a real direct `test_origin_connection` (l.427-496, connects to the candidate origin with the correct Host header and reads response headers to judge `bypass_viable`).
- **ORIGIN-STUBS (INFO, expands MD ORIGIN-1):** four advertised techniques are **stubs that return nothing**: `_get_historical_dns` (l.138-156, "would query SecurityTrails" → `pass`), `_get_asn_ips` (l.214-233, placeholder), `_detect_cloud_metadata` (l.264-284, only returns the static `169.254.169.254`/`metadata.google.internal`; the ASN-confirm is a TODO), `_probe_common_internal_ips` (l.308-332, only the `.1` gateway of each RFC1918 range; sweep/timing/DNS-rebind are TODO). So the "9 techniques" advertised is really ~5 live.
- **ORIGIN-CONF-DENOM (LOW):** `confidence = min(len(techniques_used)/9.0, 1.0)` (l.109) divides by 9, but techniques 2/5/7/9 are "Removed (stub)" and never append, so realistic max ≈ 5/9 ≈ 0.55 — **confidence is systematically understated** even when every working technique fires. Cosmetic (confidence isn't a gate here), but misleading.
- **ORIGIN-CDN-LIST (LOW):** `_rank_origin_candidates` scores `not_cdn` against a **3-entry** hardcoded CDN CIDR list (l.355-359, only Cloudflare 104.16/12 + two CloudFront ranges), so most real CDN IPs are scored "not_cdn" and over-ranked as origin candidates. Minor ranking noise, not a correctness bug (the downstream `test_origin_connection` still has to actually reach the IP).
- **Verdict:** substantive, correctly-structured, wired origin discovery with unfinished enhancement stubs — a *capability-completeness* gap, not a root-cause driver. Matches and extends ORIGIN-1.

## `cache_deception.py` — GOLD-STANDARD differential probe, non-destructive, wired
- **Wired:** exploitation_agent l.1110-1134 (`CacheDeceptionProbe().probe(...)` → emits findings). 
- **Proof-first by construction (like authz_tester, Round 33):** `probe_deception` (l.75-130) confirms only when a static-suffixed URL (`/{rand}.css`, `;{rand}.css`, `/..%2f{rand}.css`) returns the **same dynamic content** as the control (`sim ≥ 0.85`, 200, ≥40B) **AND** the response is now cacheable/cached (`_looks_cached`). `probe_poisoning` (l.134-166) confirms only when a **unique benign canary** in an unkeyed header (`X-Forwarded-Host`, etc.) is **reflected into a cacheable response**. A lone 200 can never confirm. Non-destructive within ROE (docstring l.16-19): unique canary, never persists a malicious value, never serves a poisoned entry to real users. Degrades to neutral if `requests` is absent.
- **Verdict:** no defect. Another example of the differential/evidence pattern done right — its "high" findings are backed by an observable control/test delta, so they are trustworthy (unlike EXPLOIT-EMIT-1). Immune to Pathology 2 by construction.

## `tls_fingerprint.py` — clean browser-JA3 impersonation, graceful no-op, wired
- **Wired:** waf_ghost_engine l.161-164 (`TlsFingerprintEvasion().rewrite_curl_for_impersonation(...)` inside the ghost-engine transform — the TLS/JA3 leg noted in Round 20).
- **Design:** presents a real Chrome/Firefox/Safari TLS+HTTP/2 fingerprint via `curl_cffi` (in-process) or by rewriting a `curl` command onto a `curl-impersonate` binary (l.87-103, swaps only the leading `curl` token, preserves flags/target). If no impersonation tooling is installed, `available` is False and **every method is a safe no-op** (returns the input unchanged) — "can only ever help" (docstring l.17-19). No hardcoded target logic; browser profiles are client fingerprints.
- **Verdict:** no defect. Effectiveness gated only on provisioning (`curl_cffi`/`curl-impersonate` present) — consistent with the tool-installation dependency theme, but it fails safe. `verify=False` (l.126) is intentional for a probing tool (already noted in the MD as not-a-defect).

## Priority-2 status
**Priority 2 is now COMPLETE** — every WAF-cluster + wired-intelligence file has been fully read (Rounds 20-34): waf_ghost_engine, hypothesis_engine, waf_learner, waf_fingerprinter, strategic_advisor, evidence_router, rule_generator, heuristic_optimizer, tool_success_tracker, engagement_analyzer, reasoning_engine, target_profiler, self_awareness_module, syntax_learner, structured_analyzer, attack_frontier, authz_tester, origin_discovery, cache_deception, tls_fingerprint. **Recurring pattern across the whole intelligence/WAF layer:** the *detection/proof* modules that use a control→test **differential** (hypothesis_engine, authz_tester, cache_deception, the ghost engine's reactive gate, ops_sanity) are correct and often immune to Pathology 2 by construction; the *learning* modules are mostly inert (auto_upgrader chain) or advisory (advisor, tracker, frontier snapshot, syntax hints); and the few genuine enforcement points (confirmed-vuln gate, ops-sanity downgrade) are undermined only by **substring-trust** (`VULN_PROVEN` text vs a real `Evidence` object). Net: the engine's *building blocks* for correct, evidence-gated behavior already exist and are well-built — the disease is that trust is routed through emitter-writable text and advisory prompts instead of through the proof objects and enforcement gates the codebase already contains. Next: Priority 3 (agents + core plumbing).

---

# Round 35 — the orchestrator-wired "exploit" trio: `credential_finder.py` (135) + `request_smuggler.py` (379) + `oob_exfil_engine.py` (377), FULL reads

These three are instantiated by `waf_bypass_orchestrator` (l.51-59) and **executed** by its `_execute_credential_bypass` / `_execute_smuggling_bypass` / `_execute_oob_bypass` paths (l.533-626). Reading them in full reveals they are the **weak side** of the WAF-bypass capability set — generators / stubs / non-differential detectors — in sharp contrast to the gold-standard differential siblings (authz_tester, cache_deception, origin's real connection test). Their outputs' trustworthiness depends entirely on the orchestrator's `_validate_bypass_differential` gate (WAF-ORCH) catching them.

## `credential_finder.py` — half-implemented: finds header NAMES, never VALUES
- `find_bypass_credentials` (l.23-53) scans findings for bypass-header **names** (`X-WAF-Key`, `X-Origin-Secret`, …) and records `{type, name, source}` — but the "extract value" step is a **no-op comment** ("simple regex simulation", l.41); it never captures a value.
- `create_bypass_request` (l.55-102, "FIX #3.1") correctly **refuses** a credential with no value (raises `ValueError`). Since step 1 never produces a value, **every discovered credential raises on use** → `_execute_credential_bypass` (orchestrator l.533-559) can find names but can never actually send a bypass request with a real key.
- **CREDFINDER-NO-VALUE (LOW):** the capability is non-functional end-to-end (flags "response mentioned X-WAF-Key" but cannot weaponize it). Fails safe (raises rather than sending a placeholder), so it produces no false positives — it produces *nothing usable*. Cleanup/complete-or-cut.

## `request_smuggler.py` — executes, but "detection" is a non-differential guess (false-positive prone)
- **SMUGGLER-FALSEPOS (MED — the real defect):** `execute_smuggling_attack` (l.291-361) judges success as *`response exists AND "403" not in response AND "429" not in response`* (l.353-356). That is **not** smuggling detection — it's "did we get any non-blocked response," which nearly every request yields. Real request-smuggling detection requires a **desync differential** (timing, or the smuggled request affecting a *subsequent* request). The module even declares a `smuggled_request_processed` field (l.309) and **never sets it**. So `_detect_cl_te`/`_detect_te_cl`/`_detect_te_te` return "vulnerable" on essentially any responsive non-403 target → high false-positive rate. This is the exact opposite of its siblings' control→test discipline, and it's the input to the orchestrator's `_execute_smuggling_bypass` (l.561-606). Mitigation: the orchestrator gates smuggling behind an operator-authorization HITL note (l.469) and (should) route the result through `_validate_bypass_differential` — so the false "bypassed_waf" is only as contained as that gate.
- **SMUGGLER-HTTP2-STUB (LOW):** `_detect_http2_smuggling` always returns `None` (l.216-223, "not yet implemented"), yet `confidence = len(vulnerable_to)/4.0` (l.68) counts it in the denominator → confidence understated. `payload_template` strings in the detect methods (l.97-109 etc.) are decorative — only `create_smuggling_payload`'s dynamically-built output is actually sent.

## `oob_exfil_engine.py` — a payload CATALOG with no execution and no verification
- **OOB-STUB (MED):** `discover_oob_vectors` (l.29-75) assembles a static dictionary of DNS/SSRF/XXE/SSI/mail/LDAP payload templates, each hardcoded with `"waf_bypassed": True` and `"direct_waf_contact": False` (l.87-88) — it **asserts bypass success without sending, testing, or verifying anything**. `monitor_oob_channel` (l.352-377) is a **stub**: `exfil_successful` is hardcoded `False`, `data_received` always `[]` — it does not connect to any interactsh/Burp collaborator. The default `collaborator_domain = "collaborator.oob"` (l.26) is a **placeholder**, not a real OOB server, and nothing injects a live one.
- **Consequence:** `_execute_oob_bypass` (orchestrator l.608-626) calls `discover_oob_vectors` + `create_exfil_payload` and sets `bypass_url = "via OOB channel: collaborator.oob"` — i.e. it **reports an OOB bypass via a non-existent collaborator, with no callback verification** (`monitor_oob_channel` isn't even called). So an "OOB bypass" can be asserted with zero evidence that any callback fired. This is the same class as EXPLOIT-EMIT-1 (assert-without-proof), one layer down, and depends entirely on `_validate_bypass_differential` to not promote it. The payload catalog itself is real/useful *as payloads* — the engine around it (execution + channel monitoring) is unbuilt.

## Cross-cutting verdict — the "Layer 3/5/7 WAF bypass" capabilities are substantially aspirational
The WAF-bypass suite splits cleanly in two:
- **Correct, differential, verifying:** `origin_discovery` (real direct-connection test), `cache_deception` (control→cached-test), `authz_tester` (cross-identity differential), the ghost engine's reactive gate — these *prove* what they claim.
- **Generators / stubs / non-differential (this round):** `credential_finder` (no values), `request_smuggler` (non-differential "detection"), `oob_exfil_engine` (catalog + stubbed monitoring, hardcoded success). These *assert* bypass without verifying it.
The README/architecture advertises all of them equally, but only the first group is trustworthy. **The orchestrator's `_validate_bypass_differential` (WAF-ORCH) is therefore load-bearing precisely for this weak group** — it is the single gate standing between "smuggler/OOB said bypassed" and a confirmed finding. Two fixes follow: (1) make smuggler/OOB **verify** (desync differential for smuggling; real interactsh callback for OOB) or clearly demote their output to *unproven leads*; (2) ensure every `_execute_*_bypass` result is routed through `_validate_bypass_differential` before it can become a confirmed WAF-bypass finding — same Tier-1 theme (assert nothing without a proof object). None of these change the four-pathology model; they are additional Pathology-2 loci (assert-without-proof) confined to the WAF-bypass execution layer and (partly) contained by the orchestrator's differential gate.

**Priority-3 (WAF-bypass exploit trio) done.** These were the last 🟡 items flagged "WIRED via orchestrator." Next P3: agents (weaponization, persistence, planning/objectives/specialists/mentor) + core plumbing (target_graph, tool_installer, ip_rotator, ssh_executor, vps_optimizer, target_context, app_session, tripwire_detector, session/config).

---

# Round 36 — `agents/weaponization_agent.py` (633 LOC, FULL read)

Phase-4 PoC synthesis + execution. Mostly well-guarded (good AI-PoC prompt, solid FP filter, guardian pre-exec validation, prior-FP-aware finding filter), with two real Pathology-2 loci: a substring-proof branch that skips the FP guard, and a "nuclei match = confirmed" fallback that promotes findings whose active PoC *failed*.

## Strengths (keep)
- **The AI-PoC prompt (l.381-412) pushes toward evidence proof:** per-vuln-class specific indicators (SQLi→"SQL syntax error"/time-delay, LFI→/etc/passwd content, RCE→uid=/gid=), explicit "NEVER check homepage HTML as proof," "compare against baseline — if normal target returns same, it's a FP," "use strict `assert` statements," and a `VULN_PROVEN:`/`NOT_PROVEN:` output protocol. This is the right instruction set — it asks the model to *prove*, not assert.
- **`_is_false_positive` (l.53-96)** is a real filter: WAF-block page patterns, framework error pages (Symfony/Django/Express) when the finding claims sql/rce/lfi/xxe, an HTML-drop guard for data/API vulns that requires a genuine proof marker (`root:x:0`/`uid=0`/`syntax error`/`mysql_fetch`) before accepting an HTML body, and a baseline-size match check.
- **Finding filter (l.151-202)** is thoughtful and *prior-FP-aware*: weaponizable-type gate, Nikto-noise skip, `web_vulnerability` requires high/crit (or medium + exploit keyword), `ai_dynamic_exploit` skips homepage-HTML DB records, and `http_request_smuggling` explicitly skips the old `"downgrade"`/wp-content false positives — i.e. it already knows SMUGGLER-FALSEPOS (Round 35) produced junk and filters it here.
- **Guardian pre-execution validation** of the generated PoC code (l.421-431, `validation.validate_python`) — blocks/repairs sketchy PoCs before running.
- **BUG-17 fix (l.455-457):** only stdout is checked for `VULN_PROVEN` (stderr is infra noise) — avoids rejecting a valid proof because of a stderr warning.

## WEAPON-SUBSTR-PROOF (LOW-MED) — two proof branches skip the FP guard
`_synthesize_and_execute_poc` accepts proof three ways (l.470-492):
- **`VULN_PROVEN:` branch (l.470-486):** correct — runs `_is_false_positive` + a length check before accepting.
- **`elif "root:x:0" in proof_stdout` (l.487-489)** and **`elif "SQL syntax" in proof_stdout` (l.490-492):** mark `vuln_proven = True` from a **raw substring** of the PoC stdout, **bypassing `_is_false_positive` entirely** (the FP filter only runs in the first branch). So if a PoC echoes its payload, prints a reflected `root:x:0` string, or surfaces "SQL syntax" from an unrelated error page, it is accepted as proven with no FP check. Same substring-trust class as EXPLOIT-EMIT-1 (Round 13), narrower blast radius (the PoC is a targeted script and these tokens are fairly specific), but it still emits an `add_finding("proven_…", "VULN_PROVEN: …")` — which then (a) advances the confirmed-vuln gate and (b) is exempt from the ops-sanity backstop (Round 31, SELFAWARE-OPSSANITY-BYPASS). **Fix:** route these two branches through `_is_false_positive` too, or better, require the PoC's `VULN_PROVEN:` protocol (which the prompt already mandates) rather than sniffing raw substrings.

## WEAPON-NUCLEI-CONFIRM (MED) — a finding whose active PoC FAILED is still promoted to "confirmed"
When the PoC does **not** prove (l.523-550): if the finding's type is `"vulnerability"` and severity ∈ {critical, high, medium}, the agent **still** appends it to `results["proven_exploits"]` as `"[Nuclei Template Confirmed]"` and emits an `add_finding("nuclei_confirmed", …)` (l.536-550), logging "stored as confirmed finding." So an active-exploitation **failure** is converted into a **confirmed** exploit purely because a nuclei template matched earlier. Nuclei matches are exactly the kind of signal that can be a version-based/heuristic hit without demonstrated impact, and here they are promoted to "confirmed" with **no differential proof and despite the PoC failing**. This is a genuine Pathology-2 locus: it manufactures confirmation from a prior tool's say-so. It is *defensible* as "report the nuclei finding so it isn't lost," but the label should be **"unconfirmed nuclei lead,"** not "confirmed/proven_exploit." **Fix:** keep the finding for the report, but tag it `nuclei_lead`/`info` severity-preserving and do NOT add it to `proven_exploits` or emit `nuclei_confirmed` — confirmation must come from the differential/PoC, not the scanner.

## Minor
- `_generate_standard_payloads` (l.552-633): EICAR file + path-probing the discovered gobuster paths. Reasonable; skips `/~` CDN wildcards and 301/302 redirects (prior-FP awareness again). Path probes emit only `low` findings. Fine.
- Severity assignment by vuln-type keyword (l.497-514) is reasonable and caps sensibly (open_redirect→low, missing_header→info).

**Net verdict:** weaponization_agent is one of the *better-guarded* emit paths — its AI-PoC prompt demands real proof, its FP filter is substantive, and it's visibly scarred by (and defends against) prior false positives. Its two defects are the familiar Pathology-2 shape: (1) two substring branches that skip the FP guard and mint a `VULN_PROVEN` token, and (2) a nuclei-match fallback that promotes PoC-failed findings to "confirmed." Both feed the same downstream trust problem (VULN_PROVEN substring / unproven "confirmed" advancing the kill-chain and dodging ops-sanity). Fix = same Tier-1 theme: accept confirmation only from a real proof (the PoC's VULN_PROVEN protocol + FP filter, or an Evidence object), never from a raw substring or a prior scanner's match.

---

# Round 37 — the small agents: `persistence_agent` (225) · `planning_agent` (101) · `objectives_agent` (91) · `specialists` (129) · `mentor_agent` (58) · `validation_agent` (144), FULL reads

Six phase/utility agents. Most are clean; the load-bearing items are persistence_agent's **enforced foothold gate** (a rare deterministic self-deception guard) with one residual, and validation_agent's command-hardening.

## `persistence_agent.py` — a second ENFORCED anti-self-deception gate, with a residual
- **PERSIST-FOOTHOLD-GATE (STRENGTH, enforced):** `_test_persistence_vectors` (l.37-60) **hard-skips** all host-level persistence probes (`crontab -l`, `test -w ~/.ssh/authorized_keys`, `test -w /var/www/html`) unless `_has_target_foothold()` (l.13-35) finds a real foothold finding (`valid_credential`/`shell_access`/`rce_confirmed`, or a `confirmed_vulnerability` whose detail carries RCE markers `uid=`/`/bin/sh`/reverse shell). Without it, it records a `persistence_info` "theoretical only, NOT tested" note and returns. This is a **deterministic gate** (not advisory) against the exact self-fooling artifact ops-sanity also targets ("`crontab -l` on the scanner box → 'target has crontab access'"). Together with ops-sanity (Round 31) and the confirmed-vuln gate, it's one of the few genuinely enforced checks.
- **PERSIST-LOCAL-EXEC (MED, residual — the agent is self-aware of it):** once the gate passes, the probes still run via `safe_run_tool(..., target)`, which executes on the **WSL/VPS scanner node, not the target** — there is no target-bound executor. The code says so explicitly: l.183-189 blocks credential-based target SSH "to prevent scanner-box pollution / self-infection" and marks `TargetWSLExecutor` as FUTURE. So if a foothold finding exists but was itself mis-emitted (e.g. a false `confirmed_vulnerability` with an RCE marker — cf. EXPLOIT-EMIT-1), the crontab/ssh/web-root probes (l.62-116) run **locally** and can emit **high-severity** "crontab writable / authorized_keys writable / web root writable" findings describing the *scanner box*. The gate narrows this to "only after a foothold finding," but because the foothold finding can itself be unproven (VULN_PROVEN substring), the residual self-description risk remains. Ties to the Tier-1 theme: the gate should require a *proven* foothold (Evidence object), not just a finding whose detail contains an RCE substring.

## `validation_agent.py` — solid PoC/command safety validation (the "Guardian Agent")
- This is `self.validation` used by weaponization (Round 36). `validate_python` (l.14-48): AST syntax check → AI-repair on SyntaxError → centralized `SafePayloadValidator` (payload_sandbox AST visitor) → reject on forbidden ops. `validate_bash` (l.50-111): dangerous-pattern deny (`rm -rf /`, `mkfs`, `dd if=`, `chmod 777 /`, `chown root`) + real hardening — **FIX C** rewrites hallucinated `/usr/share/wordlists...` to a provisioned wordlist path (kills the dead-wordlist failure class, same concern as syntax_learner's `{WORDLIST}` abstraction), **FIX D** auto-injects `-t 10` concurrency caps for ffuf/gobuster/wfuzz/dirsearch, and per-tool `timeout` injection. This is a distinct layer from `utils/guardian.py` (Round 22): guardian gates *tool identity* (allowlist) + destructive patterns; validation_agent gates *PoC code safety* + repairs/limits bash. No defect — good defensive hardening.

## Clean / low-risk (no defects)
- **`planning_agent.py`:** Phase-1 ConOps/RoE generation (AI JSON → formatted plan → `engagement_plan` info finding → publishes plan to all agents). Straightforward. (Note: the WAFFP-PLANNING-OVERRIDE writer of `waf_bypass_analysis`, Round 24, is NOT here — it lives elsewhere; this agent only produces ConOps.)
- **`objectives_agent.py`:** Phase-6 objectives assessment. Good **severity discipline** — `assessment_severity = "high" if (real_critical or critical) else "info"`, and it filters Nikto structural noise out of the critical set (l.65-77) and **never auto-escalates to critical** just because findings exist. Credential-based target SSH **blocked** (l.52-55, same self-infection guard as persistence). Effectively theoretical (no target executor).
- **`specialists.py`:** Recon/Exploit/Research sub-agents; build prompts from `TOOL_REGISTRY` filtered by category + learned syntax, then `run_react()`. Non-stealth mandate is aggressive by default (`nmap -T4`, no rate-limiting, l.30) — a design choice for authorized/lab perf mode, not a defect. Execution still flows through the base_agent guardian/tool_manager path.
- **`mentor_agent.py`:** `StrategicMentor.advise()` analyzes a stuck transcript + guardian logs and returns an assessment/flaws/pivot-recommendation JSON. **Advisory** (the transcript-level counterpart to reasoning_engine's per-tool `analyze_tool_failure`, Round 30) — both diagnose the stuck loop and *recommend* a pivot; neither enforces it. Consistent with the synthesis.

**Net verdict:** the agent tier is generally well-guarded and visibly self-aware of its own failure modes (scanner-box-vs-target confusion, Nikto noise, hallucinated wordlists, severity auto-escalation). persistence_agent adds a **second enforced self-deception gate** (foothold requirement) alongside ops-sanity — good — but shares the Tier-1 weakness that the gate trusts a *finding* (which can be an unproven VULN_PROVEN) rather than a *proof object*, and the residual scanner-box execution means a false foothold could still yield host-level findings about the local box. validation_agent is solid defensive code with useful anti-hallucination hardening (FIX C/D). No new pathologies — these reinforce that the engine's *guards* are real but keyed on emitter-writable findings/substrings rather than proof objects.

---

# Round 38 — `intelligence/objective_ledger.py` (179, was ⬜ NEVER-OPENED) + `core/tripwire_detector.py` (190), FULL reads

Two "control" modules: the objective-driven stop/momentum controller, and the honeypot-artifact pruner. objective_ledger yields a **significant new finding** — the corrupted success signal (Pathology 2) causes **premature false-victory termination**, a direct line to the user's "fails/hallucinates" symptom.

## OBJLEDGER-FALSE-WIN (HIGH) — a false-positive high finding can end exploitation with a declared "win"
- **Design intent (good):** `ObjectiveLedger` (docstring l.1-14) replaces the loop-counter waterfall with objective-centric control — it advances objectives from findings, drives momentum/abandon, and provides real stop conditions, claiming to be "evidence-driven … cannot be fooled into 'done' by activity alone."
- **Implementation breaks that claim:** `update_from_findings` (l.88-115) treats a finding as objective-advancing if its type ∈ {confirmed_vulnerability, valid_credential, …} **OR its severity ∈ {high, critical}** (l.91-97), then marks an objective `achieved` when a **substring marker** matches the finding blob (l.101-107: `any(m in blob for m in obj.markers)`). The markers are broad substrings — `sensitive_data` matches `"password"`, `"credential"`, `"token"`, `"secret"`, `"/etc/passwd"`, `"extracted"`; `admin_access` matches `"admin access"`, `"admin panel"`; etc.
- **Enforced stop (verified):** exploitation_agent l.1739-1743 calls `self._ledger.should_stop()` after the minimum loops and **`break`s** the exploitation loop when it returns True. `should_stop` (l.140-149) returns True when **no active primary objectives remain** (all achieved/abandoned).
- **The failure chain:** EXPLOIT-EMIT-1 (Round 13), recon-SENSITIVE (Round 14), and weaponization's substring-proof (Round 36) all **mint high/critical findings from raw substrings** without differential proof. Such a finding — e.g. a "critical" whose detail contains `"/etc/passwd"` or `"password"` — makes `update_from_findings` mark the `sensitive_data` (or `authenticated_access`, `admin_access`) primary objective **`achieved`**. Enough false achievements (or target-tailored abandonments) empty `active_primaries()` → `should_stop` fires → exploitation **breaks with "All primary objectives resolved."** So **Pathology 2 doesn't only poison learning — through the objective ledger it makes the engine QUIT EARLY believing it already won.** This is arguably the most user-visible consequence found so far: the corrupted success signal converts into *false victory + premature termination*, which reads exactly as "the engine hallucinated success and stopped."
- **Fix (Tier-1, same theme):** advance an objective only on a **proof object** (an `Evidence.is_proven()`-backed confirmed finding — like AuthzTester emits, Round 33), never on `severity ∈ {high,critical}` + substring marker. The ledger's *intent* ("evidence-driven, cannot be fooled by activity") is right; it just trusts severity+substring instead of proof.

## OBJLEDGER good parts (keep)
- **`_tailor_to_target` (l.74-84) is ENFORCED — a partial correction to Round 31:** it reads the Target Model's `implausible_vuln_classes` and **marks the corresponding objective `abandoned`** (e.g. RCE on a static SPA apex), and elevates object-authz to PRIMARY for api/spa. So the Target Model's "IMPOSSIBLE" list has a **real enforced consumer here** (abandons the objective → won't wait for it / won't push it in momentum), not merely the advisory prompt text of `target_profiler.format_for_prompt` (Round 31). Note: "abandoned" steers the ledger's stop/momentum but does not hard-block the AI from *attempting* the class — partial enforcement.
- The idle-streak exhaustion stop (`idle_limit=6`, l.146-148) is a genuine convergence backstop; `should_stop` respects `min_exploit_loops` (l.1739) so it can't stop too early by loop count; momentum directives (l.151-159) are objective-aware and reasonable (advisory via format_for_prompt). `attack_frontier.boost_for_objective` (Round 33) is the intended cross-link, though the frontier's pop-loop is dead (FRONTIER-POPLOOP-DEAD).

## `tripwire_detector.py` — solid honeypot-artifact mitigation (the mechanism behind recon's pruning)
- **Functional and correct:** `is_honeypot_active` (port-density threshold), `check_banner_similarity` (Jaccard similarity across sampled ports ≥75% pairs → Portspoof-style honeypot), and `prune_honeypot_ports` (l.87-118) — the deterministic backstop that strips the "Tor connect-scan → all 65535 ports open" artifact down to **verified-live** standard web ports (80/443/8080/8443), each confirmed via `_verify_live_http_service` (any HTTP code, incl. 401/403/404/500, counts as a real service). Falls back to 80/443. This is the concrete mechanism behind recon's honeypot pruning (Round 14) and pairs with self_awareness ops-sanity (Round 31) and the target_profiler port-scan-low-trust prompt (Round 31) — three independent defenses against the same self-fooling artifact. No real defect.
- **TRIPWIRE-WEB-ONLY (LOW, intended trade-off, closes the MD's "tripwire false-positive" check):** `prune_honeypot_ports` discards **all** non-web ports when a honeypot is suspected, so a legitimate multi-service host that trips the density/similarity heuristic (many genuinely open ports) would lose real non-web services (SSH, DB, etc.) from downstream consideration. This only runs under honeypot suspicion, so it's a deliberate "trust only verified web under a suspected tarpit" trade-off — acceptable, but worth recording as the false-positive behavior the MD flagged (l.488): the cost of the artifact defense is potential under-enumeration of real multi-service targets.

**Net verdict:** tripwire_detector is a clean, functional artifact-defense — no concern. objective_ledger is the important one: a well-intentioned, partially-enforced objective controller (it *does* enforce implausible-objective abandonment and objective-based stopping) whose achieve/stop logic is undermined by keying on **severity + substring markers instead of proof** — turning the corrupted success signal into **premature false-victory termination (OBJLEDGER-FALSE-WIN)**. This is a new, concrete, high-value manifestation of Pathology 2 at the control-flow level, and it strengthens the Tier-1 fix priority: route *every* trust decision (confirm, ops-sanity exemption, objective-achieve, objective-stop) through a real `Evidence` proof object, never through emitter-writable severity/text.

---

# Round 39 — infrastructure trio: `core/app_session.py` (240) + `core/ssh_executor.py` (338) + `core/target_context.py` (215), FULL reads

Three well-built infrastructure modules, all clean (no root-cause defects). Recorded for coverage completeness with the one or two minor notes each.

## `app_session.py` — the auth-session enabler for the gold-standard authz path
- A real authenticated HTTP session: carries cookies + bearer/JWT + CSRF and injects them into every request; `request()` returns `None` on transport error and never raises. `clone_anonymous()` / `clear_identity()` provide the **control arm** for authz differentials — this is exactly what `AuthzTester` (Round 33) uses to request the same object as owner vs. another identity vs. anonymous. `_maybe_lift_token` (JSON login → bearer), `_capture_csrf` (cookie/meta/hidden-input), and `decode_jwt_claims` (unverified payload decode so the AI can find the id claim to manipulate for IDOR) are all correct and dependency-light (requests + stdlib).
- **Minor:** `login_form`/`login_json` success detection is heuristic (status<400 + optional markers + gained-cookie/bearer) and sets `authenticated=True` optimistically — a login page that returns 200+cookie on *failed* auth could read as "logged in." Low impact: nothing is *confirmed* from `authenticated` alone; the downstream authz differential (control vs test) is what proves a finding, so an optimistic session flag can't manufacture a false vuln. No defect.

## `ssh_executor.py` — solid VPS execution with a thoughtful stall detector
- `connect`/`execute`/`execute_streaming` with remote `timeout` + a Python `timeout+5s` buffer so the remote timeout fires first. Config from `config_backends` (VPS_HOST/KEY/…) with env fallback; `BatchMode=yes`/`StrictHostKeyChecking=no` for non-interactive.
- **`_workload_active` stall detector (l.149-174) is the good part:** on a long-running command that stops emitting output, it samples `/proc/stat` CPU + `/proc/net/tcp` socket count twice ~0.5s apart and only kills the command if there's **no CPU movement AND no socket churn** — so a scanner that is legitimately silent for minutes while probing filtered/rate-limited hosts is **not** killed as "hung," but a truly hung process is. Parity with WSLExecutor. This is the right way to bound tool execution without banning slow scanners. (Note: this bounds *tool* execution only — it does **not** touch AIBACKEND-SLEEP-1 / ORCH-TIMEOUT-1, which is a Python-side `time.sleep` inside `ai.query()`, a different layer.)
- **Safety:** `cleanup_tmp` refuses to `rm -rf` an unsafe/`"/"`/short `VPS_TEMP_DIR` (l.298-304); `check_vps_health` surfaces disk>90% / CPU>5.0. No defect.

## `target_context.py` — clean URL model with a documented parse fix
- `from_input` (l.52-101) parses any user input into scheme/host/port/path/query with a **documented, correct fix**: it collapses only a *duplicated leading* scheme (`https://http://…` → `http://…`) and no longer strips the real scheme when `"://"` appears in a path/query (e.g. `?next=https://x`) — the old logic silently downgraded such URLs to `http://`. Rich dynamic-knowledge accumulators (endpoints/subdomains/tech/auth/api), `base_url`/`full_url`/`netloc` helpers, and `to_dict` for prompt/state serialization.
- **Minor (scope):** `add_subdomain` auto-adds each discovered subdomain to `scope_hosts` (l.150-155), and `is_in_scope` treats any subdomain of the root host as in-scope (l.180). For a wildcard-scoped authorized engagement this is intended; it does mean discovered subdomains are auto-in-scope without a separate authorization check — but `scope_enforcer` (already read ✅) is the actual enforcement gate, so this is a convenience model, not the security boundary. No defect.

**Net verdict:** all three are competent, correct infrastructure with only benign/heuristic edges. `app_session` is notable as the concrete enabler of the engine's best (differential, proof-first) capability — AuthzTester. `ssh_executor`'s workload-aware stall detector is a model for "bound the runtime without killing slow-but-working scanners." None affect the four-pathology diagnosis; they are the solid substrate the higher-level (mis-trusting) logic runs on.

---

# Round 40 — `core/ip_rotator.py` (358) + `core/vps_optimizer.py` (291), FULL reads

Two VPS-infra modules. ip_rotator is well-built and closes an MD open-question about repair-transform corruption; vps_optimizer is mostly a WSL no-op.

## `ip_rotator.py` — solid Tor rotation; the `build_proxychains_cmd` fix closes an MD check item
- **Tor lifecycle:** `ensure_tor_ready` checks the SOCKS port, restarts tor if down, and grabs a baseline exit IP. **Fail-fast `_tor_disabled` short-circuit (l.99-106):** once Tor is determined unroutable, it never re-pays the ~50s probe (ss + 4×10s curl checks) — a documented startup-time fix. `rotate` sends NEWNYM via a shell-agnostic python socket script, verifies the exit IP actually changed, and restarts tor after repeated failures. Thresholds are config/rules-driven.
- **BUILD-PROXYCHAINS fix (closes MD l.488 "does the repair transform corrupt valid commands like the WAF path once did?"):** `build_proxychains_cmd` (l.247-310) wraps **only the tool binary** (not `export`/env segments) with `proxychains4`, and — critically — has a **documented guard against splitting a literal `|` inside an argument**: it only treats a pipeline stage as real when the segment after `|` starts with a command-word token (`^[a-zA-Z][\w./-]*$`); a literal pipe followed by non-command text (`%s`, a quote, a bracket — e.g. `git --pretty=format:"%h | %s"`, awk/sed scripts, regexes) is **re-joined, not wrapped**. This is exactly the class of "repair transform corrupts a valid command" bug the MD worried about, and here it is explicitly handled. When `_tor_disabled`, it returns the command **unchanged** (no forced routing through a broken proxy). 
- **Reinforces the egress-cascade refutation (Rounds 20/24):** when Tor is blocked, ip_rotator **bypasses** (returns the unmodified command) rather than force-routing traffic through a dead proxy — consistent with "the engine does not force everything through a broken Tor and then misread the fallout."
- **Minor residual:** the pipe-split heuristic is best-effort and could still mis-handle an exotic genuine-pipeline-stage whose first token isn't a simple command word — but it errs toward *not* wrapping (re-join), which is the safe direction (a missed proxy wrap ≠ a corrupted command). No defect.

## `vps_optimizer.py` — advertised tuning is mostly a WSL no-op (VPS-OPT-STUBBED)
- The module's docstring advertises "Tunes SSH, networking, and filesystem for high-throughput scanning," but **all four tuning steps are stubbed** for WSL: `_optimize_ssh_maxsessions`, `_optimize_file_descriptors`, `_optimize_tcp_buffers`, `_optimize_congestion_control` (l.110-136) each just append `"Skipped (WSL)"` and do nothing (sysctl/SSHD tuning isn't available under WSL). The only real work is `_prepare_scan_directories` (mkdir + 24h buffer cleanup), `_cleanup_old_results` (keep 15 recent `eng_*` dirs; deletes oldest via a **scoped** `cd VPS_RESULTS_DIR && ls -td eng_*/ | tail -n +N | xargs -0 rm -rf` — safe, scoped, matches the MD's "careful cleanup" note), and `_verify_disk_space` (locale-robust `df` parse; warns <5GB/<15GB).
- **VPS-OPT-STUBBED (LOW):** the perf-tuning value proposition is inert on WSL — not a bug (correct to skip sysctl there), but "WSL Optimization Complete: N changes applied" over-reports (most "changes" are skips). On a real VPS (non-WSL) these would presumably do the tuning, but as written they always skip regardless of node type.
- **Leftover instrumentation (INFO):** `_agent_debug_log(...hypothesisId="H3"...)` (l.29-46, l.214-276) writes structured "H3 hypothesis" debug records to `debug-<session>.log` — leftover investigation scaffolding, harmless but should be removed for cleanliness.

**Net verdict:** ip_rotator is a well-engineered rotation/proxy layer whose command-rewrite is *careful* about not corrupting valid commands (closing an MD open question) and whose Tor-down behavior is safe-bypass (reinforcing the egress-cascade refutation). vps_optimizer is functionally reduced to dir-prep + result-cleanup + disk-check on WSL, with its advertised network/kernel tuning stubbed out and some leftover H3 debug logging. Neither affects the four-pathology diagnosis; both are clean-to-benign infrastructure.

---

# Round 41 — `agents/reporting_agent.py` (756 LOC, FULL read) — the CAPSTONE: where false positives reach the user

Phase-7 reporting. It has **genuinely good report-integrity design** (two-tier proven/leads split, honest objective-based verdict, FIX-E severity demotion, Evidence-backed PoC export, defensive anti-hallucination prompts) — but its "PROVEN" classifier keys on the **same emitter-writable substring/type** that the false-positive emitters write, so the corrupted-signal false positives (EXPLOIT-EMIT-1, weaponization substring-proof, objective ledger) **reach the final report as confirmed/critical**. This completes the Pathology-2 propagation chain end-to-end: classifier → confirmed-vuln → objective "win"/stop → report "PROVEN / COMPROMISED."

## REPORT-SPLIT-SUBSTR (HIGH — the capstone) — "PROVEN" is decided by a substring, not a proof object
- `_split_two_tier` (l.612-632) is the gate that decides what counts as a proven vulnerability for the entire report. Its test (l.623-626):
  `is_proven = (ftype == "confirmed_vulnerability") OR ("vuln_proven" in detail) OR ftype in {valid_credential, rce_confirmed, shell_access}`.
- So a finding is classified **PROVEN** if its type is `confirmed_vulnerability` **or its detail contains the substring `"vuln_proven"`** — exactly the type/token that **EXPLOIT-EMIT-1's substring branch (Round 13)** and **weaponization's `root:x:0`/`SQL syntax` branches (WEAPON-SUBSTR-PROOF, Round 36)** emit **without differential proof**. The report has no access to (and does not consult) a real `Evidence.is_proven()` object at this decision — it trusts the text.
- **Downstream blast radius of a mis-classified "proven":** it drives the **`COMPROMISED` verdict** (`_engagement_verdict`, l.650-653), the **headline "PROVEN vulnerabilities (Critical/High)" counts** (l.88-99) that anchor the executive summary, it **survives the FIX-E demotion gate** (l.66: `if any(f is pf for pf in proven_vulns): has_proof = True`), and it gets a **PoC-export entry** (l.708-727 fallback path). So a single substring-minted `VULN_PROVEN` finding can make the report tell the user "COMPROMISED — 1 critical vulnerability proven with reproducible evidence." **This is the end of the chain the user actually sees.**
- **Why the good controls don't catch it:** the two escape hatches that *do* demote — `"unverified lead" in detail` / `"[demoted" in detail` (l.629) — are set by the **ops-sanity backstop** (Round 31) and FIX-E. But EXPLOIT-EMIT-1's `VULN_PROVEN` findings **bypass ops-sanity** (SELFAWARE-OPSSANITY-BYPASS, Round 31, precisely because they carry `VULN_PROVEN`), so they never get the `[UNVERIFIED LEAD]` tag, so `_split_two_tier` never demotes them. The integrity controls are structurally sound but keyed on the very token the false positives carry — they filter *honest* low-confidence findings (which self-report as leads) and miss *confident-looking* false positives.
- **Fix (Tier-1 capstone):** `_split_two_tier` should classify PROVEN **only** when a finding has an associated `Evidence.is_proven()` object (the `evidence_objects` store it *already loads* at l.667-673 and exports at l.693-705 — the infrastructure exists!), never on the `confirmed_vulnerability` type or `vuln_proven` substring. Route the confirm-gate, ops-sanity exemption, objective-achieve, and this report split through the **same** Evidence check, and every substring-minted false positive is filtered at every stage at once.

## The report-integrity DESIGN is genuinely good (keep — it just needs the right key)
- **Two-tier split (W7.1):** headline risk counts reflect **proven vulns only**; leads are reported separately and "never inflate the risk rating" (l.86-101). Correct instinct.
- **Honest objective-based verdict (W7.2, `_engagement_verdict` l.634-665):** `COMPROMISED` / `PARTIAL` / `NOT COMPROMISED` based on *proven* impact, not "tools ran." It also appends the objective ledger's **achieved objectives** to the rationale (l.639-663) — which means OBJLEDGER-FALSE-WIN (Round 38) surfaces here too: a falsely-achieved objective is printed as "Objectives achieved: …" in the verdict. Same root, same fix.
- **FIX-E severity demotion (l.35-76):** high/critical findings **without** a matching proven exploit are demoted to medium with a `[DEMOTED: Unverified PoC]` tag (excluding CVE/subdomain/open_port). A real report-level guard — but it explicitly *exempts* anything in `proven_vulns` (l.66), so it inherits REPORT-SPLIT-SUBSTR's blind spot.
- **Evidence-backed PoC export (W7.3, `_export_pocs` l.675-736):** for each proven vuln, writes a reproducible export (proof_type / reproducible_command / request / response_excerpt / baseline_excerpt / **differential**) **from the real `evidence_objects`** — so legitimately-proven findings (AuthzTester/cache_deception Evidence, Round 33-34) export with genuine control/test differentials. This is the proof-object path done right; the split just doesn't gate on it.
- **Defensive AI prompts:** the exec/tech prompts explicitly forbid inventing vulns ("do NOT invent or assume vulnerabilities not listed"), forbid the classic XXE-from-`<!DOCTYPE html>` false positive (l.124-125), and instruct that leads be described only as "areas warranting further manual testing." Good anti-hallucination guardrails at the narrative layer.
- Graceful AI-down degrade (static summary), severity-sorted top-30 so critical findings aren't truncated, Rich terminal summary, `findings.json` export.

## Also observed (already-diagnosed, confirmed at their call-site)
- **Inert learning tail:** l.357-393 calls `AutoUpgrader.run_system_upgrade(dry_run=False)` (AUTOUPGRADE-FULLY-INERT, Round 28 — computes+discards), l.183-190 calls `EngagementAnalyzer` → `save_insights` (archival, Round 29), l.395+ calls `WafLearner` (WAFLEARN-BATCH-DEAD reads the wrong store, Round 23). All confirmed here as end-of-report calls whose "learning" doesn't close a runtime loop; the "[AUTO-UPGRADE] … changes applied" console output (l.368-383) over-reports learning that isn't applied.
- `_format_findings`/`_build_markdown_report`/Rich tables (l.579-600, ~400-560) are report formatting — noisy-type filter (`tech_stack`/`ssl_observation` dropped l.16-21), BUG-16 type/finding_type fallback. No logic defect.

**Net verdict:** reporting_agent is the best-*designed* integrity layer in the engine — it *wants* to separate proven from unproven and give an honest verdict — and it is the **capstone proof** of the whole diagnosis: because its "PROVEN" decision (like the confirm-gate, ops-sanity exemption, and objective ledger) trusts an **emitter-writable substring/type** instead of a **proof object**, the corrupted success signal propagates unbroken from the tool classifier all the way to a user-facing "COMPROMISED — N critical vulnerabilities proven." Every good control here (two-tier, verdict, FIX-E, PoC export) is already built and already loads the `evidence_objects` it needs — the single Tier-1 change (classify PROVEN on `Evidence.is_proven()`, not on `"vuln_proven"`/`confirmed_vulnerability`) would make all of them actually filter the false positives they were designed to catch.

---

# Round 42 — `core/tool_installer.py` (631 LOC, FULL read) — a sophisticated 7-gate installer that is DEAD CODE

`ToolInstaller` is a well-engineered, singleton, 7-gate autonomous install system (registry → hard-block → scope → resource → trusted-source → install → verify, with SHA256 integrity and a session install cap). **But its entry point `request_install` has no production caller** — a repo-wide grep shows `request_install`, `get_installer`, and `get_runtime_allowlist` are referenced **only in tests**. So the entire safety-gated install path is **unwired**, with three consequences that refine earlier findings.

## TOOLINSTALL-DEAD (HIGH-for-Pathology-4 / MED-for-safety) — the safest install path is never used
- **Evidence:** `request_install` (the sole entry to the 7 gates) is invoked only in `tests/test_tool_installer_concurrency.py`. `get_runtime_allowlist` — documented as "Convenience function for guardian.py to get current runtime-cleared tools" (l.629-631) — has **no caller** either. Production tool installation goes through **tool_manager's own install engine** (Round 12: VPS/WSL AI-repair install + PATH-locator) and/or `capability_registry._install_tool` (Round 15, specialist path) — **not** through this module.
- **Consequence 1 — the 7 safety gates are NOT applied to production installs.** Everything this module enforces is bypassed in the live path:
  - **Trusted-source gate** (Gate 5, l.399-417 + curl-pipe-bash guard l.341-346): production installs are not checked against the trusted-source allowlist, so tool_manager's AI-generated install commands aren't gated by "apt/pip/official-GitHub-only."
  - **Hard-block list** (Gate 2, `HARD_BLOCKED_BINARIES` — dd/mkfs/reboot/userdel/crontab/meterpreter…): not consulted on the live install path (tool_manager has its own logic; the guardian's DESTRUCTIVE/BLOCKED patterns cover *run*-time, but this install-time binary hard-block is dead).
  - **SHA256 integrity check** (Gate 6, l.489-507): this is the **only place** sha256 is actually verified — and it's dead. This refines **CAPREG-GATES-DEAD (Round 15)**: `capability_registry` *declares* `sha256`/`min_disk_mb`/`min_ram_mb` and doesn't enforce them; `tool_installer` *does* enforce them but is unwired. **Net: SHA256 tool-integrity verification is effectively never performed in production.**
  - **Resource pre-flight** (Gate 4, disk/RAM/load) and **session install cap** (Gate 7, 50/session): also dead on the live path (tool_manager may have partial equivalents, but this bounded, rate-limited version isn't used).
- **Consequence 2 — confirms GUARDIAN-ALLOWLIST-1 (Round 22) stands.** I flagged that the guardian could reconcile its hardcoded `ALLOWED_RECON_TOOLS` with installed tools; `get_runtime_allowlist` is exactly that intended bridge ("convenience function for guardian.py"). But **guardian.py never calls it** (no caller). So the guardian's run-time gate uses **only** its hardcoded ~90-tool set, with no awareness of what was installed this session — a novel AI-installed tool is still blocked at run time. The reconciliation exists in code but is not wired; GUARDIAN-ALLOWLIST-1 is unaffected.
- **Consequence 3 — a third dead install/registry mechanism deepens Pathology 4.** The engine now has **three install paths** — tool_manager's engine (LIVE), `capability_registry._install_tool` (specialist), and this 7-gate `ToolInstaller` (DEAD) — and **three tool allowlists** — guardian `ALLOWED_RECON_TOOLS` (live run-gate), `capability_registry.ALL_TOOLS` (Gate-1 install-registry, referenced by the dead installer), and `tool_installer._runtime_allowlist` (dead). They are maintained separately and none is authoritative. Add ~631 LOC to the dead-code census (symbol-level dead: the module is imported nowhere in production, only self-tests).

## Design quality note (why this is a loss, not a nitpick)
Ironically, `ToolInstaller` is the **most safety-conscious** provisioning code in the tree — it's exactly the "AI can install autonomously, but behind hard safety gates" design that reconciles the user's "install any tool from anywhere" goal with not curl-pipe-bashing arbitrary code onto the VPS. Its Gate 1 (must be in `capability_registry`, "a human must add it first," l.207-213) is the one autonomy-limiting piece — but the *rest* (trusted-source, hard-block, sha256, resource, verify) is precisely the safety envelope autonomy needs. Because it's dead, production gets the **autonomy-limiting** parts of provisioning (the guardian allowlist at run time) **without** the compensating **safety** parts (source/integrity/resource gating at install time). That's the worst of both: constrained *and* less safe.
- The one gate that *would* contradict full autonomy — Gate 1's human-pre-registration requirement — is moot here since the whole module is unused; but note it as the same Pathology-4 theme if the module is ever wired: revive it with a *derived* registry (union of live installs), not a hand-maintained one.

## Verification/verify logic (for completeness)
- `_verify_install` (Gate 7, l.546-610) is robust: PATH + common-location search, then `--version`/`--help`/`-h`/bare-run with marker matching (`binary`/`version`/`usage`/`help`) or exit-0 fallback. This verifies the *binary runs*, not that a *scan found something* — so it is **not** an instance of the TOOLMGR-1 false-success class (different concern: "does the tool exist and execute," which is the correct question for install verification).
- `_do_install` (l.450-544) wraps the script non-interactively (base64 + `sudo -E bash`), retries across strategies, and captures failure details. Sound — just unreachable.

**Net verdict:** `tool_installer.py` is a high-quality, safety-first, autonomous-install subsystem that **isn't wired into anything** — its 7 gates (including the *only* SHA256 integrity check and the *only* trusted-source install gate in the codebase) never run in production, and its guardian-reconciliation bridge (`get_runtime_allowlist`) is uncalled, so GUARDIAN-ALLOWLIST-1 stands unmitigated. This is simultaneously (a) a Pathology-4 finding (third dead install path + third unreconciled allowlist), (b) a safety gap (production installs bypass source/integrity/hard-block/resource gating), and (c) ~631 LOC of dead code. The fix is inverted from most findings: here the *dead* code is the *good* code — wire `request_install` as the production install path (with a derived, not hand-maintained, Gate-1 registry) and have the guardian consult `get_runtime_allowlist()`, and both a safety gap and a chunk of Pathology-4 fragmentation close at once.

---

# Round 43 — `intelligence/engagement_recorder.py` (163, was ⬜) + `core/target_graph.py` (483), FULL reads

One dead learning-feeder (which retroactively neutralizes a Round-25 finding) and one genuinely-sound, wired pivot graph.

## RECORDER-DEAD (refines Round 25) — EngagementRecorder is dead, so ADVISOR-WAF-ALLTRUE is on a dead path
- `EngagementRecorder` records per-engagement data (tools_used, tech_stack, waf tactics, findings, phase durations) and `finalize_and_learn` (l.99-120) forwards it to `advisor.record_engagement_outcome`.
- **No production caller:** a repo-wide grep shows `EngagementRecorder`, `finalize_and_learn`, and `record_tool_usage` are referenced **nowhere outside this file** (not even in tests). The class is never instantiated. So it is **dead code** (~163 LOC → dead census).
- **Consequence — corrects Round 25's blast radius:** Round 25 flagged `StrategicAdvisor.record_engagement_outcome` (l.473-479) as marking **every** WAF tactic `success: True` unconditionally (ADVISOR-WAF-ALLTRUE). But `record_engagement_outcome`'s **only caller is `EngagementRecorder.finalize_and_learn`** (confirmed by grep in Round 25: the sole hit was engagement_recorder.py:109). Since EngagementRecorder is dead, **`record_engagement_outcome` is never invoked in production** — so ADVISOR-WAF-ALLTRUE is a **real bug on a dead path**, not a live poisoning source. (The advisor's *live* poison remains `record_tool_outcome`/`record_finding`, which base_agent calls directly — Round 25 ADVISOR-NONATOMIC-SAVE / ADVISOR-SIGNAL stand.) This further shrinks the durable-poison surface: another "learning feeder" that doesn't run.
- **Pattern reinforced:** EngagementRecorder duplicates recording that base_agent already does directly against the advisor/tracker/awareness — a redundant, unwired second recording layer. Consistent with the session's recurring finding that the learning apparatus is heavily inert/dead (auto_upgrader chain, EngagementRecorder, ToolInstaller, EvidenceRouter class).

## `target_graph.py` — sound, wired, no defects (confirms prior MD characterization)
- **Genuinely used** (MD l.479 already noted this; confirmed here): `TargetGraph` is imported and read by exploitation_agent (l.402-480) for **cross-target credential reuse and lateral-movement/pivot** decisions — `get_all_credentials`, `nodes`, `register_credential_test`, `register_pivot`, port-22 checks.
- **Correct machinery:** `add_target`/`add_credential`/`add_relationship` (dedup on src+dst+rel_type), `analyze()` correlation passes (`_detect_shared_ips`/`_shared_certs` incl. SAN cross-reference/`_shared_nameservers`/`_shared_mx`/`_subdomain_relationships`), `register_credential_test`/`register_pivot`, and query helpers `get_pivot_candidates` (priority-sorted: pivot_path > credential_tested > shared_ip > …) and `get_shared_infra_clusters` (union-find). All straightforward and correct.
- **Notably NOT corrupted-signal-driven:** `register_credential_test` (l.268-276) records the result of an **actual** credential test on another host (`success` comes from a real auth attempt in exploitation), and `register_pivot` records a **confirmed** pivot method — these are genuine cross-target signals, not the structural tool-classifier verdict. So the graph's high-value edges (credential_tested/pivot_path) are trustworthy by construction. `internal_reference` (JS/HTML on A references B) is confidence 0.9; correlation edges are evidence-tagged.
- **Only real limitation (already in MD):** the graph is **starved by corrupted/thin recon** — its value depends on recon populating nodes with real IPs/certs/nameservers/credentials. If recon under-enumerates (e.g. honeypot pruning to web-only, Round 38; or Tor-thin evidence), the graph has little to correlate. That's an *input* limitation, not a graph defect. No own-logic bug.

**Net verdict:** engagement_recorder is dead (and its deadness retires ADVISOR-WAF-ALLTRUE as a live concern — a net *reduction* in the live-poison surface). target_graph is one of the cleaner, genuinely-wired pieces of decision machinery in the engine, and — refreshingly — its important edges are driven by **real** test outcomes rather than the corrupted success signal, so it does not participate in Pathology 2; it is only limited by the quality of the recon that feeds it. Neither changes the four-pathology model: one adds to the dead/inert census, the other is a sound consumer starved by upstream input quality.

---

# Round 44 — config & session cluster: `config_thresholds.py` (171) · `core/config_loader.py` (201) · `config.py` (304) · `core/session.py` (79) · `core/config_manager.py` (35) · `core/unified_config_loader.py` (53), FULL reads

All functional and clean; no logic defects. Two things worth recording: `session.py` **corroborates Round 28's path-split**, and the cluster exhibits **config fragmentation** (a minor cousin of Pathology 4).

## `session.py` — corroborates Round 28 (per-engagement results_dir)
- `EngagementSession.__post_init__` sets `results_dir = RESULTS_DIR / self.engagement_id` (l.51) — a **fresh per-engagement directory** (`results/eng_<hex>/`), with `state.db` and WSL/VPS temp dirs also engagement-scoped (l.58-65). This **confirms two Round-28 findings**: (1) `ToolSuccessTracker`'s `db_path = session.results_dir/tool_metrics.json` is a new file each engagement → its learning is **within-run only** ("cross-run learning aspirational"); (2) `auto_upgrader` writes `<repo_root>/tool_metrics.json` — a *different*, persistent path the tracker never reads → the AUTOUPGRADE-FULLY-INERT path-mismatch is real, now proven from the session wiring. Also good: per-engagement segregation of temp/results dirs prevents cross-engagement artifact bleed. `normalized_target()` strips scheme/path correctly. No defect.

## `config.py` — good safety defaults (keep)
- Genuinely useful scope-safety defaults: **`BLOCKED_IP_RANGES`** (RFC1918 + link-local + multicast, l.256-260) and **`ALWAYS_BLOCKED_DOMAINS`** (google/cloudflare/aws/microsoft/apple/facebook, l.261-264) — prevent accidentally scanning private ranges or major infra; **`REQUIRE_WRITTEN_CONSENT=True`** (l.249-253) legal gate. **`AUTO_APPROVE_INSTALLS=True`** (l.51-55) is the autonomy default (auto-approve AI installs, apt/pip validated) — so install *approval* is not the bottleneck; the tool registries/guardian are (Pathology 4). STEALTH_HEADERS / CURL_TLS_FLAGS / DNS_FALLBACK_SERVERS all config-driven. No defect.

## `config_thresholds.py` / `config_loader.py` — clean
- `config_thresholds.py`: pure env-overridable constants — feeds tripwire (`HONEYPOT_PORT_THRESHOLD=50`, `HONEYPOT_RESPONSE_SIMILARITY_THRESHOLD=0.95`, Round 38), the token-budget circuit breaker (`PHASE_TOKEN_BUDGET_*` 400k/600k/300k, wired per MD), the dead installer's resource gate (`MIN_FREE_DISK_MB/RAM_MB`, Round 42). Values reasonable. Note: `AI_REQUEST_TIMEOUT=60` and `TOOL_AI_TIMEOUT=180` don't bound the internal `ai.query()` recovery sleep (AIBACKEND-SLEEP-1, Round 16) — that's an ai_backend issue, not a config bug.
- `config_loader.py`: YAML loader with **path-traversal guard** (`safe_config_name` regex, l.22) + `lru_cache`, env-override `get_config(config_name, key_path, default, env_var)` (4-arg), and a unified `ConfigManager` (FIX #4.1) with section routing + typed getters. Clean.

## CONFIG-FRAG (LOW — organizational, a minor cousin of Pathology 4)
The engine has **seven** overlapping config modules — `config.py`, `config_thresholds.py`, `config_backends.py`, `config_paths.py`, `core/config_loader.py`, `core/config_manager.py`, `core/unified_config_loader.py` — with concrete redundancy:
- **Two different functions named `get_config`:** `config_loader.get_config(config_name, key_path, default, env_var)` (4-arg, returns a value) vs. `config_manager.get_config()` (no-arg, returns a `MockConfig` with `.timeout`/`.vps` attributes, l.30-34). Different call sites import different ones (`base_agent` uses the no-arg `MockConfig` form for `get_config().vps.use_remote_vps`; `tool_installer` uses the 4-arg form). Same name, different signatures/semantics — a real readability/foot-gun hazard.
- **Two "unified/centralized" config classes:** `config_loader.ConfigManager` (FIX #4.1, "single entry point") and `unified_config_loader.UnifiedConfigLoader` ("Centralizes configuration") — but the latter only merges a **handful** of keys (USE_REMOTE_VPS/USE_WSL/VPS_DISK_ABORT_PCT/LOG_DIR/WORDLIST_DIR/VPS_HEALTH_CHECK_TIMEOUT/AI_BACKENDS, l.16-49), a partial and likely-redundant unifier alongside the real one.
- `config_manager.py`'s class names (`MockTimeoutConfig`/`MockVpsConfig`/`MockConfig`) suggest a test mock that became production wiring.
- **Impact:** functional (they all resolve values correctly), but it is *config* fragmentation mirroring the *tool-registry* fragmentation of Pathology 4 — multiple overlapping "centralizers" none of which is authoritative. Cleanup value, not a runtime defect. Consolidating to the single `config_loader.ConfigManager` + retiring the `MockConfig`/`UnifiedConfigLoader` duplicates would remove the same-named-`get_config` foot-gun.

**Net verdict:** the config/session layer is functionally sound with good safety defaults and a useful path-traversal guard; `session.py` independently confirms Round 28's per-engagement results_dir (validating both the tracker-within-run-only and auto_upgrader path-split findings). The only observation is CONFIG-FRAG — seven overlapping config modules, two clashing `get_config` signatures, two partial "unified" loaders — a low-severity organizational echo of Pathology 4, cleanup-only. No pathology-changing findings.

---

# Round 45 — weaponization/registry support: `tools/tool_registry.py` (409) + `utils/poc_customizer.py` (446) + `utils/poc_templates.py` (576), FULL reads

Three support modules for tool metadata and PoC synthesis. All clean; two notes: `tool_registry` is the **third Pathology-4 registry**, and `poc_templates` is a genuinely **evidence-based** PoC path (a positive).

## `tool_registry.py` — the third tool registry (Pathology 4), well-maintained
- Holds `TOOL_REGISTRY` (~30 tools: binary/install/category/timeout/**description-with-syntax-constraints**), plus `TOOL_TIMEOUTS`, `VIRTUAL_TOOLS`, `VIRTUAL_AI_TOOLS`, `HTTP_TOOLS`, `STREAMING_TOOLS`, `FAST_TOOLS`, `WRAPPER_TOOLS`, `FILE_OUTPUT_TOOLS`, and `TOOL_FALLBACKS` (nuclei→nikto→ffuf→curl chains).
- **Quality:** install commands use the **GitHub latest-release API** (not hardcoded versions) for nuclei/ffuf/subfinder; descriptions carry useful hard constraints ("masscan: MUST prefix sudo, IP/CIDR only, IP last"; "sqlmap: MUST --batch"; "nmap: -T4"). These descriptions are what `specialists.py` injects into sub-agent prompts. Well-maintained tool data, no defect.
- **Pathology-4 confirmation (the third registry, concrete sizes):** this `TOOL_REGISTRY` (~30 tools with install metadata) is a **third** hardcoded tool list, distinct from `guardian.ALLOWED_RECON_TOOLS` (~90, the live run-gate, Round 22) and `capability_registry.ALL_TOOLS` (44 ToolCapability, Round 15). The three differ in size and membership and are maintained separately: a tool can be in the guardian allowlist (runnable) but absent from `TOOL_REGISTRY` (no install metadata → relies on tool_manager dynamic discovery), or in `TOOL_REGISTRY` but not resolvable by a specialist (which uses `capability_registry`). None is authoritative. This is the data-level proof of the registry fragmentation that GUARDIAN-ALLOWLIST-1 / CAPREG-FRAG / TOOLINSTALL-DEAD describe.

## `poc_customizer.py` — recon-grounded PoC parameterization, clean
- `customize_poc_params` (l.23-71) reads the recon phase data and derives per-vuln-class parameters (frameworks, hosting, discovered endpoints/ports/services/CMS, response headers, waf presence) from **actual recon**, then dispatches to `_customize_{disclosure,misconfig,traversal,ssrf,redirect}_poc`. The framework→headers/error-paths maps (l.89-112) are reasonable hardcoded defaults that get *overlaid* with real discovered endpoints — so the customization is grounded in recon, not blind. This is what feeds weaponization's template params (Round 36) and is a genuine improvement over target-agnostic PoCs.
- **Minor (consistent with WAFFP-TYPE-MISNOMER, Round 24):** `waf_type = recon_data.get("waf_fingerprint", {}).get("type", "unknown")` (l.44) — the fingerprint never sets `"type"`, so `waf_type` here is always `"unknown"`. Harmless (it's context for the PoC), same root as Round 24. No defect.

## `poc_templates.py` — EVIDENCE-BASED PoC templates (a positive; the reliable proof path)
- A library of hardcoded PoC skeletons per vuln class (SQLi, XSS, LFI, …); the AI fills only `{target}/{path}/{param}`. **Crucially, the templates enforce real proof, not bare-200 assertion:**
  - **SQLI_TEMPLATE (l.10-60):** confirms only on an **actual SQL error string** in the body (`"sql syntax"`/`"mysql"`/`"ora-"`/`"unclosed quotation"`/…) **or a time-based blind delay** (`SLEEP(5)` → `elapsed ≥ 4.5s`), with an explicit homepage guard (`"<!doctype html"` + `"wp-content"` → skip) and a clear `NOT_PROVEN` default. `XSS_TEMPLATE` uses a **unique canary** (`gw5xss7probe`) and checks for reflection.
  - Each template emits the strict `VULN_PROVEN: <proof>` / `NOT_PROVEN: <reason>` protocol that weaponization's validator expects.
- **Why this is the good path:** unlike EXPLOIT-EMIT-1's raw-substring mint (Round 13) or weaponization's `root:x:0`/`SQL syntax` elif bypass (WEAPON-SUBSTR-PROOF, Round 36), these templates check for **genuine, vuln-specific indicators** (DB error, timing, canary reflection) and guard against the homepage/404 false positive **inside the template**. So a `VULN_PROVEN` produced by the template path is **legitimately evidenced** (subject still to weaponization's `_is_false_positive` on top). This is the "reliable, FP-guarded template PoC" Round 36 credited — confirmed here at the source. The hardcoding is acceptable because these are **proof-checking skeletons**, not blind payloads, and they are demoted/validated downstream.
- No defect. (Residual: they still print the `VULN_PROVEN` token that downstream over-trusts — but the *content* behind it here is real, so the fix remains downstream: have consumers key on an Evidence object; the template correctly demonstrates the impact.)

**Net verdict:** all three are clean support code. `tool_registry` is the concrete third leg of the Pathology-4 registry fragmentation (well-maintained data, but one of three unreconciled hardcoded tool lists). `poc_customizer` grounds PoC params in real recon (good). `poc_templates` is a **positive** — evidence-based, FP-guarded PoC skeletons with a proper proof protocol, i.e. the *right* way to produce a `VULN_PROVEN` (real indicator check), in contrast to the substring-mint paths elsewhere. None changes the four-pathology model; `poc_templates` is further evidence that the engine already contains correct evidence-first building blocks — the disease is the un-gated *shortcut* paths and the substring-trusting *consumers*, not the proof-checking code like this.

---

# Round 46 — final infra/diagnostics/entrypoint: `main.py` (580) · `utils/display.py` (515) · `utils/logger.py` (119) · `core/health_monitor.py` (70) · `health_check.py` (215) · `integration_test.py` (250) — FULL-READ PASS COMPLETE

The last six files: the entrypoint, terminal rendering, logging, the health-abort monitor, and two standalone diagnostic scripts. All are non-decision infrastructure with no pathology-relevant defects. Reading them closes the full-read pass.

## `main.py` (580) — entrypoint, wiring (already 🟢, now fully confirmed)
- CLI → Windows UTF-8/console-buffer setup → target validation (`is_valid_target`) → `EngagementSession` → `Orchestrator.run`. Includes a startup readiness ping (`dummy.analyzer && dummy.reasoning`, l.304) that confirms the AI backend + `StructuredAnalyzer`/`ReasoningEngine` are live before the run. Legal/consent gate (`REQUIRE_WRITTEN_CONSENT`, print_legal, mission_briefing). Standard orchestration entry; no decision logic beyond wiring the components already analyzed. No defect.

## `health_monitor.py` (70) — the disk-abort backstop (clean)
- Background daemon thread polling VPS disk% + load every 60s; sets `_abort_flag` when disk **> 95%** (l.44-49), consumed by the orchestrator's health kill-switch (Round 17) via `should_abort()`. The one genuine hard-abort on real resource exhaustion. Minor: only disk triggers abort (load is recorded, never aborts); `_health_status["issues"]` appends each over-threshold loop (unbounded within monitor lifetime) — cosmetic. No defect.

## `logger.py` (119) — logging (clean)
- Rich console handler (HUD-themed level prefixes) + **RotatingFileHandler** (10MB × 5 backups, bounded) per named logger, cached in `_loggers`, UTF-8-forced on Windows before Rich import. Standard, bounded, no defect.

## `display.py` (515) — terminal rendering only (confirmed presentation-layer)
- Rich UI helpers: `banner`, `section`, `info`/`warning`/`error`/`success`, `print_legal`, `preflight_check`, `mission_briefing`, color constants, and the report tables used by reporting_agent (Round 41). Pure presentation — no finding/severity/proof logic. Confirms the ledger's "low-risk render" classification. No defect.

## `health_check.py` (215) + `integration_test.py` (250) — standalone dev/CI scripts (not runtime)
- `health_check.py`: a diagnostic script — `py_compile` syntax check of critical files, import checks, and "core patches" feature verification (target normalization, command building). Run manually/CI, not imported by the engine.
- `integration_test.py`: a standalone integration test — mocks session/store/bus (`SimpleNamespace`) and exercises the AI-prompt→command-generation→guardian-validation pipeline end-to-end against a sample target. Also a script, not runtime.
- Neither is part of the engine's execution path; both are test/diagnostic tooling. No defect (and not decision code).

---

# ✅ FULL-READ PASS COMPLETE — coverage & closing synthesis (Rounds 1-46)

Every non-test source file in `agents/`, `core/`, `intelligence/` (incl. `waf_bypass/`), `tools/`, `utils/`, and root/config has now been read **end-to-end** and logged (the FILE_COVERAGE_LEDGER reflects ✅ across the tree; remaining ⬜ were the dev/diagnostic scripts, now read here). The full read **did not overturn** the four-pathology diagnosis — it **sharpened it**, traced it end-to-end, and substantially **re-scoped Pathology 3**.

**The one chain that explains the user's symptom (fully traced, every link a read finding):**
1. `tool_manager._execute` classifier marks banner-only/exit-0 output SUCCESS (TOOLMGR-1) — structural success, not result-presence (`result_contracts.ToolResult.success`).
2. `exploitation_agent._emit_exploit_findings` substring branch mints `VULN_PROVEN`/critical with no differential (EXPLOIT-EMIT-1); `weaponization` has the same `root:x:0`/`SQL syntax` shortcut (WEAPON-SUBSTR-PROOF).
3. That `VULN_PROVEN` token **exempts** the finding from the one enforced anti-self-deception gate (`_ops_sanity_backstop`, SELFAWARE-OPSSANITY-BYPASS).
4. `objective_ledger.update_from_findings` marks a primary objective **achieved** on (severity∈{high,critical} OR type)+substring, and `should_stop` **enforced-breaks** exploitation → **premature false victory** (OBJLEDGER-FALSE-WIN).
5. `reporting_agent._split_two_tier` classifies it **PROVEN** on the same substring/type → user sees "**COMPROMISED — N critical vulnerabilities proven**" (REPORT-SPLIT-SUBSTR).

**The single Tier-1 fix that severs every link at once:** make *every* trust decision — classifier success, confirm-gate, ops-sanity exemption, objective-achieve/stop, report-PROVEN — key on a real `Evidence.is_proven()` object, never on the emitter-writable `"vuln_proven"` substring / `confirmed_vulnerability` type. The proof infrastructure **already exists and is correct** (`AuthzTester`, `cache_deception`, `poc_templates`, `hypothesis_engine.validate_result` all produce/consume real differentials; `reporting_agent` already *loads* `evidence_objects`). The disease is un-gated shortcut paths and substring-trusting consumers, not missing capability.

**Re-scoping from the full read (net corrections to the original MD):**
- **Pathology 3 (permanent corrupted feedback) is much smaller than framed.** The entire `auto_upgrader` pipeline is INERT (Round 28), `syntax_learner` is DEFENDED (Round 32), `EngagementRecorder`/`record_engagement_outcome` is DEAD (Round 43), `EvidenceRouter`/`TechStackRouter`-commands are dead/demoted (Round 26), `ToolInstaller` is DEAD (Round 42). The live learners are mostly **advisory** (advisor note, tracker summary, frontier snapshot, syntax hints) — META-RC-0/Pathology 1 — with only `hypothesis_engine` and `ReasoningEngine`-calibration actually **enforcing/clean**. The dominant real failure is **Pathology 1 + 2**: unenforced self-knowledge + the model reasoning from a poisoned *context window*, not durable state corruption.
- **Pathology 4 (fragmentation) is concretely three unreconciled tool registries** — `guardian.ALLOWED_RECON_TOOLS` (~90, live run-gate) vs `capability_registry.ALL_TOOLS` (44) vs `tool_registry.TOOL_REGISTRY` (~30) — plus three install paths (tool_manager LIVE, capability_registry specialist, tool_installer DEAD). The safest install path (7-gate `ToolInstaller` with the *only* SHA256/trusted-source gates) is dead, so production is *constrained AND less safe*.
- **The engine is consistently better-built than a survey suggests**, and its enforced gates (confirmed-vuln gate, ops-sanity downgrade, persistence foothold-gate, hypothesis differential, AuthzTester/cache_deception proofs, tripwire pruning) are real — they are only undermined by trusting substrings/severity instead of proof objects.

Nothing further to explore in the source tree: all decision-critical logic, all learning/WAF/registry machinery, all agents, all plumbing, and all config/diagnostics have been read line-by-line and documented across Rounds 1-46.
