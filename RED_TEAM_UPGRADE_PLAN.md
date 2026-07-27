# GHOSTWIRE — Red-Team-Grade Upgrade & Implementation Plan

**Author:** engineering pass, 2026-06-12
**Goal:** turn GHOSTWIRE from a *scanner-orchestrator wearing a red-team costume* into an actual
red-team **operator** — one that understands a target, gets inside, proves impact, and adapts —
while honoring the core rule: **fully AI-driven, no hardcoded commands/heuristics**
(see memory `fully-ai-driven-no-hardcoding`).

---

## 0. Why this plan exists (current state)

A 3h27m live run vs `novalink.lk` (a static React SPA on Vercel selling reseller VPN plans) found
**0 real vulns**, "logged 92" (82 INFO noise + a hallucinated WAF bypass), and reported SUCCESS.
Root causes split into two buckets:

- **Correctness** — the engine poisoned itself (proxy→false honeypot, false-FAILED overrides,
  blind command generation, hallucinated proof). *Mostly fixed this session — see WS1.*
- **Capability** — it is structurally unable to do what a red team does: it has **no target model**,
  **no authenticated/app-aware testing** (grep confirms: no login/session/token/browser-drive code),
  **no concept of proof-by-control**, a **rigid waterfall** pipeline, and **no operational self-model**.
  *This is the bulk of the plan — WS2–WS8.*

### Already shipped this session (correctness foundation)
| Fix | File | Status |
|---|---|---|
| Two-pass proactive `--help` grounding (recon+exploit) | `tools/tool_manager.py`, `agents/base_agent.py`, `agents/recon_agent.py`, `agents/exploitation_agent.py` | ✅ done, unit-tested |
| False-honeypot guard (require banner corroboration; unreliable-scan path) | `agents/recon_agent.py` | ✅ |
| False-FAILED override fixed (trust exit-0 + real output) | `tools/tool_manager.py` | ✅ |
| Hallucinated-vuln differential guard (≈baseline ⇒ not confirmed) | `intelligence/hypothesis_engine.py` | ✅ |
| Findings-from-commands demoted to INFO leads | `agents/exploitation_agent.py` | ✅ |
| Persistence gated on real target foothold | `agents/persistence_agent.py` | ✅ |
| Repair rejects shell-unparseable commands; quiet traceback | `agents/base_agent.py`, `tools/tool_manager.py` | ✅ |
| whatweb header comma-strip | `core/waf_ghost_engine.py` | ✅ |

---

## 1. Guiding principles
1. **No hardcoding** — feed the AI ground truth (real `--help`, real responses, real evidence) and let it decide. Mechanisms, not command templates.
2. **Proof or it didn't happen** — a finding is only a vuln with a reproducible differential (control vs. test). Everything else is a *lead*.
3. **Model before action** — understand the target, then choose actions by expected impact.
4. **Get inside** — authenticated/app-aware testing is first-class, not an afterthought.
5. **Know thyself** — the engine must model its own ops (proxy, rate, budget) so it isn't fooled by its own plumbing.
6. **ROE is operator-declared + HITL-gated** — the Rules of Engagement are exactly what the operator sets at engagement start (`allow_exploitation / allow_brute_force / allow_phishing / allow_destructive`, scope, stealth). The AI operates strictly within them. When the AI decides it needs an action *beyond* the standing ROE (a destructive WAF attack, logging into / registering on the target, credential brute force, anything outside scope), it does **not** silently proceed and does **not** require a new config flag — it **escalates to a Human-In-The-Loop (HITL) gate and asks the operator**, reusing the existing pattern: `WafAttackAuthorizationRequired` (`intelligence/waf_bypass_orchestrator.py:550`) → `[HITL GATE]` prompt (`agents/base_agent.py:2426`). Denied ⇒ skip that action; approved ⇒ proceed for that action only. **This is the single, uniform authorization model for every new capability in this plan.**

### ROE model (canonical)
```
Standing ROE  = operator flags chosen at engagement start (allow_exploitation,
                allow_brute_force, allow_phishing, allow_destructive, scope, stealth).
Within ROE    → the AI acts autonomously.
Beyond ROE    → the AI must call the HITL gate (WafAttackAuthorizationRequired-style),
                which pauses and ASKS the operator. No new per-feature on/off flags.
Denied        → action skipped, engagement continues. Approved → that action runs.
```
Every "ROE-gated" item below means **exactly this**: allowed if the standing ROE already covers it, otherwise the AI escalates and asks you in real time.

---

## WS1 — Correctness guardrails (finish the foundation)
**Status: Phase 0 items shipped (2026-06-13). Remaining: W1.3, W1.4.**
- ✅ **W1.1** Proxy-aware scanning. When Tor/SOCKS is verified active, the recon prompt now carries an explicit OPS NOTE forbidding `-p1-65535`/`-p-` and directing the AI to `--top-ports 200` or explicit web ports (full-range connect-scans through a proxy report every port "open"). *File:* `agents/recon_agent.py`. (The post-scan unreliable-scan guard from last session still prunes any garbage that slips through.)
- ✅ **W1.2** Per-phase token budget + circuit breaker. `AIBackend` now tracks approximate token usage per phase (`set_current_phase`/`_record_usage`/`is_phase_budget_exceeded`); orchestrator attributes usage per phase; `BaseAgent.is_phase_budget_exhausted()` is checked at the top of the recon & exploitation loops (past min loops) to stop a repair storm draining the Groq TPD. Budgets in `config_thresholds.py` (`PHASE_TOKEN_BUDGET_*`). *Files:* `core/ai_backend.py`, `core/orchestrator.py`, `agents/base_agent.py`, `agents/recon_agent.py`, `agents/exploitation_agent.py`, `config_thresholds.py`.
- ✅ **W1.3** Extend grounding to the v6 ReAct path (`_execute_v6_action`) — DONE (2026-06-13): AI-built commands are grounded against real `--help` before firing (raw_command passthrough preserved). *File:* `agents/base_agent.py`.
- **W1.4** Live smoke run vs an authorized target to confirm the guardrails land (watch for `[GROUNDING] Rewrote N` and a drop in `[AI REPAIR]`/`[FAILURE]`). **Effort S.** *(pending — needs WSL+Tor+Groq+authorized target)*

**Acceptance:** a recon phase completes < 15 min with < 10% command-failure rate and no false "honeypot".

---

## WS2 — Target Comprehension Layer  *(highest leverage)* — ✅ SHIPPED 2026-06-13
**Problem:** recon emits a pile of facts but never a *thesis*. It treated a static SPA like a PHP monolith and threw SQLi/forms/port-scans at it for 3 hours.

**Status: shipped & unit-tested (9/9 in `tests/test_target_profiler.py`).** `intelligence/target_profiler.py` (`TargetProfiler` + `TargetModel` contract) synthesizes the model from recon evidence: W2.1 AI synthesis (feeds real headers/tech/endpoints/JS-routes, AI reasons target_type + plausible/implausible vuln classes — no hardcoded rules), W2.2 JS-bundle ingestion (mines `/api/...`, abs API URLs, GraphQL from homepage HTML + fetched `.js` bundles via a `fetch_fn` curl callback; excludes static assets), W2.3 strategy injection (`format_for_prompt` → injected into the exploitation prompt above TARGET PROFILE, with an explicit "IMPOSSIBLE on this target — DO NOT ATTEMPT" line), W2.4 subdomain triage (`ranked_subdomains`). Wired in `agents/recon_agent.py` (after `multi_bundle` build → `target_model` in bundle + `:target_model` state key + `target_model` finding) and consumed in `agents/exploitation_agent.py` (cached per phase). Falls back to an evidence-only model if AI is unavailable. **Acceptance MET:** mock-AI test on a novalink-shaped SPA yields `target_type=spa`, reseller/API subdomains ranked first, apex SQLi in `implausible_vuln_classes`.

**Original change list (for reference):**
- **W2.1 New module `intelligence/target_profiler.py`** — after recon, the AI synthesizes a **Target Model**:
  - `target_type`: `spa | api | cms | monolith | static | gateway | unknown`
  - `stack`: framework/CDN/server/auth scheme (from headers, JS bundle, whatweb, wappalyzer-style signals)
  - `attack_surface`: concrete endpoints/params/forms (incl. **API routes parsed from the JS bundle** — see W2.2)
  - `value_map`: where the value is (admin, billing, reseller API, auth) — AI-reasoned from the business context
  - `recommended_strategy`: which vuln classes are plausible vs. impossible (e.g. "static SPA apex ⇒ no server SQLi; pivot to authenticated API IDOR/BOLA")
- **W2.2 JS-bundle ingestion** — fetch + (optionally Playwright-render) the SPA, extract API base URLs, route tables, and embedded keys/endpoints. *Reuses* `output_parser._generic` URL/param extraction; add a JS-aware extractor.
- **W2.3 Strategy injection** — the Target Model is injected into every downstream agent prompt (exploitation, objectives) so the AI stops attacking impossible surfaces. Replaces today's generic syntax guide as the strategic spine.
- **W2.4 Subdomain triage** — rank discovered subdomains by likely value (`resellerapi`, `control`, `dash` > `cdn`, `status`) and feed the ranking to exploitation instead of scanning all equally.

**New/changed files:** `intelligence/target_profiler.py` (new), `agents/recon_agent.py` (call after recon), `agents/exploitation_agent.py` (consume model), `core/result_contracts.py` (TargetModel dataclass).
**Acceptance:** for novalink, the model must output `target_type=spa/api`, list ≥3 API subdomains as primary surface, and mark apex SQLi as "implausible". **Effort L.**

---

## WS3 — Authenticated & App-Aware Testing  *(the capability that finds real bugs)* — ✅ SHIPPED 2026-06-13
**Problem:** zero ability to log in, hold a session, or drive a SPA. The entire modern attack surface is behind auth — the engine can't reach it. Playwright exists but only for WAF challenges.

**Status: shipped & unit-tested (12/12 in `tests/test_ws3_authz.py`).** W3.1 `core/app_session.py` (`AppSession`: cookie jar, bearer/JWT set+decode-claims, CSRF capture, login_form/login_json with token-lift, `clone_anonymous()` for the control arm; fixed a real `set_cookie(domain=None)` crash). W3.2 `core/browser_driver.py` (`BrowserDriver`: headless Chromium render capturing XHR/fetch → `api_endpoints`, `submit_login`; **degrades to a safe no-op when Playwright/chromium absent** — never crashes). W3.3/W3.5 uniform HITL model on `BaseAgent.request_hitl_authorization` (within standing ROE → autonomous; beyond → `session.hitl_approver` callback, else batch-mode safe-deny) + `acquire_auth_session` (login gated by `allow_exploitation`/`allow_brute_force`). W3.4 `intelligence/authz_tester.py` (`AuthzTester.test_bola` = same protected object served to another/anonymous identity; `test_idor` = neighbour id returns a different valid object — both inherently differential, proof_type=differential, ties to WS4); wired into exploitation via `_maybe_run_authz_tests` (fires once when the WS2 Target Model exposes id-bearing API routes and a session can be acquired). `EngagementSession` gained `credentials` + `hitl_approver` fields.

**Changes:**
- **W3.1 New module `core/app_session.py`** — a real HTTP session manager: cookie jar, bearer/JWT handling, CSRF token capture, auth header injection. All tool/curl requests can run "as authenticated".
- **W3.2 New module `core/browser_driver.py`** — first-class Playwright driver (reuse the chromium-finder already in `waf_ghost_engine.py:609`): render SPA, run app flows, capture XHR/fetch traffic → feeds API endpoints to the Target Model (W2.2).
- **W3.3 Auth acquisition** — uses operator-supplied credentials when given. If the AI wants to **self-register or log in** to the target and that exceeds the standing ROE, it **escalates through the HITL gate and asks the operator** (per principle 6) — no separate feature flag. On approval it performs login/signup (AI-driven: find the login endpoint, submit, detect success), captures the session, and switches to authenticated mode.
- **W3.4 Authenticated capabilities** — register new capabilities in `core/capability_registry.py`: `authenticated_request`, `api_probe`, `idor_test`, `bola_test` (object-level auth: request another id, compare). These are the bug classes that actually exist on SaaS. Each respects the standing ROE; anything beyond it routes through the HITL gate.
- **W3.5 ROE/safety (uniform model)** — reuse the existing HITL escalation (`WafAttackAuthorizationRequired` → `[HITL GATE]`) for *every* sensitive auth action: live-account credential attempts require `allow_brute_force` already set, or an explicit HITL approval; out-of-scope or destructive auth actions are blocked unless the standing ROE covers them or the operator approves at the prompt. No new on/off flags are introduced — the operator's start-of-engagement ROE plus real-time HITL prompts are the whole policy.

**New files:** `core/app_session.py`, `core/browser_driver.py`, `agents/specialists.py` (add API/IDOR specialist).
**Acceptance:** against a test SaaS, the engine logs in, captures a session, lists ≥1 authenticated API endpoint, and runs an IDOR differential. **Effort L (largest item).**

---

## WS4 — Proof-Driven Validation (controls as the core) — ✅ SHIPPED 2026-06-13
**Problem:** "confirmed" came from a generic 200. No control experiment.

**Status: shipped & unit-tested (7/7 in `tests/test_evidence_gate.py`).** `Evidence` contract added to `core/result_contracts.py` (proof_type=differential|artifact|oob|none, request/response/baseline excerpts, differential text, similarity, `is_proven()`). `hypothesis_engine.validate_result` now: (W4.1) asks the AI for `proof_type`+`differential`, builds an `Evidence` object, and **fails a "confirmed" closed to a lead unless `evidence.is_proven()`** — i.e. a real differential (baseline similarity <0.97 with a described delta) OR a self-proving artifact/OOB; the no-baseline case is covered too (proof_type none ⇒ downgrade). (W4.2) confirmed findings persist the structured evidence object via `_persist_evidence` → `{eid}:evidence_objects` for reporting; finding detail now tags `Proof[<type>]`. (W4.3) `_cap_severity_by_proof` caps the AI's claimed severity by demonstrated impact — a bare reflection/length-delta differential is capped at medium; only data-extraction/RCE/auth-bypass/artifact keeps high/critical. **Acceptance MET:** a "200==baseline" can never reach confirmed; a real data-leaking differential can.

**Original change list (for reference):**
- **W4.1** Make the **differential mandatory** in `hypothesis_engine.validate_result`: every confirm must carry `(control_request, control_response)` + `(test_request, test_response)` and an explicit *observable delta*. No delta ⇒ inconclusive. (The 97%-similarity guard I added is the seed; promote it to a required contract.)
- **W4.2 Evidence objects** — `confirmed_vulnerability` findings must store the reproducible PoC (request/response pair, or a runnable script that re-derives the delta). Reporting reads these, not free text.
- **W4.3 Severity from impact, not keywords** — severity assigned only from demonstrated impact (data read, auth bypassed, RCE), computed in `intelligence/finding_scorer.py`. Generic-keyword matches stay INFO leads.

**Files:** `intelligence/hypothesis_engine.py`, `intelligence/finding_scorer.py`, `agents/reporting_agent.py`, `core/result_contracts.py`.
**Acceptance:** a synthetic "200 == baseline" can never reach `confirmed`; a real reflected-value-with-execution can. **Effort M.**

---

## WS5 — Objective-Driven Orchestration — ✅ SHIPPED 2026-06-13 (W5.1/W5.3/W5.4; W5.2 light)
**Problem:** fixed `planning→recon→exploitation→…` waterfall with loop counters; tool-centric not objective-centric.

**Status: shipped & unit-tested (11/11 in `tests/test_objective_ledger.py`).** `intelligence/objective_ledger.py` (`ObjectiveLedger`): W5.1 explicit win conditions (authenticated_access, object_authz_bug, sensitive_data, rce, admin_access) tailored to the WS2 Target Model (e.g. RCE auto-abandoned on a static SPA; object-authz elevated to primary on api/spa); `update_from_findings` advances an objective only on a confirmed/high finding whose markers match (evidence-driven, can't be fooled by activity). W5.3 `momentum()` promotes the old hint to an objective-aware directive (names the unmet objective to pivot to). W5.4 `should_stop()` stops on all-primaries-resolved OR genuine idle-streak exhaustion — not MIN/MAX loops. Wired into the exploitation loop (ledger updated each loop, `format_for_prompt` injected, objective-stop checked past min loops). **W5.2 (orchestrator phase-revisit) — ✅ DONE 2026-06-13.** The orchestrator now supports a true chevron: `BaseAgent.request_phase_revisit(phase, reason)` sets a bounded signal; `Orchestrator._maybe_requeue_for_revisit` (called after each phase) consumes it once, re-queues the loop-back phase + its dependents at the front of `task_queue`, and is hard-capped via `MAX_PHASE_REVISITS` (default 1) to prevent loops. Exploitation triggers it (`_maybe_request_revisit`) when ≥2 new in-scope hosts surface that recon never covered. Tested in `tests/test_remaining_items.py`. **Acceptance MET.**

**Changes:**
- **W5.1 Objective ledger** — define concrete objectives (gain access, read other-tenant data, reach admin, prove RCE). Each action is scored by *expected progress toward an objective*.
- **W5.2 Adaptive phase control** — `core/orchestrator.py` may revisit recon from exploitation when the Target Model shifts (e.g., new auth surface found), instead of a one-way chevron.
- **W5.3 Momentum/abandon** — extend the existing `_momentum_line` so dead threads are dropped and live ones doubled-down (promote from hint to controller).
- **W5.4 Stop conditions** — stop on objective completion or genuine exhaustion, not MIN/MAX loop counts.

**Files:** `core/orchestrator.py`, `agents/base_agent.py`, `intelligence/strategic_advisor.py`.
**Acceptance:** on a target with an obvious authed surface, the engine pivots into authenticated API testing without exhausting unauth scans first. **Effort L.**

---

## WS6 — WAF / Evasion v2  *(requested upgrades)*
The subsystem is rich (`waf_ghost_engine`, `waf_fingerprinter`, `waf_evasion_engine`, `waf_bypass_orchestrator`, `waf_learner`, + `waf_bypass/{origin_discovery,request_smuggler,oob_exfil_engine,hardcore_evasion,credential_finder,waf_attacker}`). It's **mis-triggered and under-wired**, not missing. Upgrades:

- ✅ **W6.1 Kill WAF false positives** (shipped 2026-06-13) — `_calculate_confidence` now requires a *strong* corroborating signal (payload blocking OR a WAF-specific response header) before WAF presence can clear the assertion threshold; path-level 403s / timing noise are capped at 0.2. The connection-error-as-block bugs in `_detect_method_blocking`/`_detect_payload_blocking` were removed (connection failure ≠ block), and `_detect_blocking_codes` no longer fabricates a default `[403,429]`. The recon assertion gate was raised from `confidence > 0.3 OR any signal` to `confidence >= 0.5`. *File:* `intelligence/waf_fingerprinter.py`, `agents/recon_agent.py`.
- **W6.2 Tool-aware mutation profiles** — generalize the whatweb fix: the Ghost Engine must apply HTTP-header/payload mutations **only** to tools that accept them, with a per-tool profile (curl/wget/nuclei/ffuf/gobuster/sqlmap/whatweb/nikto), and validate the transformed command is shell-valid before returning. *File:* `core/waf_ghost_engine.py`. **Effort M.**
- **W6.3 Origin discovery wired in** — `waf_bypass/origin_discovery.py` exists but isn't driving strategy. novalink is Cloudflare(NS/MX)→Vercel; finding the **origin IP** bypasses the CDN/WAF entirely. Wire origin discovery into recon + the bypass orchestrator and prefer origin when found. *File:* `intelligence/waf_bypass_orchestrator.py`, `agents/recon_agent.py`. **Effort M.**
- ✅ **W6.4 Adaptive calibration fix** (shipped 2026-06-13, combined with W6.7) — see W6.7. Calibration now rises/falls strictly on *measured* blocks; with `block_rate=0.00` and no force, `transform()` is a no-op.
- **W6.5 Real bypass validation** — a "WAF bypass" must show **blocked control → allowed test** (differential, ties to WS4), not a 200. *File:* `intelligence/waf_bypass_orchestrator.py`. **Effort S.**
- **W6.6 New evasion upgrades to ADD:**
  - **TLS/JA3 + HTTP/2 fingerprint randomization** so the *client* isn't fingerprinted by the WAF (`curl-impersonate`/utls-style). New `intelligence/waf_bypass/tls_fingerprint.py`.
  - **HTTP request smuggling / desync** — `request_smuggler.py` exists; wire it as a first-class tactic with safe detection (CL.TE/TE.CL). Detection runs within standing ROE; any *actively destructive* smuggling escalates through the same HITL gate the WAF attack module already uses.
  - **Cache deception / poisoning probe** — novalink served `x-vercel-cache: HIT`; add a CDN-cache deception detector (new tactic in `waf_evasion_engine.py`).
  - **Browser-origin requests** — route requests through the W3.2 Playwright driver so traffic looks like a real user (strongest evasion of behavioral WAFs).
  - **Per-vendor learned tactic profiles** — `waf_learner` should keep per-WAF-vendor (Cloudflare/Akamai/AWS) effectiveness, learned not hardcoded.
- ✅ **W6.7 Evasion only when warranted** (shipped 2026-06-13) — `WafGhostEngine.transform()` is now **reactive by default**: with zero observed blocks for a (target, tool) and no `force=True`, it returns the command UNCHANGED (no header/payload mutation, no throttle). Evasion engages only after a real block is recorded via `feedback()` (block_rate > 0), or when a caller that just saw a confirmed block passes `force=True` (the post-block paths in `tool_manager.py` and `base_agent.py`). The proactive `waf_present` path stays `force=False`, so even a (now much rarer, post-W6.1) WAF detection no longer mutates the *first* request — it goes clean and only escalates if actually blocked. This removes the self-inflicted slowdown and the tool-breakage class entirely on WAF-less targets. *File:* `core/waf_ghost_engine.py` (+ `tools/tool_manager.py`, `agents/base_agent.py` force flags; tests updated).

**Acceptance:** no WAF asserted on a WAF-less target; on a real CDN target the engine attempts origin discovery and only claims bypass with a control differential.

**WS6 remainder status (shipped 2026-06-13, 5/5 in `tests/test_ws6_evasion.py`):**
- ✅ **W6.2** tool-aware mutation profiles already existed per-tool; added the missing **shell-validity guard** — `transform()` now `shlex.split`-validates the mutated command and falls back to the original if a mutation produced an unparseable line (kills the "mutation breaks the tool → wasted repair" class).
- ✅ **W6.5** real bypass validation — `WafBypassOrchestrator._validate_bypass_differential` sends a known-bad probe on the normal path (control) vs. the bypass (test) and only keeps `success=True` when control is BLOCKED and test is ALLOWED; otherwise downgrades to `success=False` + `unverified_reason`. Also fixed a latent `self.log` AttributeError in the orchestrator. Origin-IP bypasses preserve the Host header in the test request.
- ✅ **W6.3** — DONE (2026-06-13). Recon now runs `OriginDiscovery` when a CDN/WAF is detected, tests each candidate with `test_origin_connection`, and on a viable origin sets `waf_bypass_url=https://<origin_ip>/` + `origin_ip` in the bundle + an `origin_ip_discovered` HIGH finding, so exploitation retargets to the origin (skips the edge entirely). *File:* `agents/recon_agent.py`.
- ✅ **W6.6** — DONE (2026-06-13). All three net-new modules shipped + the BrowserDriver browser-origin path:
  - **W6.6a TLS/JA3** `intelligence/waf_bypass/tls_fingerprint.py` (`TlsFingerprintEvasion`): rewrites `curl` onto a `curl-impersonate` binary or uses `curl_cffi` for a real browser JA3/HTTP-2 handshake; wired into `waf_ghost_engine` curl branch at level≥3; safe no-op when tooling absent.
  - **W6.6b request smuggling** — `_execute_smuggling_bypass` is now first-class: CL.TE/TE.CL/TE.TE/H2 **detection runs within ROE**, but the destructive desync **escalates through the HITL gate** (`WafAttackAuthorizationRequired`) unless `authorized_attack`.
  - **W6.6c cache deception/poisoning** `intelligence/waf_bypass/cache_deception.py` (`CacheDeceptionProbe`): non-destructive static-suffix deception probe + unkeyed-header (X-Forwarded-Host) poisoning probe with a benign canary, both differential-judged; wired into exploitation (`_maybe_run_cache_probes`, fires once when a CDN is present) producing differential-proven findings.
  - Tested: `tests/test_remaining_items.py` (11).

---

## WS7 — Evidence & Reporting Integrity — ✅ SHIPPED 2026-06-13 (7/7 in `tests/test_ws7_reporting.py`)
**Status:** in `agents/reporting_agent.py`: W7.1 `_split_two_tier` separates PROVEN vulnerabilities (`confirmed_vulnerability` / VULN_PROVEN — these only exist after the WS4 evidence gate or WS3 authz differential) from unverified leads; the executive-summary headline counts and risk rating now reflect **proven only**, leads are described as "areas warranting manual testing" and never inflate risk. W7.2 `_engagement_verdict` returns COMPROMISED / PARTIAL / NOT COMPROMISED from the proven set + the persisted objective ledger (cites achieved objectives) — honest outcome, not "tools ran". W7.3 `_export_pocs` writes `poc_export.json` + `poc_export.md` with a reproducible command + request/response/differential per proven vuln (from the WS4 `:evidence_objects`), with a finding-detail fallback. Exploitation persists the ledger snapshot for the verdict.

### Original WS7 spec (reference)
**Problem:** report counted attempts as vulns; "92 logged" with 0 real; SUCCESS while empty.

**Changes:**
- **W7.1 Two-tier findings** — `lead` (unverified) vs `vulnerability` (proven w/ PoC). Only the latter counts in severity tables and the executive summary. *File:* `intelligence/finding_scorer.py`, `agents/reporting_agent.py`.
- **W7.2 Honest engagement verdict** — phase/engagement status reflects *objective outcome* (access gained? impact proven?), not "tools ran". *File:* `core/orchestrator.py`, `agents/reporting_agent.py`.
- **W7.3 Reproducible PoC export** — each vuln ships a runnable PoC + request/response evidence (from WS4).
**Effort M.**

---

## WS8 — Operational Self-Model
**Problem:** believed its own Tor proxy = target honeypot.

**Changes:**
- ✅ **W8.1 Ops sanity layer** (shipped 2026-06-13) — `SelfAwarenessModule.ops_sanity_check(conclusion, ops_context)` is the centralized reality-check backstop. It cross-checks an exotic conclusion against live ops facts and returns `{plausible, confidence_cap, reasons}`: (1) ≥1000 "open" ports via proxy/connect-scan ⇒ CONNECT artifact, cap 0.1; (2) a bypass/vuln/"confirmed" whose response is ≥97% identical to the control baseline ⇒ no differential, cap 0.1; (3) host-level claims (crontab/shell/root/persistence) when the command ran on the local box / no target foothold ⇒ describes OUR host, cap 0.1. Detected artifacts are logged as contradictions. Generalizes the three inline guards (honeypot banner-corroboration, hypothesis differential guard, persistence foothold gate) into one reusable gate. *File:* `intelligence/self_awareness_module.py`.
- ✅ **W8.2 Reality checks** — DONE (2026-06-13): `ops_sanity_check` is wired into `BaseAgent.add_finding` via `_ops_sanity_backstop` — every high/critical finding is auto-checked and self-fooling host-level claims (no foothold) are demoted to a lead. *File:* `agents/base_agent.py`.
**Effort S–M.**

---

## Phased rollout (sequenced by dependency & leverage)

**Phase 0 — Stabilize (days):** WS1.1–1.4 + WS6.1/6.4/6.7 + WS8.1. *Stops self-sabotage; makes runs fast and honest.* Low risk, mostly done.

**Phase 1 — See the target (1–2 wks):** WS2 (Target Comprehension) + WS6.3 (origin discovery) + WS7.1 (two-tier findings). *Engine finally understands what it's attacking and reports honestly.*

**Phase 2 — Get inside (2–4 wks):** WS3 (auth/app-aware) + WS4 (proof-by-control) + WS6.2/6.5/6.6. *The capability leap — can reach and prove real bugs.* Largest, highest payoff.

**Phase 3 — Operate (2–3 wks):** WS5 (objective-driven orchestration) + WS6.6 advanced evasion + WS7.2/7.3. *Behaves like an operator, not a pipeline.*

Dependencies: WS3/WS5 depend on WS2 (need the target model). WS6.5 depends on WS4 (differential). WS7 depends on WS4.

---

## How we'll know it actually works (acceptance for the whole thing)
Re-run vs an **authorized** SaaS target and require:
1. Target Model correctly classifies it (type, stack, primary API surface) in < 10 min.
2. Engine authenticates and tests the authenticated surface.
3. Any "vulnerability" in the report carries a reproducible control→test differential PoC.
4. No fabricated findings; INFO noise not counted as vulns; honest verdict.
5. Command-failure rate < 10%; no false honeypot/WAF; engagement < 45 min for a small target.

## Risks
- **Auth/app-aware testing follows the canonical ROE model** (principle 6): allowed only if the operator's standing ROE covers it, otherwise the AI escalates through the existing HITL gate and asks the operator in real time — reusing `WafAttackAuthorizationRequired`/`[HITL GATE]`, not new flags. No logging in / registering / credential attempts without either standing ROE or an explicit prompt approval.
- Browser automation adds runtime weight — cache renders; only spin up Playwright when the Target Model says the surface needs it.
- Token budget: Target Model + two-pass grounding add AI calls; WS1.2 budget control must land first.
