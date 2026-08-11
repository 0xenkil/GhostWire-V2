# GhostWire V7 — Master Remediation Plan

*Lead-architect synthesis of six dimension designs + their adversarial critiques into one prioritized, dependency-ordered program. Plan only — no code is changed here. Every file/function reference below was cross-checked against the live tree at `red team/`; the linchpin claim (`Evidence.is_proven()` is forgeable) was re-verified directly at `core/result_contracts.py:660-666`.*

***Version 1.1 (completeness closure).*** *v1.0 was strong on the false-victory chain but incomplete against the full defect inventory. v1.1 closes every gap the adversarial completeness audit (Appendix D) found: the two dependencies the proof spine silently rested on — **STATE-1** (silent write-loss) and **PARSER-1/2/3 + SANITIZE-1** (parse fidelity) — are promoted to hard Phase-0 prerequisites (P0-0a/P0-0b); all 12 orphan defect IDs are assigned to phases; every contract risk is resolved. See **§9 Completeness closure** for the full amendment set; Appendix D is now a historical record with each item marked CLOSED in §9.*

---

## 1. Executive summary

GhostWire V7 already *computes* almost everything it needs to be honest and autonomous — a measured control-vs-test differential (`Evidence`), its own privilege/egress/budget state (`raw_socket`, `_tor_verified`, phase token budget), and its own tool runs. It then throws that ground truth away and re-derives trust from **emitter-writable substrings** (`"VULN_PROVEN"`, `"header_mutation"`), **bare exit codes** (`exit-0 + non-empty == success`), and **advisory prompt text** the model is free to ignore. That single mistake — *asserted* truth standing in for *measured* truth — is the root of every headline failure: false "COMPROMISED / N proven" reports, the 86-deep Tor evasion cascade, the privilege death-spiral, the budget starvation, and the learners that compound toward activity instead of impact.

**The one spine.** Route *every* trust decision through two deterministic seams that consume ground truth the engine already has:

1. **Evidence-first trust.** "Proven" becomes a property of a **non-forgeable, re-measured `Evidence` object** resolved from a per-engagement **proof ledger**, never of a string an emitter can write. A capability-keyed **proof-method registry** mints Evidence only from a measured differential.
2. **Deterministic self-knowledge gates.** Accurate self-knowledge (root path, raw-socket capability, Tor egress health, remaining token budget, remediation intent) becomes **pre-execution gates that can say "no" and are obeyed** — not sentences in a prompt.

**Why this makes the tool MORE autonomous and LESS hardcoded, not less.** The cure is *deletion + one thin seam*, never *more advice or more LLM passes*:

- It **deletes** the guardian's ~47-name tool allowlist, the exploit/weaponization keyword→severity tables, `EvidenceRouter`'s per-tech routing dict, `_WAF_EXEMPT_TOOLS`, the reactive `-sS→-sT` downgrade, and ~1,500 LOC of dead "intelligence." Every deleted list is a hardcoding violation, so cutting it is a feature.
- It **gates on capability + evidence, never tool identity.** New tools, vuln-proof types, WAF techniques, and LLM backends slot in via `register()` / a JSON row / a `Protocol` impl — with zero core edits.
- It **reduces human-in-the-loop and LLM round-trips.** The engine self-escalates privilege instead of asking the model to guess flags; it self-diagnoses "my own Tor exit is blocked" instead of firing 86 useless evasions; it sheds the self-correction stack when the backend is starving instead of sleeping an event-loop thread for an hour until a human kills it.

**Core insight:** the fix is a *deterministic enforcement seam consuming ground truth the engine already computes*, plus the *deletion of brittle signature/allowlist code*. More LLM calls worsen the budget-starvation pathology; the plan therefore adds **zero** net LLM passes and removes several.

**The single most important correction the critics forced (and I adopted as a hard override):** the design's foundation was **not actually non-forgeable**. `Evidence.is_proven()` returns `True` unconditionally for `proof_type in ('artifact','oob')` and, for `'differential'`, passes on the unmeasured `similarity_to_baseline < 0` default. And the designs hand-constructed `Evidence(...)` at emit sites, relocating forgery from a substring to a dataclass field. **Phase 0 therefore begins by hardening `is_proven()` to require a persisted measurement per proof type, and by making `ProofLedger.stamp(method, ctx)` the sole constructor of Evidence.** Without that, the entire spine is bypassable. This is the difference between the plan working and shipping a rename of the same bug.

---

## 2. Design principles / invariants (every change obeys these)

1. **Proof is measured, never asserted.** `is_proven()` re-derives from a persisted differential (similarity, canary-present-in-test-and-absent-in-control, or a verifiable OOB token). An emitter can write text; it cannot write a measurement.
2. **Single writer, many readers.** The `ProofLedger` is the only place Evidence is stored, and only after a *re-measured* `is_proven()` returns True. Every trust consumer is a read-only, deterministic `finding_is_proven()` lookup.
3. **Gate on capability + evidence, never tool identity.** No tool allowlist, no per-tool signature table, no static CVE table, no per-target/tech assumption. The only surviving identity list is a short **destructive-verb RUN denylist**, which cannot cap which useful tools the AI may adopt.
4. **Delete brittle code over adding advice.** Every change removes a substring/severity/allowlist branch or converts it into a control-vs-test measurement. No new signature tables.
5. **Deterministic gates, not prompt text.** A privilege/egress/budget/convergence check must be able to return "no" and be obeyed by control flow — never injected as advisory text the model can override.
6. **Fewer LLM round-trips under stress.** Net zero new LLM passes across the whole program; several removed. Self-correction sheds to existing deterministic classifiers when the backend is starving.
7. **Fail-closed on anonymity and on missing measurement.** Requested stealth that cannot be honored blocks loudly; a proof method that cannot measure returns `None` and degrades to an *unproven lead*, never a confirmed finding.
8. **Atomic-or-nothing persistence.** Every learning/ledger write uses temp-file + `os.replace` or the state-store single-writer queue; no truncate-write, no KV read-modify-write race.
9. **Provide capability, do not forbid it.** When the environment can escalate, the gate routes through the real root path rather than downgrading — but never regresses graceful degradation (an unprivileged box still gets a connect scan).
10. **Observability precedes cleverness.** You cannot attribute a failure you never recorded; structured failure records are the substrate for plausibility and convergence, not an afterthought.
11. **Extension via registry/`Protocol`, never by editing core.** New capability = register a proof method / WAF technique / tool row / backend, never touch `base_agent`/`orchestrator`.

---

## 3. New core contracts / interfaces

> All signatures are the *reconciled* forms after folding in critic overrides. Home paths are live modules verified present.

### 3.1 Hardened Evidence + proof-method registry (the spine)

`core/result_contracts.py` — **harden the existing `Evidence`** (drop the "reuse unchanged" constraint):

```python
@dataclass
class Evidence:
    proof_type: str = "none"          # differential | artifact | oob | none
    reproducible_command: str = ""
    request: str = ""; response_excerpt: str = ""; baseline_excerpt: str = ""
    differential: str = ""
    similarity_to_baseline: float = -1.0
    # NEW persisted measurement fields (survive to_dict/from_dict):
    control_absent: bool = False      # artifact: token NOT in control
    test_present: bool = False        # artifact: token IS in test
    oob_token: str = ""               # oob: verifiable callback id
    notes: str = ""

    def is_proven(self) -> bool:
        if self.proof_type == "differential":
            # MEASURED only: reject the unmeasured (-1) escape hatch
            return bool(self.differential) and 0.0 <= self.similarity_to_baseline < 0.97
        if self.proof_type == "artifact":
            return self.control_absent and self.test_present
        if self.proof_type == "oob":
            return bool(self.oob_token)
        return False
```

`core/proof.py` (**NEW** — the one deterministic seam):

```python
@dataclass
class ProofContext:                    # measured inputs a method reasons over
    control_response: str = ""; test_response: str = ""
    control_latency: float = -1.0; test_latency: float = -1.0
    oob_events: list = field(default_factory=list)
    canary: str = ""; command: str = ""; notes: str = ""

ProofMethod = Callable[[ProofContext], Optional[Evidence]]

class ProofRegistry:
    @classmethod
    def register(cls, name: str, fn: ProofMethod) -> None: ...
    @classmethod
    def build(cls, method: str, ctx: ProofContext) -> Optional[Evidence]: ...
    # built-ins registered at import: differential, artifact_reflection, oob_callback, time_delta

class ProofLedger:                     # SOLE writer of proof state
    def __init__(self, store, engagement_id): ...
    def stamp(self, method: str, ctx: ProofContext) -> str:
        """Build Evidence via ProofRegistry.build; persist + return 16-hex id
        ONLY if Evidence.is_proven(); else ''. stamp is the ONLY constructor
        callers may reach — no pre-built Evidence is ever accepted."""
    def get(self, evidence_id: str) -> Optional[Evidence]: ...
    def is_proven(self, evidence_id: str) -> bool:   # re-instantiate + recompute

PROOF_TOKEN_RE = re.compile(r'\[proof:([0-9a-f]{16})\]')
def extract_proof_id(detail: Optional[str]) -> str: ...          # None-safe → ''
def finding_is_proven(finding: dict, ledger: ProofLedger) -> bool:
    """THE one gate every consumer calls: extract token → resolve → recompute."""
```

**Persistence (critic override):** the ledger is its own findings-style table with `INSERT OR IGNORE` on `evidence_id`, written through `state_store`'s single-writer queue — **not** a KV read-modify-write map (which lost-updates under `ThreadPoolExecutor(10)`). It also appends to `{eng}:evidence_objects` atomically so `reporting._export_pocs` keeps working.

`agents/base_agent.py`:

```python
def add_finding(self, ftype, target, detail, severity, *,
                proof_method: str = None, proof_ctx: ProofContext = None): ...
    # if proof_method: eid = self._proof_ledger.stamp(proof_method, proof_ctx)
    #   if eid: detail = f'[proof:{eid}] ' + detail   (BEFORE _validate_severity + dedup)
    # NO evidence= param that accepts a pre-built object — closes the hand-forge hole
```

### 3.2 Honest success signal (recon-side analogue of proof)

`core/result_contracts.py`:

```python
class ToolResult:
    def produced_result(self, capability: str) -> bool:
        """Capability-keyed result-presence predicate, derived from PARSED fields,
        not a per-tool table. scanner→open_ports/findings non-empty;
        fetch→GOT A RESPONSE (distinct from 'differs from baseline'); discovery→
        non-empty parsed list. 'fetch succeeded' and 'fetch differs' are separate."""
```

### 3.3 `enforce_capability` self-knowledge seam

`agents/base_agent.py`:

```python
@dataclass
class CapabilityDecision:
    command: str; action: Literal['allow','escalate','rewrite','reject','connect_fallback']
    requires_root: bool; reason: str

def enforce_capability(self, tool, command, caps) -> CapabilityDecision: ...  # pure, no LLM, no per-tool table
def _command_intent_key(self, command, target) -> str: ...  # THE unified key (see 3.6)
def _probe_capabilities(self) -> dict:  # returns {uid, root, raw_socket,
                                        # raw_socket_via_root, root_path_available, probe_ok}
```

### 3.4 Unified `ToolCatalog` + safe install

`core/tool_catalog.py` (**NEW**):

```python
@dataclass
class ToolEntry:
    name: str; binary: str; capabilities: list[str]
    install_cmds: dict[str,str]; run_timeout: int = 120; install_timeout: int = 300
    category: str = 'utility'; risk: str = 'low'; sha256: str = ''
    source: str = 'builtin'; description: str = ''
    # installed is a per-session MEASURED flag, held in memory, NEVER persisted

class ToolCatalog:
    def register(self, entry, *, persist=True) -> ToolEntry: ...   # persists DURABLE data only
    def get(self, name_or_binary) -> ToolEntry | None: ...
    def resolve(self, capability, risk_cap=None, destructive_allowed=False) -> ToolEntry | None: ...
    def all_binaries(self) -> frozenset[str]: ...
    def install_method(self, entry, os_family, arch) -> str: ...
    def is_installed(self, binary) -> bool: ...     # re-probes per node/session
```

`core/provisioning_policy.py` (**NEW**, shared by guardian + installer):

```python
INSTALL_DENY: frozenset[str]   # never PROVISION (dd, mkfs, meterpreter, ...)
RUN_DENY: frozenset[str]       # never EXEC — SHORT, destructive verbs only
                               # (mkfs, fdisk, reboot, halt, userdel, dd-to-block-device)
TRUSTED_INSTALL_SOURCES: list[str]
def is_run_blocked(binary) -> bool; def is_install_blocked(binary) -> bool
```

### 3.5 Learning-from-proof contract

`intelligence/learning_signal.py` (**NEW**):

```python
@dataclass(frozen=True)
class LearningOutcome:
    tool: str; target_type: str = 'generic'; evasion_tactic: Optional[str] = None
    duration: float = 0.0; waf_blocked: bool = False
    proof: Optional[Evidence] = None
    _raw_status: str = ''; _output: str = ''; _produced_result: bool = True
    @property
    def proven(self) -> bool:
        if self.proof is not None: return self.proof.is_proven()   # real proof path
        # fallback (honest, NOT called 'proven' to the user): executed cleanly AND
        # produced an actionable result AND not waf_blocked AND no hard-fail marker
        return (self._raw_status in {'success','partial','partial_success'}
                and self._produced_result and not self.waf_blocked
                and not looks_like_failure(self._output))

HARD_FAIL_MARKERS: tuple[str, ...]      # single shared source (syntax_learner imports it)
def looks_like_failure(text: str) -> bool
```

`intelligence/truth_gate.py` (**NEW**):

```python
class TruthGate:
    def __init__(self, proven_outcomes: list[LearningOutcome]): ...
    def supports(self, change: dict, min_proven: int = 3) -> bool:
        """A persistent self-upgrade is admitted ONLY if backed by >= min_proven
        PROVEN outcomes whose proven success-rate on a held-out slice does not
        regress. If it cannot be evaluated → False (stay dry-run)."""
```

### 3.6 Unified intent key + de-poisoned verdict cache

One normalization function is the key for the failure-reject window, cycle detection, the outcome-verdict cache, **and** the convergence ledger — folding self-knowledge `_command_intent_key` (DEDUP-1), convergence `_remediation_intent` (C3), and the existing per-`cmd_hash` evasion breaker into one authority:

```python
def _command_intent_key(command, target) -> str:
    # f"{primary_tool}|{host}|{sorted(significant_flag_names)}"
    # STRIPS: wrapper (proxychains4/sudo/env), flag VALUES, volatile flags
    #         (-o*/-v*/timeout/silent), AND evasion mutations injected by the
    #         WAF loop (proxychains prefix, rotated UA/header flags, delay args).
    # This last point is why the old per-cmd_hash breaker never tripped.
```

### 3.7 Egress-causality probe

`core/egress_probe.py` (**NEW**): `EgressProbe.classify(target_host, egress_fingerprint) -> Literal['self_egress','target','unknown']`, using a **diverse control set that includes at least one CDN/WAF-fronted endpoint**, majority vote, fail-to-`unknown`. `tools/tool_manager.py::attribute_block(result, tool, command, went_through_tor)` — attribution is conditioned on whether *this command actually traversed Tor* (raw-socket/direct tools attribute to target). Fingerprint captured at exec time.

### 3.8 Budget + backend resilience

`core/ai_backend.py`:

```python
@dataclass(frozen=True)
class BudgetSnapshot:
    backends_live: bool; recovery_seconds: int | None; phase_tokens_left: int | None
    def can_spawn(self, kind: str) -> bool: ...   # triage > repair > grounding/mentor
class BackendExhausted(RuntimeError):             # subclasses RuntimeError → existing catches hold
    recovery_seconds: int | None
def remaining(self, phase='', max_tokens=None) -> BudgetSnapshot:
    """Built ON TOP of the EXISTING is_phase_budget_exhausted(); ONE budget
    authority. max_tokens MUST be _phase_token_budget(), never _phase_budget_total
    (that is wall-clock seconds)."""
```

### 3.9 Observability + future-proof extension interfaces

- `core/failure_record.py` (**NEW**): `FailureRecord` + `record_failure()` + `observe(...)` context manager, **folded into the existing failures table** (reuse `get_cross_engagement_failures` schema), with per-engagement cap and a self-safe recorder (never raises into the wrapped op).
- `intelligence/waf_bypass/technique.py`: `class WafTechnique(Protocol): name; def run(target, ctx) -> Evidence | None`.
- `tools/tool_catalog.ToolCatalog` (§3.4) is itself the tool extension point.
- `core/llm_backend.py` (**NEW**): `class LLMBackend(Protocol): name; def query(...) -> LLMResult; def token_budget() -> int`.
- `core/config_loader.ConfigManager` gains attribute views (`cfg.timeout.tool_default`, `cfg.vps.use_remote_vps`) with explicit precedence **env > YAML > module default**; the clashing no-arg `get_config` (`config_manager.MockConfig`) is retired.

---

## 4. Phased roadmap (dependency order)

> Effort: S/M/L/XL. Risk: Low/Med/High. Each phase lists prerequisites that must land first.
>
> **v1.1 amendments:** Phase 0 below now opens with prerequisites **P0-0a/P0-0b** (STATE-1 durability + parser/sanitize fidelity). Additional changes assigned to Phases 2/4/5 by the completeness closure (**P2-5, P4-6, P4-7, P5-9…P5-13**) are fully specified in **§9.5** and folded into the coverage matrix (§5) and §9.6; they are labelled "Amends Phase N" there rather than duplicated inline.

### Phase 0 — Evidence spine + honest success signal

**Goal:** make "proven" and "success" both *measured*; sever the false-victory chain `TOOLMGR-1 → EXPLOIT-EMIT-1 → OPSSANITY-BYPASS → OBJLEDGER-FALSE-WIN → REPORT-SPLIT-SUBSTR` at every link with one shared key. This is the phase that kills false "COMPROMISED / N proven" reports.

**Prerequisites:** none — but P0-0a/P0-0b below are the *internal* foundation and must land before the ledger (P0-2) and the honest success signal (P0-9) respectively. **(v1.1: these two were the dependencies the audit found the spine silently resting on; they are now blocking Phase-0 work, not assumed.)**

**Changes:**

- **P0-0a Durable state/ledger writes (STATE-1)** *(v1.1 — promoted prerequisite for P0-2)*. `core/state_store.py` single-writer queue: writes become **acknowledged** (the caller learns whether the row landed), a queue-put/commit timeout is **raised as an error, never silently dropped**, with a bounded retry, and the SQLite WAL is checkpointed on shutdown. Rationale: `ProofLedger.stamp()` and *every* learning write route through this queue — a silent drop here silently demotes a genuinely-proven finding (safe direction) but corrupts the trust guarantee the whole spine depends on. **Closes:** STATE-1. **Blast radius:** the state-store write path (already touched by P0-2's ledger table, so the edits co-locate). **Verify:** stall the writer → `stamp()` blocks/raises, never returns a fabricated id; kill-9 mid-write → WAL replay yields a consistent DB; 10-thread `stamp()` burst loses zero rows.
- **P0-0b Parse fidelity + CR-safe sanitize (PARSER-1/2/3, SANITIZE-1)** *(v1.1 — promoted prerequisite for P0-9)*. Fix the port/liveness/discovery parsers so parsed `open_ports`/hosts/lists are **faithful** (no silently dropped ports or live hosts), and fix `clean_text` so carriage-return tool output is **preserved** (parse the raw stream before sanitizing, or make `clean_text` CR-safe). Rationale: P0-9's `produced_result` derives success from these parsed fields — a dropped port makes a *real* scan read `NO_FINDINGS` (a false negative injected upstream), and a CR-mangled line makes a real result vanish. **Closes:** PARSER-1/2/3, SANITIZE-1. **Blast radius:** recon result parsing consumed by `produced_result` and the frontier. **Verify:** golden nmap/masscan/gobuster fixtures parse to the exact expected port/host/path sets; a CR-heavy progress-bar capture still yields its final result line; `produced_result` returns True for a scan with ≥1 real parsed port and False only when genuinely empty.
- **P0-1 Harden `Evidence.is_proven()` + persist the measurement** *(new, forced by evidence-spine & cleanup critics)*. `core/result_contracts.py:660-666` + `to_dict`/`from_dict`. Differential requires `0.0 <= similarity < 0.97`; artifact requires `control_absent and test_present`; oob requires `oob_token`. **Closes:** EVIDENCE-ISPROVEN-FORGEABLE.
- **P0-2 Add `core/proof.py`** — `ProofContext`, `ProofRegistry`, `ProofLedger` (own table via single-writer queue), `finding_is_proven`, 4 built-in methods. `ProofLedger.stamp(method, ctx)` is the **sole** Evidence constructor. Reuses `hypothesis_engine._response_similarity` for the differential method. **Closes:** the shared-key substrate.
- **P0-3 `add_finding` gains `proof_method`/`proof_ctx`; stamp token BEFORE `_validate_severity` and dedup; rewire `_ops_sanity_backstop` and `_validate_severity` off the substring** *(base_agent ~l.1200-1294)*. Delete the `"VULN_PROVEN"/"Proof["` ops-sanity exemption; replace `_validate_severity`'s `'vuln_proven:'/'confirmed' in detail` gate with `finding_is_proven`. Add `evidence_id` to the dedup key. **Closes:** SELFAWARE-OPSSANITY-BYPASS, VALIDATE-SEVERITY-SUBSTR (new), the token-durability/dedup-window gap.
- **P0-4 Plausibility gate `_plausible_handoff(recon_data)`** *(base_agent + exploitation_agent `_preflight` l.18)* reusing `tripwire_detector.prune_honeypot_ports`. This is also the explicit **pre-exploit result-quality gate**: empty/garbage recon (no plausible parsed target) yields **no handoff**, so exploitation never runs on garbage. **v1.1 bound on TRIPWIRE-1:** `prune_honeypot_ports` is used only to **lower confidence / flag `needs_confirmation`, never to hard-drop a port** — a honeypot-adjacent-but-real port still reaches exploitation and is settled by the Evidence differential (measurement is the final arbiter), so the pruner cannot silently kill a working exploitation path. **Closes:** DEEP-5, RC-6. **Bounds:** TRIPWIRE-1.
- **P0-5 exploitation_agent: delete the substring mint branches; route genuine paths through `stamp`** *(l.312-333 delete; l.919-959 & l.1019-1037 pass `proof_method='differential'/'artifact_reflection'` + ctx; confirm-gate l.2254-2274 → `finding_is_proven`)*. **Closes:** EXPLOIT-EMIT-1.
- **P0-6 weaponization_agent: delete `root:x:0`/`SQL syntax` proof elifs and the nuclei-confirmed promotion; stamp real proof; retag failed-PoC nuclei as `nuclei_lead`/info** *(l.470-492, l.536-550)*. **Closes:** WEAPON-SUBSTR-PROOF, WEAPON-NUCLEI-CONFIRM.
- **P0-7 objective_ledger proof-gated** *(l.88-107 + inject `proof_resolver` at exploitation l.1638-1646)*; drop the `severity in {high,critical}` inclusion. **Closes:** OBJLEDGER-FALSE-WIN.
- **P0-8 reporting `_split_two_tier` → `finding_is_proven`** *(l.612-632)*; keep the "unverified lead" belt-and-suspenders. **v1.1 (REPORT-1 broad):** route **every** finding-rendering path through `finding_is_proven`, not just the two-tier split — the exec-summary "N proven" count, the per-finding confirmed/lead label, and any severity roll-up all read the one gate, so no rendering path (not just the split) can launder a corrupted finding into the report. **Closes:** REPORT-SPLIT-SUBSTR, REPORT-1.
- **P0-9 Honest success signal `ToolResult.produced_result(capability)` at EVERY status-finalization site** *(critic override: not just one classifier — local exec l.1541/1545/1594, empty-stdout l.1674, file-fallback l.1789, remote-VPS l.1948-1962/2020-2030)*; delete the per-tool nmap-banner hack (l.1495-1516); **preserve** the whatweb/curl salvage carve-outs; separate "fetch succeeded" from "fetch differs." **Closes:** RC-SUCCESS-DEF, TOOLMGR-1.
- **P0-10 Tool-run→finding linkage** *(new, unblocks Phase 3)*: persist the originating `tool_run_id` on the finding row and have `state_store.get_tool_runs()` return the row id. Lands here because Phase 0 already touches the state-store schema for the ledger table. **Closes:** the Phase-3 join gap at the source.

**Autonomy / no-hardcode rationale:** all proof methods key on capability + measurement and are runtime-extensible via `ProofRegistry.register()`; `artifact_reflection` works for *any* leaked string (absent-in-control vs present-in-test), never a fixed list. The AI still chooses every attack — the seam only *measures* whether a control/test pair demonstrates impact, removing an LLM/human adjudication step. Zero new LLM passes.

**Verification/tests:** (a) `stamp('differential', ctx sim=0.4)` → 16-hex id, `finding_is_proven` True; forged `[proof:deadbeef…]` with no ledger row → False; artifact present in both control+test → not proven. (b) `add_finding(..., proof_method=None)` with `"VULN_PROVEN"` prose → lead, not exempt, severity capped. (c) reporting: `type=='confirmed_vulnerability'` + `'vuln_proven'` in detail but no ledger row → LEAD, verdict NOT COMPROMISED. (d) banner-only nmap `exit-0` at every finalization site → `NO_FINDINGS`; parsed-ports scan → success; PARTIAL (whatweb-behind-WAF) still success. (e) concurrency: 10 threads `stamp()` → no lost rows.

**Effort:** L. **Risk:** Med (base_agent is hot; new params default to None so existing calls keep correct "unproven-lead" semantics).

---

### Phase 1 — Deterministic self-knowledge gates

**Goal:** turn measured privilege/intent/verdict state into obeyed gates; stop the privilege death-spiral and the flag-churn loop.

**Prerequisites:** Phase 0 (the unified intent key is reused by Phase 4; nothing here needs proof, but landing after P0 keeps `base_agent` edits sequenced).

**Changes:**

- **P1-1 Dual-context capability probe** *(CAP-1, base_agent `_probe_capabilities` ~l.4906)*: run the SOCK_RAW test a second time via the existing `as_root` path; add `raw_socket_via_root`, `root_path_available`, and a `probe_ok` flag. **Critic override:** never cache a partial/empty caps dict as authoritative — distinguish "probe ran, no root" from "probe failed"; on failure retry-once or fall back to the advisory path, never a cached hard-reject.
- **P1-2 `enforce_capability` gate** *(CAP-2, base_agent + tool_manager)*: strip euid-inert `--privileged/--unprivileged`; if `raw_socket` allow; **else if `raw_socket_via_root`** *(override: escalate on the MEASURED root-raw capability, not the inferred `root_path_available`)* prepend `sudo` through the existing `tool_manager:1829` as_root path; **else `connect_fallback`** — **critic override: keep graceful degradation, fall back to `-sT` when no root path exists rather than `reject`** so unprivileged boxes still scan. Add the deterministic privilege-error evidence backstop (one as_root re-dispatch). Preserve the QUITTING-banner FAILURE suppression that the deleted `-sS→-sT` block provided. **Closes:** NEW-1, META-RC-0 (privilege), RC-3 (privilege loop).
- **P1-3 Delete the false advisory prose** *(PROSE-1, base_agent `_get_environment_snapshot` ~l.5022, `_ground_prescriptions` ~l.3942)* that forbids the working path; optionally replace with one truthful capability line. **Closes:** META-RC-0 residue.
- **P1-4 Unified intent key `_command_intent_key`** *(DEDUP-1 + convergence C3 merged, §3.6)* — **critic override: migrate ALL ~25 write sites and re-compute sites, not just the two reads**, or dedup/cycle detection silently disables. Retire the per-`cmd_hash` evasion breaker so there is one convergence authority. **Closes:** DEEP-8 (dedup half).
- **P1-5 De-poison the outcome-verdict cache** *(CACHE-1 + evidence-spine CH8/DEEP-8 merged — one edit to `_interpret_outcome` ~l.2115)*: key = `intent | status | exit_code | full_error_fingerprint` (collapse whitespace/digits over the *full* error, not a 160-char prefix); bound by **TTL + size**; add the lazy-init lock as cheap defense. **Critic override: DROP the "LLM re-verify after N reuses" — it re-introduces LLM calls into the starvation loop.** Convergence is achieved by the Phase-4 intent ledger instead. **Closes:** DEEP-8 (cache half).

**Autonomy / no-hardcode rationale:** every gate keys on a measured capability or a normalized intent, never a tool name or a literal token. The engine self-escalates and self-stops doomed loops — strictly *less* human babysitting. The only static artifact is a tiny generic raw-request regex used as a fast-path *hint*; the evidence backstop is tool-agnostic.

**Verification/tests:** `enforce_capability('nmap -sS --privileged', {raw_socket:False, raw_socket_via_root:True})` → escalate + sudo, `--privileged` stripped; `{root_path_available:False}` → `connect_fallback` yields a real `-sT` scan (not zero output); backstop fires exactly one as_root re-dispatch, zero `ai.query`. Intent key: the three `-sS` variants collapse correctly *after* mutation-stripping; two distinct 900-char errors sharing a 160-char prefix get distinct verdicts.

**Effort:** L. **Risk:** Med-High (hot dispatch path; the `connect_fallback` and probe-failure overrides are what keep it from regressing unprivileged/transient-failure cases).

---

### Phase 2 — Autonomy-preserving provisioning + registry unification

**Goal:** make "the AI can pick ANY tool from anywhere, install it safely, and run it" literally true; collapse three registries into one capability-keyed catalog; revive the safe installer as the single provisioning entry.

**Prerequisites:** none hard, but sequence after Phase 1 so guardian/catalog edits don't collide with the `enforce_capability` dispatch changes.

**Changes:**

- **P2-1 `core/tool_catalog.py` + `core/provisioning_policy.py`** *(CHG-1)*. **Critic override (bootstrap paradox):** keep authored data as PRIVATE `_RAW_TOOL_REGISTRY`/`_RAW_ALL_TOOLS` that only the seed reads; public `TOOL_REGISTRY`/`ALL_TOOLS`/`WRAPPER_TOOLS` become thin generated views. **Critic override (NEW-6 durability):** persist install *method*/sha/capabilities only; **never persist `installed=True`** — re-probe per node/session. **Critic override (denylist):** split `INSTALL_DENY` vs `RUN_DENY` (short destructive-verb list; not `crontab -l`/`iptables -L`). Atomic locked `catalog.json` writes (temp + `os.replace`). **Closes:** TRIPLE/DUAL-REGISTRY-1, CAPREG-FRAG-2, CAPREG-GATES-DEAD.
- **P2-2 Delete guardian's `ALLOWED_RECON_TOOLS` allowlist; replace with deny+scope gate** *(CHG-2, guardian.py l.13-38/195-196)*. **Critic override (l.89 prose extraction):** use `get_catalog().get(first_word) is not None OR '=' in first_word OR first_word in {export,sudo,timeout,env,nice,proxychains4,proxychains}` — **drop the permissive `^[A-Za-z0-9][\w./-]*$` branch** (it matches "here" in "here is the command:" and breaks wrapper extraction). Keep all pattern/scope/length rails; add the `RUN_DENY` check. **Closes:** GUARDIAN-ALLOWLIST-1.
- **P2-3 Revive `tool_installer` as the single provisioning entry** *(CHG-3)*: Gate-1 → catalog lookup + bounded AI self-registration; Gates 2-7 become live safety envelope; fold the PATH-locator/symlink into Gate-7 verify; install-truth = Gate-7 verified `--version`, then `mark_installed`. **Critic override (local path):** add a local-executor branch so WSL-local installs survive the consolidation (or keep tool_manager's local path and route only the remote path through the installer). **Critic override (self-registration budget):** cache negative results with TTL, cap self-registrations/session (`SESSION_INSTALL_LIMIT`), installer-only (not resolve-triggered). **Critic override (Gate-5):** audit builtin install strings against `TRUSTED_INSTALL_SOURCES` and widen the trusted list (data) before routing, so modern recon tools don't fail to install. **Closes:** TOOLINSTALL-DEAD, NEW-2, NEW-3, NEW-6, CAPREG-GATES-DEAD.
- **P2-4 Registries become generated views; unify caches; seed modern recon tools** *(CHG-4)*. Enumerate ALL exports (incl. `WRAPPER_TOOLS`, `register_tool`, `load_custom_tools`) and every direct-mutation site before migration. Seed httpx/katana/gau/dnsx/naabu/hakrawler/waybackurls/assetfinder/arjun with REAL install methods (go install / GitHub release / pipx), **deduped-by-binary** (dnsx/naabu already exist in `ALL_TOOLS`). **Closes:** NEW-2 (data level), CAPREG-INSTALL-DUP, CAPREG-OS-DUP.

**Autonomy / no-hardcode rationale:** the one autonomy-limiting gate (human pre-registration) becomes a catalog lookup the AI can satisfy at runtime; everything else the installer enforces is tool-agnostic safety (source/integrity/resource/scope). Adding a tool = a data row or a JSON drop, never a core edit. The only surviving identity list is the short `RUN_DENY`.

**Verification/tests:** `all_binaries()` ⊇ both legacy sets, no dup-by-binary; `httpx` resolves to the ProjectDiscovery/go install (not apt/pip); pip-library-only httpx fails Gate-7 and is never cached installed; a binary only in `/root/go/bin` is symlinked and verifies; a novel benign tool with in-scope target passes the guardian (old "not allowlisted" string gone); `rm -rf /`/`mkfs` still blocked; `crontab -l`/`iptables -L` NOT blocked; concurrent `register()` never corrupts `catalog.json`; WSL-local install still works.

**Effort:** XL. **Risk:** Med-High (wide import surface; the generated-view migration and local-path override are the blast-radius controls).

---

### Phase 3 — Learning-from-proof

**Goal:** every learner derives "what worked" from the Phase-0 proof (where a proof exists) or a signal-cleaned execution verdict; every persistent write is atomic; self-upgrade is gated on a TRUTH check, not a schema check.

**Prerequisites:** Phase 0 (Evidence, `finding_is_proven`, `produced_result`, and the P0-10 tool-run→finding linkage).

**Changes:**

- **P3-1 `intelligence/learning_signal.py`** *(C1)* — `LearningOutcome` + shared `HARD_FAIL_MARKERS`. **Critic override:** `.proven` fallback also requires `_produced_result` (reuse P0-9 `produced_result`) so "ran clean, proved nothing" (nmap host-up-no-ports, gobuster all-404, sqlmap not-injectable) does NOT score proven. `from_confirmed_hypothesis` carries the Evidence and calls `is_proven()` directly (no `status=='confirmed'` trust). **v1.1 (resolves the HARD_FAIL_MARKERS contract risk — no new blessed substring authority):** the classification **authority is `produced_result` + process/exit semantics** (non-zero exit, signal death), never a substring table. `HARD_FAIL_MARKERS` is narrowed to a **generic, tool-agnostic process-failure set** (`command not found`, `permission denied`, `segmentation fault`, `no space left`) used **only as a fast-path hint that `produced_result` can override** — it is never per-tool and never the deciding vote. This keeps the zero-hardcode invariant: the plan does not condemn substring-classification-as-authority in Phase 0 and then re-enshrine it here. **Closes:** LEARN-1 (signal).
- **P3-2 engagement_analyzer proof-anchored** *(C2, `_analyze_tool_effectiveness` l.104-142, `_analyze_waf_patterns` l.271-291)* using the P0-10 exact join (not target-fuzzy). **Closes:** LEARN-1 (origin), AUTOUPGRADE insight quality.
- **P3-3 WafLearner: unify keys, revive batch path, gate on proven** *(C3, base_agent l.3023-3045/3215-3250, reporting l.430-435, waf_learner l.148-193)* — one `record_outcome(LearningOutcome, waf_id)` credits/debits the SAME normalized tactic name; batch reads `store.get_tool_runs()`. **Closes:** WAFLEARN-KEYSPLIT, WAFLEARN-BATCH-DEAD.
- **P3-4 StrategicAdvisor durable + proven-fed; delete dead/buggy WAF learning** *(C4)* — atomic temp+`os.replace` + debounce; feed from `.proven`; delete `should_continue_trying` (dead) and the all-True WAF branch. **Critic override:** add a lock/shard for multi-agent writers to `strategic_knowledge.json`. **Closes:** ADVISOR-NONATOMIC-SAVE, ADVISOR-WAF-ALLTRUE, ADVISOR-SIGNAL, ADVISOR-PIVOT-LOGIC.
- **P3-5 TruthGate in front of auto_upgrader; delete the inert corrupting write** *(C5, `intelligence/truth_gate.py`, auto_upgrader `_validate_changes` l.187-251, delete `_update_tool_metrics` l.317-360)*. **Critic override (the default flip is a no-op):** gate application *inside* `_validate_changes` (fail-closed when unevaluable) AND neutralize BOTH explicit `dry_run=False` callers by name — `reporting_agent:365` and `orchestrator:799 → run_incremental_upgrade:53` (per-phase). **Recommended simplification:** given the held-out slice is under-powered per engagement, prefer *deleting the apply path entirely* (keep pure analysis/reporting) unless a cross-engagement proven-outcome ledger is built. **v1.1 (resolves the "permanently inert = lost autonomy" tension):** the two are not either/or — **build the durable cross-engagement proven-outcome ledger** (the same store Residual-risk #1 calls for) and keep the apply path **behind `TruthGate`, dry-run by default, applying only when the held-out proven-rate is non-regressing across engagements.** That preserves the self-upgrade autonomy *safely* instead of trading it away. Deleting the apply path is the **fallback** only if that ledger is deferred — an explicit, reversible choice (inert but non-corrupting), not a permanent capability loss. **Closes:** UPGRADE-1, AUTOUPGRADE-FULLY-INERT.
- **P3-6 Disarm the rule-merge landmine (keep loop open)** *(C6, rule_generator `_append_to_rule_file` l.390-436, `merge_rules_to_system` l.361-388)* — id-dedup, preserve `{"rules":[...]}` shape, atomic write, replace the 0.9/0.95 confidence gate with `TruthGate.supports`. **Closes:** RULEGEN-APPEND-LATENT, RULEGEN-MERGE-DEAD.
- **P3-7 ToolSuccessTracker proven-fed; expose ranking as a deterministic seam** *(C7, tool_success_tracker l.157-182, base_agent l.1032-1036)*. **Closes:** LEARN-1 (tracker), Pathology-1 residue (partial — enforcement of the ranking belongs to a future tool-selection change; this exposes the clean seam).
- **P3-8 Delete dead feeders** *(C8 — EngagementRecorder)* **plus the `syntax_learner` marker dedup** *(C9)*. **CRITIC OVERRIDE — DO NOT delete `evidence_router.py` wholesale:** `TechStackRouter` is LIVE (`exploitation_agent:847`). Delete only the dead `EngagementRecorder`; the `EvidenceRouter` class + `ROUTING_RULES` deletion is handled in Phase 5 (D-DEL-1, which correctly splits the file). **Closes:** RECORDER-DEAD.

**Autonomy / no-hardcode rationale:** the AI keeps choosing tools; only the signal it learns from is cleaned, deterministically, no prompt/approval. Gates count PROVEN outcomes and compare held-out proven rates — no tool list, CVE table, or per-tool threshold. Deleting the all-True lie and the hardcoded critical-tool/confidence literals removes hardcoding. Zero new LLM calls.

**Verification/tests:** banner-only nmap `success` → `proven==False`; differential Evidence → `proven==True`; WAF header_mutation 5 successes + 5 blocks → success_rate ≈ 0.5 (not a 1.0/0.0 split); kill -9 mid-save leaves valid JSON; corrupted-but-schema-valid insights → `TruthGate.supports` False and nothing applied; repo-root `tool_metrics.json` no longer written; `grep` shows no `EngagementRecorder` callers; `TechStackRouter` import still resolves.

**Effort:** L. **Risk:** Med (the apply-path gating and the honest re-labeling of tool-effectiveness "learning" are the correctness controls).

---

### Phase 4 — Loop convergence + budget resilience + egress causality

**Goal:** stop the self-inflicted 403→rotate-Tor→still-403 cascade and the self-correction-stack budget starvation; fail-close stealth.

**Prerequisites:** Phase 1 (unified intent key), Phase 0 (Evidence — the egress differential is `is_proven()` applied to egress).

**Changes:**

- **P4-1 Bound the recovery sleep + `BackendExhausted` + `BudgetSnapshot`** *(C1, ai_backend `query()` l.868-882)*. **Critic override (ORCH-TIMEOUT-1 not truly fixed by a cap):** replace `time.sleep` with `await asyncio.sleep` when on a running loop (detect via `asyncio.get_running_loop`), or run `query()` via `asyncio.to_thread` from the agent, so the loop stays awaitable and `asyncio.timeout` can cancel mid-recovery. The cap is the belt; async is the suspenders. Transitively closes DEEP-9 (checkpoint runs). **Closes:** AIBACKEND-SLEEP-1, ORCH-TIMEOUT-1, DEEP-9.
- **P4-2 Budget-gate the self-correction stack** *(C2, base_agent `_afford_llm` + the triage/repair/grounding/mentor calls)*. **Critic override:** `remaining()` must use `_phase_token_budget()` (tokens), NOT `_phase_budget_total` (wall-clock seconds); implement `can_spawn` ON TOP of the existing `is_phase_budget_exhausted()` — one budget authority. Fall through to existing deterministic classifiers (`classify_unrepairable`, transport-dead abandon, exit-code backstop) when starving. **Closes:** RC-4, DEEP-3, DEEP-10.
- **P4-3 Enforced convergence breaker fed by an intent ledger** *(C3 + strategic_advisor `should_continue_trying`)*. **Critic override:** the intent must be the Phase-1 `_command_intent_key` *with evasion mutations stripped* (the whole reason the old breaker never tripped), and progress (`evidence_seq`) must be **intent-local** (findings attributable to this intent's target/tool window), not `len(_findings_seen)` global. `should_continue_trying(..., no_progress)` returns False authoritatively; the loop breaks with no LLM. **Closes:** DEEP-2, RC-3, DEEP-10 (convergence).
- **P4-4 Egress causality — one merged seam** *(EGR-1 from self-knowledge + C4 from convergence, unified)*. `core/egress_probe.py` + `tool_manager.attribute_block`. **Critic overrides folded:** (a) condition attribution on a per-command `went_through_tor` bool from the existing `_apply_stealth_routing` raw-vs-proxied decision — raw-socket/direct tools attribute to target; (b) **relocate `waf_markers` as the block HYPOTHESIS (test arm), delete only `_WAF_EXEMPT_TOOLS`**, and require the block signal be an actual HTTP response to the tool's own request (not a substring anywhere in output — keeps nmap/subfinder "403-as-data" out); (c) control set MUST include a CDN/WAF-fronted endpoint, majority vote, fail-to-`unknown`; (d) capture the egress fingerprint at exec time so a mid-flight rotation can't flip self_egress→target; (e) `unknown` → do NOT fire evasion (rotate-once-or-abandon). Preserve the whatweb/curl salvage carve-outs. **Closes:** RC-2, RC-1, DEEP-1, DEEP-7, the egress-cascade trigger surface.
- **P4-5 Fail-closed stealth** *(C5 + STEALTH-DEGRADE-1, base_agent `_stealth_leak_guard` l.942-989)*. Widen the trigger from `rotate_ip`-only to any requested anonymity (`_stealth_requested()`). **Critic override (the higher-severity half):** add a raw-socket branch that fires **regardless of `_tor_verified`** when stealth is requested — raw-socket tools (nmap/masscan/dig/naabu) run DIRECT even under verified Tor, so verified Tor does not protect them; block/force-skip or require explicit `allow_direct_on_tor_fail`. Keep local-tool/`--help` exemptions and the one `ensure_tor_ready()` recovery. **Closes:** STEALTH-DEGRADE-1 (both halves).

**Autonomy / no-hardcode rationale:** deletes `_WAF_EXEMPT_TOOLS` and demotes `waf_markers` to a hypothesis; the block verdict is a measured control-vs-target differential keyed on egress reachability, not a marker list. The engine self-diagnoses self-egress blocks and stops wasting the whole budget rotating Tor against its own 403. Budget/convergence gates are deterministic and obeyed — strictly fewer LLM calls under stress.

**Verification/tests:** all-keys-dead → `query()` returns/raises within cap+ε (not 3600s) and the phase timeout fires mid-recovery with a WAL checkpoint written; starved pool → ≤1 LLM call per failing tool; 86-evasion replay → convergence within N (bounded, not 86); Tor-exit-403 with a CDN-fronted control blocked → `self_egress`, one rotation, no evasion; same 403 with control clean → `target`, evasion allowed; nmap "403-as-data" never flips status; stealth+verified-Tor+raw-scan → guard blocks/force-skips (no real-IP leak).

**Effort:** L. **Risk:** Med-High (the async-sleep, budget-authority-unification, intent-mutation-stripping, and raw-socket-leak overrides are each load-bearing).

---

### Phase 5 — Dead-code deletion + config consolidation + observability + future-proof extension contracts

**Goal:** delete the phantom "intelligence" that inflates trust and misdirects audits; one config loader; structured observability; and ship the four extension `Protocol`s so new tools/vuln-types/WAF-techniques/backends slot in without core edits.

**Prerequisites:** Phase 0 (hardened `is_proven` — the proof registry and `WafTechnique` feed it), Phase 2 (`ToolCatalog` populated), Phase 4 (`observe`/failure store consumed by plausibility can land after the loop work).

**Changes:**

- **P5-1 Delete confirmed-dead modules** *(D-DEL-1)*: `constraint_engine.py`, `finding_scorer.py`, `engagement_recorder.py`, and the **`EvidenceRouter` class + `ROUTING_RULES` only** — **KEEP `TechStackRouter`** (live via `exploitation_agent:847`). **Critic override:** flag `TechStackRouter`'s `cve_database` static table as inherited hardcoding debt handed to the proof registry (route tech-stack findings through `ProofRegistry` keyed on capability; keep `TechStackRouter` as an interim *lead* generator only). Add `.pyc`/`__pycache__` cleanup + import smoke test to verification (stale bytecode shadows deletions). **Closes:** PHANTOM-1/2, ARCH-1.
- **P5-2 Delete `unified_config_loader.py`; consolidate to one `ConfigManager`; retire `MockConfig`** *(D-DEL-2, D-CONFIG-1)* with explicit precedence env > YAML > module default; migrate the 3 prod import sites (base_agent:26, tool_manager:19, capability_registry:16). **Closes:** CONFIG-FRAG.
- **P5-3 Reduce `vps_optimizer` to real work** *(D-VPS-1)*: delete the 4 WSL no-op "optimizations" and the hardcoded `run1/H3` debug side-channel; route diagnostics through the logger/`observe`. **Closes:** VPS-OPT-STUBBED.
- **P5-4 Structured `FailureRecord` + `observe()`** *(D-OBS-1)*. **Critic override:** fold into the EXISTING failures table (reuse `get_cross_engagement_failures` schema) — do not stand up a parallel store; per-engagement cap/rotation; `record_failure` never raises into the wrapped op. Migrate the highest-value swallow sites first (base_agent's 94 except clauses, in batches). Feeds the Phase-0/4 plausibility gates. **Closes:** NEW-5.
- **P5-5 `WafTechnique` `Protocol` + Evidence-or-lead for the arsenal** *(D-FUT-2, request_smuggler/oob_exfil/credential_finder/origin + `waf_bypass_orchestrator._validate_bypass_differential`)*: each technique returns `Evidence | None`; only `is_proven()` becomes a confirmed bypass; demote (don't delete) non-differential techniques to leads. Depends on P5-4 to have somewhere to record leads. **Closes:** SMUGGLER-FALSEPOS, OOB-STUB, CREDFINDER-NO-VALUE, ORIGIN-STUBS.
- **P5-6 Proof-method registry as the vuln-class extension seam** *(D-FUT-1)* — repoint at the EXISTING `core/result_contracts.Evidence` (the phantom `intelligence/evidence.py` does not exist); registration validates through the hardened `is_proven`. This is the same registry created in P0-2, now populated with `cache_deception`, `authz_tester`, `test_origin_connection` as reference methods.
- **P5-7 `ToolCatalog` + `LLMBackend` `Protocol` contracts** *(D-FUT-3)* — `ToolCatalog` is the Phase-2 implementation; `LLMBackend.token_budget()` aligns with the Phase-4 budget authority.
- **P5-8 AttackGraph: fix + wire or delete** *(D-WIRE-1)*. **Critic override (the stated fix is a no-op):** the real bug is edges to depth-3 neighbors never added to `visited_nodes`; fix = append an edge only when `depth+1 <= 2` (or post-filter edges to endpoints in `visited_nodes`) + dedupe. Reads are test-only → **lean to the delete-both-sides fallback** unless the convergence work commits to consuming `get_filtered_context`. **Closes:** PHANTOM-1 (graph).

**Autonomy / no-hardcode rationale:** every deletion removes a hardcoded table (routing rules, priority maps, exploit-keyword lists, WSL no-ops, `waf_bypassed:True` asserts). The four `Protocol`s are capability-keyed extension points; new capability = a registration or a `Protocol` impl, never a core edit. Observability *adds* self-knowledge, not human-in-the-loop.

**Verification/tests:** `grep` for each deleted symbol returns only tests; `.pyc` removed + `python -c 'import …'` smoke test passes; config parity test (env beats YAML beats module default); `observe()` around a raiser persists exactly one record and never re-raises the recorder's own error; each WAF technique returns `None` on a target with no real desync/callback/value and `is_proven()==True` only on a synthetic positive differential.

**Effort:** L. **Risk:** Low-Med (mostly deletion; the `is_proven` repoint and failures-table fold-in are the coordination points).

---

## 5. Coverage matrix (major defect IDs → phase / change)

| Defect ID | Phase | Change |
|---|---|---|
| EVIDENCE-ISPROVEN-FORGEABLE *(new, critic)* | 0 | P0-1 harden `is_proven` |
| RC-SUCCESS-DEF / TOOLMGR-1 | 0 | P0-9 `produced_result` (all finalization sites) |
| EXPLOIT-EMIT-1 | 0 | P0-5 delete substring mint; stamp real proof |
| WEAPON-SUBSTR-PROOF | 0 | P0-6 delete root:x:0/SQL elifs |
| WEAPON-NUCLEI-CONFIRM | 0 | P0-6 retag failed-PoC nuclei → lead |
| SELFAWARE-OPSSANITY-BYPASS | 0 | P0-3 exemption keys on proof token |
| VALIDATE-SEVERITY-SUBSTR *(new, critic)* | 0 | P0-3 rewire `_validate_severity`; stamp before it |
| OBJLEDGER-FALSE-WIN | 0 | P0-7 proof_resolver gate |
| REPORT-SPLIT-SUBSTR | 0 | P0-8 `_split_two_tier` → `finding_is_proven` |
| DEEP-5 | 0 | P0-4 `_plausible_handoff` |
| tool-run→finding linkage *(new, critic)* | 0 | P0-10 schema |
| NEW-1 | 1 | P1-1/P1-2 dual-probe + escalate-or-`connect_fallback` |
| META-RC-0 | 1 | P1-2/P1-3 gate + delete advisory prose |
| DEEP-8 (dedup + cache) | 1 | P1-4 intent key + P1-5 cache de-poison |
| GUARDIAN-ALLOWLIST-1 | 2 | P2-2 delete allowlist |
| TRIPLE/DUAL-REGISTRY-1, CAPREG-FRAG-2 | 2 | P2-1/P2-4 catalog + generated views |
| TOOLINSTALL-DEAD, CAPREG-GATES-DEAD | 2 | P2-3 revive installer |
| NEW-2 | 2 | P2-3/P2-4 correct install methods |
| NEW-3 | 2 | P2-3 Gate-7 symlink onto PATH |
| NEW-6 | 2 | P2-3 verify-not-exit-code + `installed` never persisted |
| LEARN-1 | 0+3 | P0-9/P3-1/P3-2 proof-anchored signal |
| WAFLEARN-KEYSPLIT / -BATCH-DEAD | 3 | P3-3 |
| ADVISOR-NONATOMIC-SAVE / -WAF-ALLTRUE | 3 | P3-4 |
| UPGRADE-1 / AUTOUPGRADE-FULLY-INERT | 3 | P3-5 TruthGate + neutralize both `dry_run=False` callers |
| RULEGEN-APPEND-LATENT / -MERGE-DEAD | 3 | P3-6 |
| RECORDER-DEAD | 3 | P3-8 delete EngagementRecorder |
| RC-4 / DEEP-3 / DEEP-10 | 4 | P4-1/P4-2 bounded sleep + budget shed |
| AIBACKEND-SLEEP-1 / ORCH-TIMEOUT-1 / DEEP-9 | 4 | P4-1 async recovery + cap |
| DEEP-2 / RC-3 | 4 | P4-3 enforced convergence breaker |
| RC-2 / RC-1 / DEEP-1 / DEEP-7 | 4 | P4-4 egress causality (EGR-1+C4 merged) |
| STEALTH-DEGRADE-1 | 4 | P4-5 fail-closed stealth (incl. raw-socket-under-Tor) |
| PHANTOM-1/2, ARCH-1 | 5 | P5-1/P5-3/P5-8 |
| CONFIG-FRAG | 5 | P5-2 |
| NEW-5 | 5 | P5-4 FailureRecord/observe |
| OOB-STUB / SMUGGLER-FALSEPOS / CREDFINDER-NO-VALUE / ORIGIN-STUBS | 5 | P5-5 WafTechnique |
| absence of extension contracts | 5 | P5-6/P5-7 registries + Protocols |
| STATE-1 *(v1.1)* | 0 | P0-0a durable/acknowledged state-store writes (spine prerequisite) |
| PARSER-1/2/3, SANITIZE-1 *(v1.1)* | 0 | P0-0b parser fidelity + CR-safe `clean_text` (feeds `produced_result`) |
| RC-6 *(v1.1)* | 0 | P0-4 pre-exploit result-quality gate (garbage recon → no handoff) |
| REPORT-1 *(v1.1)* | 0 | P0-8 all rendering paths through `finding_is_proven`, not just the split |
| SEC-1 *(v1.1)* | 2 | P2-5 make the install sandbox real or drop the "sandboxed" claim (fail-closed) |
| `_RAW_SOCKET` identity set / CVE-1 *(v1.1)* | 2 / 5 | P2-1 raw-socket → catalog capability tag; P5-13 `cve_database` → `CVESource` Protocol (leads-only) |
| DEEP-4 *(v1.1)* | 4 | P4-6 deterministic context-window budget (trim history/output; prevents truncation) |
| WAFFP-PLANNING-OVERRIDE / WAFFP-TYPE-MISNOMER *(v1.1)* | 4 | P4-7 delete synthesized-0.8 override; WAF signal is a labelled hypothesis, not a fact |
| BUS-1 *(v1.1)* | 5 | P5-9 event-bus buffered/replayed delivery for late subscribers |
| FRONTIER-POPLOOP-DEAD *(v1.1)* | 5 | P5-10 wire the `attack_frontier` pop-loop or delete it |
| ROUTER-CMD-DEMOTED *(v1.1)* | 5 | P5-11 fix/delete command-router demotion; align with the unified intent key |
| CONCURRENCY-1 *(v1.1)* | 5 | P5-12 systematic shared-cache lock audit (supersedes piecemeal P1-5/P3-4/P2 locks) |
| HARD_FAIL_MARKERS contract risk *(v1.1)* | 3 | P3-1 authority = `produced_result` + exit semantics; markers are a generic hint only |
| auto_upgrader autonomy tension *(v1.1)* | 3 | P3-5 TruthGate + cross-engagement proven-outcome ledger (apply-path preserved, gated) |

---

## 6. What to DELETE vs. What to KEEP UNTOUCHED

### DELETE (dead code + brittle hardcoded lists)

- **Substring proof branches:** exploitation `_emit_exploit_findings` step-3 (l.312-333); weaponization `root:x:0`/`SQL syntax` elifs (l.487-492) and the nuclei-confirmed promotion (l.536-550); the ops-sanity `"VULN_PROVEN"/"Proof["` exemption; `_validate_severity`'s `'vuln_proven:'/'confirmed'` gate; reporting's `type/substring` split test.
- **Identity gates / signature tables:** guardian `ALLOWED_RECON_TOOLS`; `_WAF_EXEMPT_TOOLS`; the reactive `-sS→-sT` downgrade block (superseded by escalate + `connect_fallback`); the per-tool nmap-banner hack; `EvidenceRouter` + `ROUTING_RULES`; `constraint_engine` tool-priority/keyword tables; `finding_scorer` CONFIDENCE/EXPLOITABILITY/PRIORITY tables; `auto_upgrader` curl/nuclei critical-tool list and `rule_generator` 0.9/0.95 confidence literals. **(v1.1)** the `_RAW_SOCKET` identity set in `_apply_stealth_routing` (→ moved to a `ToolEntry.capabilities` tag, P2-1 / §9.5 — the last identity list falls); `TechStackRouter.cve_database` static CVE table (→ pluggable `CVESource` Protocol, leads-only, P5-13).
- **Dead modules:** `constraint_engine.py`, `finding_scorer.py`, `engagement_recorder.py`, `unified_config_loader.py`, `config_manager.MockConfig`; the 4 `vps_optimizer` WSL no-ops + `run1/H3` debug channel; the `strategic_advisor.should_continue_trying`/all-True WAF branch; `auto_upgrader._update_tool_metrics`. **(v1.1)** the dead `attack_frontier` pop-loop (FRONTIER-POPLOOP-DEAD → wire-or-delete, P5-10).
- **Demote, don't delete:** `waf_markers` (relocate to block-hypothesis/test-arm); non-differential WAF techniques (→ leads); nuclei/tech-stack matches (→ leads).

### KEEP UNTOUCHED (the working gates — do not "fix")

- `Evidence` fields + `hypothesis_engine.validate_result` / `_response_similarity` (reuse for the differential method) — *but the `is_proven()` body IS hardened; that is the one deliberate change to an otherwise-correct object.*
- `authz_tester`, `cache_deception`, `test_origin_connection` differentials (register as reference proof methods).
- `tripwire_detector.prune_honeypot_ports`; reporting's `evidence_objects` loader / `_export_pocs`; the FIX-E demotion exemption and two-tier verdict machinery (they inherit the corrected key).
- `waf_learner`'s atomic+locked DB internals; `tool_success_tracker`'s atomic save + WAF-block-excluded denominator; `syntax_learner`'s input signal-cleaning + atomic save (only its private marker list is swapped for the shared import).
- `reasoning_engine.analyze_tool_failure` calibration (clean; its enforcement is a future tool-selection change, not this program).
- `TechStackRouter` (live) — kept, with its `cve_database` flagged as debt, used as a *lead* generator only.
- `orchestrator`'s `asyncio.timeout` + `finally` teardown + sqlite `.backup()` checkpoint (they finally get to run once the sleep is bounded/async).

---

## 7. Sequencing, dependencies, and the minimal first PR

**Hard dependency chain:** P0 (hardened `is_proven` + `proof.py` + `produced_result` + tool-run→finding linkage) is the trunk. P3 (learning) needs P0's Evidence, `produced_result`, and the linkage. P4's egress differential is "`is_proven()` applied to egress" → needs P0; its convergence ledger needs P1's unified intent key. P5's proof registry and `WafTechnique` feed P0's hardened gate; its `observe()` substrate is consumed by P0/P4 plausibility (so a *thin slice* of P5-4 may be pulled forward, but its bulk migration stays last). P2 (provisioning) is largely independent but sequenced after P1 to avoid colliding `base_agent` dispatch edits.

**Consolidations that prevent two dimensions editing the same code twice:** one hardened `is_proven`; one `proof.py` seam with `stamp` as sole constructor; one `_command_intent_key` (dedup + cycle + verdict-cache + convergence, evasion-mutations stripped); one `_interpret_outcome` de-poison (CH8 ⊕ CACHE-1, no LLM re-verify); one `produced_result` (recon success ⊕ learning "proved nothing"); one egress-causality seam (EGR-1 ⊕ C4); one budget authority (`remaining()` on top of `is_phase_budget_exhausted`); one catalog with private raw seeds + generated views; one failures table.

**Minimal first PR — de-risk the worst user-facing symptom (false "COMPROMISED / N proven" + false victory) fastest.** Ship a tight slice of Phase 0:

1. **P0-1** harden `Evidence.is_proven()` (+ persisted `control_absent`/`test_present`/`oob_token`).
2. **P0-2** add `core/proof.py` — ledger as its own table, `ProofRegistry`, `finding_is_proven`, `stamp(method, ctx)` as sole constructor.
3. **P0-3** stamp the proof token in `add_finding` *before* `_validate_severity`; rewire `_ops_sanity_backstop` + `_validate_severity` to the token.
4. **P0-7 + P0-8** rewire `objective_ledger.update_from_findings` (proof_resolver) and `reporting._split_two_tier` to `finding_is_proven`.
5. **Wire the three genuine proof paths** (hypothesis-confirmed, authz differential, real leaked-artifact) to `stamp`, and **delete** the exploitation/weaponization substring mint branches (P0-5/P0-6).

**Why this is the right first cut:** because reporting and the objective ledger now key on `finding_is_proven`, and the ledger only holds *re-measured* Evidence, the report **cannot** print "COMPROMISED — N proven" from a substring — the worst case degrades to a *truthful under-report* (a genuinely proven finding whose emit path isn't yet wired shows as a lead) rather than a false over-claim. That is exactly the safe direction. `produced_result` (P0-9), the intent key/cache (Phase 1), and everything downstream can follow without re-touching these consumers.

---

## 8. Critic objections folded in as resolved decisions (and where a design was overridden)

**Overrides where a critic was right and I changed the design:**

1. **`is_proven()` must be hardened; "reuse unchanged" is dropped.** Verified live: `differential` passes on unmeasured `similarity < 0`; `artifact`/`oob` return True unconditionally. Both the evidence-spine and cleanup critics caught this independently. → P0-1 requires a persisted measurement per proof type. *This is the single most important override — without it the spine is a rename of the bug.*
2. **`stamp` is the sole Evidence constructor.** The design hand-constructed `Evidence(...)` at emit sites, relocating forgery to a dataclass field. → `add_finding` takes `proof_method`/`proof_ctx`, never a pre-built `evidence=`.
3. **`_validate_severity` substring gate + ordering.** It runs before the token was stamped and would cap a genuinely-proven critical to medium. → stamp before it and key it on the token.
4. **ProofLedger as a table, not a KV map.** KV read-modify-write lost-updates under `ThreadPoolExecutor(10)`. → single-writer queue + `INSERT OR IGNORE`.
5. **CH7 scoped to ALL finalization sites, "fetch succeeded" ≠ "fetch differs".** The design patched one classifier and would downgrade a cached identical-to-baseline body to `NO_FINDINGS`. → route every site through `produced_result`; separate the two signals; delete the nmap-banner hack; keep whatweb/curl salvage.
6. **CH8 LLM re-verify removed.** It re-introduced LLM calls into the starvation loop. → TTL/size bound only; convergence handled by the Phase-4 intent ledger.
7. **Keep graceful degradation on unprivileged boxes.** CAP-2's `reject` would give zero scan output. → `connect_fallback` to `-sT` when no root path; escalate on the *measured* `raw_socket_via_root`, not inferred `root_path_available`; never cache a probe-failure as a hard reject.
8. **Egress attribution conditioned on the actual egress + CDN-fronted control.** Global `_tor_verified` misattributes raw-socket (DIRECT) tool 403s; ipify-class controls aren't CDN-fronted so the differential collapses. → per-command `went_through_tor`, diverse CDN-inclusive control set, fingerprint at exec time, `unknown`→don't-evade, delete only `_WAF_EXEMPT_TOOLS` and demote `waf_markers` to a hypothesis.
9. **Fail-closed stealth covers raw-socket-under-verified-Tor.** The higher-severity leak: nmap/masscan run DIRECT even when Tor is verified. → raw-socket branch fires regardless of `_tor_verified`.
10. **Bootstrap paradox + durable `installed` + denylist split.** Private `_RAW_*` seeds → generated public views; never persist `installed=True`; split `INSTALL_DENY`/`RUN_DENY` so `crontab -l`/`iptables -L` stay runnable; preserve WSL-local install; bound AI self-registration.
11. **Do NOT delete `evidence_router.py` wholesale.** `TechStackRouter` is live at `exploitation_agent:847` — the learning dimension's C8 was wrong. → delete only `EvidenceRouter`/`ROUTING_RULES` (Phase 5), keep `TechStackRouter`, flag its `cve_database` as debt.
12. **`dry_run` default flip is a no-op.** Both callers force `dry_run=False` (`reporting:365`, `orchestrator:799`→`run_incremental_upgrade:53`). → gate inside `_validate_changes`, neutralize both callers by name, prefer deleting the apply path.
13. **Budget gate uses tokens, not seconds, and reuses the existing authority.** `_phase_budget_total` is wall-clock. → `_phase_token_budget()` + `can_spawn` on top of `is_phase_budget_exhausted()`.
14. **ORCH-TIMEOUT-1 needs async, not just a cap.** Sync `time.sleep` on the event-loop thread still blinds `asyncio.timeout`. → `await asyncio.sleep`/`to_thread`.
15. **Convergence intent must strip evasion mutations + be progress-local.** The old per-`cmd_hash` breaker failed precisely because proxychains/header/delay mutations changed the hash. → one intent key that normalizes them; `evidence_seq` intent-local.
16. **Tool-effectiveness "learning" is honestly labeled.** No `tool_run→Evidence` link existed → add P0-10 linkage so it's real; where a proof genuinely can't exist, the signal is a cleaned execution verdict (incl. `produced_result`), not called "proven."
17. **Guardian prose-extraction regex dropped.** The permissive `^[A-Za-z0-9][\w./-]*$` matched "here" and broke wrapper extraction. → catalog-membership + env/wrapper predicate only.
18. **AttackGraph fix corrected + lean-to-delete.** The stated fix was a no-op; the real bug is depth-3 edges never added to `visited`. → correct filter + prefer deletion since reads are test-only.
19. **Observability folded into the existing failures table, self-safe recorder.** No parallel store; `record_failure` never raises into the wrapped op.
20. **`.pyc`/`__pycache__` cleanup + import smoke test on every deletion.** Stale bytecode can shadow deletions.

**Objections acknowledged but *not* over-corrected (design stands, with a bound):** AI self-registration is a *bounded* new LLM call (cached negatives, per-session cap, installer-only) — accepted because it replaces the guardian phantom-block feedback loop that wasted *more* turns; the CACHE-1 lock is kept as cheap defense but no longer justified by a non-existent race; TruthGate may stay dry-run/inert on small engagements — accepted as safe, with the explicit option to delete the apply path entirely.

**Residual, deliberately out of scope (handed off):** enforcing the `tool_success_tracker` ranking into tool selection (a future tool-selection change); `reasoning_engine` pivot/calibration converted to a loop-control budget. *(**Superseded in v1.1:** the `_apply_stealth_routing` `_RAW_SOCKET` set — v1.0's "last identity branch" — is **no longer out of scope**; §9.5 moves it to a `ToolEntry.capabilities` tag (P2-1 amendment), deleting the last identity list.)*


---

## 9. Completeness closure (v1.1) — orphan IDs assigned, prerequisites promoted, contract risks resolved

> This section closes every gap the adversarial completeness audit (Appendix D) found in v1.0. Nothing here changes the spine; it finishes the coverage around it. After this section, **Appendix D is a historical record** — each of its items is marked CLOSED below. Change IDs added here (P0-0a/0b, P2-5, P4-6, P4-7, P5-9…P5-13) obey the same invariants as §2: measured-not-asserted, gate-on-capability-not-identity, delete-over-advise, zero net new LLM passes.

### 9.1 Promoted Phase-0 prerequisites (the spine's hidden foundations)

The audit's single most important structural finding: the Evidence spine silently rested on two layers it never verified. A "green" Phase 0 could still lose a proof row or misread a real scan as empty. Both are now the **first changes in Phase 0** (fully specified inline above):

- **P0-0a — Durable state/ledger writes (STATE-1).** Acknowledged writes, timeouts raised not dropped, WAL checkpoint on shutdown. Blocks P0-2 (the ledger sits on this queue).
- **P0-0b — Parse fidelity + CR-safe sanitize (PARSER-1/2/3, SANITIZE-1).** Faithful parsed ports/hosts/lists + CR-preserving `clean_text`. Blocks P0-9 (`produced_result` reads these fields).

**Why this is correct and not scope-creep:** every other trust guarantee in the plan is downstream of "the measurement was actually stored" and "the scan output was actually read." Leaving these to a later phase would ship a spine that is honest about data it may have already silently corrupted.

### 9.2 Orphan-ID assignments (all 12 audit gaps → a phase + change)

| Defect ID | Phase | Change | One-line approach |
|---|---|---|---|
| STATE-1 | 0 | **P0-0a** | Durable, acknowledged state-store writes; no silent drop on timeout. |
| PARSER-1/2/3 | 0 | **P0-0b** | Fix port/liveness/discovery parsers; golden-fixture parse-fidelity tests. |
| SANITIZE-1 | 0 | **P0-0b** | CR-safe `clean_text` (parse raw before sanitize) so real result lines survive. |
| REPORT-1 | 0 | **P0-8 (broadened)** | Route *all* rendering paths through `finding_is_proven`, not only the two-tier split. |
| SEC-1 | 2 | **P2-5** | Make the install sandbox actually isolate, or drop the "sandboxed" label; fail-closed. |
| DEEP-4 | 4 | **P4-6** | Deterministic context-window budget: trim ReAct history/tool-output; kill truncation at source. |
| WAFFP-PLANNING-OVERRIDE | 4 | **P4-7** | Delete the synthesized 0.8-confidence override; WAF signal enters P4-4 as a hypothesis only. |
| WAFFP-TYPE-MISNOMER | 4 | **P4-7** | Rename the field to a *candidate* WAF family (a labelled guess), never a confirmed type. |
| BUS-1 | 5 | **P5-9** | Event bus gains buffered/replayed delivery so late subscribers don't miss events. |
| FRONTIER-POPLOOP-DEAD | 5 | **P5-10** | Wire the `attack_frontier` pop-loop into exploitation, or delete it (default: delete). |
| ROUTER-CMD-DEMOTED | 5 | **P5-11** | Fix/delete the command-router demotion; align routing with the unified intent key. |
| CONCURRENCY-1 | 5 | **P5-12** | Systematic shared-cache lock audit; supersedes the piecemeal P1-5/P3-4/P2 locks. |

### 9.3 Contract-risk resolutions (all 8)

| Risk (Appendix D) | Resolution |
|---|---|
| STATE-1 dependency unverified | **Resolved:** promoted to **P0-0a** (Phase-0 prerequisite), no longer assumed. |
| PARSER-1/2/3 dependency unverified | **Resolved:** promoted to **P0-0b** (Phase-0 prerequisite). |
| `HARD_FAIL_MARKERS`/`looks_like_failure` re-introduces a blessed substring list | **Resolved (P3-1):** classification authority is `produced_result` + process/exit semantics; the marker set is narrowed to a **generic, tool-agnostic** process-failure hint that `produced_result` overrides — never per-tool, never the deciding vote. |
| Residual hardcoded `_RAW_SOCKET` identity set | **Resolved (P2-1 / §9.5):** the raw-socket requirement moves into `ToolEntry.capabilities` as a `needs_raw_socket` tag; `_apply_stealth_routing`/`enforce_capability`/egress attribution read the tag. **The last identity list is deleted** — new raw-socket tools work with zero core edits. |
| `TechStackRouter.cve_database` static CVE table retained | **Resolved (P5-13):** replaced by a pluggable `CVESource` Protocol whose output can only ever be an **unproven lead** the Evidence spine must confirm; the static table is deleted. |
| `TRIPWIRE-1` pruning in P0-4 can suppress a real handoff | **Resolved (P0-4 bound):** the pruner may only **lower confidence / flag `needs_confirmation`, never hard-drop** a port; the Evidence differential is the final arbiter, so a real port behind a honeypot signal still gets exploited and measured. |
| AI self-registration (P2-3) is a new model-in-the-loop | **Accepted, bounded:** cached negatives + per-session cap + installer-only. It **replaces** the guardian phantom-block feedback loop that wasted *more* turns, so it is a net reduction in LLM round-trips, not an addition. Deterministic catalog lookup is tried first; the LLM call fires only on a miss. |
| auto_upgrader "delete the apply path" trades away autonomy | **Resolved (P3-5):** build the durable **cross-engagement proven-outcome ledger** and keep the apply path behind `TruthGate`, dry-run by default, applying only on a non-regressing held-out proven-rate. Autonomy preserved *safely*; deletion is the reversible fallback if the ledger is deferred, not a permanent loss. |

### 9.4 Weakly-addressed items tightened (all 9)

| Item | Tightening |
|---|---|
| RC-6 (blind exploit on garbage) | **Named:** P0-4 is now the explicit pre-exploit result-quality gate — empty/garbage recon → no handoff. |
| DEEP-6 (3084-LOC WAF firing on self-403s) | P4-4 demotes `waf_markers` to a test-arm hypothesis and fires evasion only on a **proven-target** block; the module's firing surface collapses accordingly. Broad refactor of the module body is deferred as data-cleanup, not logic. |
| CVE-1 (static CVE table) | **Upgraded from deferred debt to a fix:** P5-13 makes it a `CVESource` Protocol, leads-only. |
| TRACKER-DECISION-DEAD / Pathology-1 | P3-7 exposes the ranking as a clean deterministic seam; **enforcement into tool selection is explicitly deferred** (it needs the tool-selection-loop rework, out of scope) — flagged, not silently dropped. |
| REASON-ADVISORY | Calibration kept (it is clean); enforcement into loop-control/tool-selection is the same deferred selection-loop change. Explicitly deferred. |
| ADVISOR-STORE-FRAG | P3-4 adds durability + a multi-writer lock/shard **and** consolidates onto the one `strategic_knowledge.json` authority (no fragmented parallel stores). |
| HARDCODE-1 (weaponization template-first) | P0-6 deletes the substring proof; **v1.1 adds the re-order:** weaponization runs the differential/PoC **first** and uses templates only as scaffolding, never as the proof source. |
| WAF-TRANSFORM (good-code-wrong-premise) | P4-4 (block = measured control-vs-target differential) + P4-7 (WAF type = hypothesis) fix the premise directly. |
| TRIPWIRE-1 (double-edged pruning) | Bounded in P0-4 (demote-not-drop); see §9.3. |

### 9.5 New change specs (amendments to Phases 2 / 4 / 5)

> Labelled "Amends Phase N." Each keys on capability + measurement, adds no per-tool table, and adds no net LLM pass.

- **P2-5 — Real sandbox or no sandbox claim (SEC-1)** *(Amends Phase 2)*. Inside the revived `tool_installer` safe-install envelope, the isolation gate must **actually** isolate execution (namespace/container/`firejail`-class, or resource-limited `unshare`) **or** be removed with its "sandboxed" label dropped so no consumer trusts a boundary that isn't there. **Fail-closed:** if isolation can't be established, the run is refused or tagged `unsandboxed` — never silently trusted as isolated. **Verify:** a tool that tries to escape the configured boundary is contained or the run is refused; the `sandboxed` flag is True only when a boundary is provably in effect.
- **P2-1 amendment — raw-socket as a capability tag** *(resolves the `_RAW_SOCKET` contract risk)*. `ToolEntry.capabilities` carries `needs_raw_socket`; the seed sets it for nmap/masscan/naabu/dig etc. `_apply_stealth_routing` (P4-4/P4-5) and `enforce_capability` (P1-2) read the tag instead of the hardcoded set. **Verify:** a newly-registered raw-socket tool is routed/guarded correctly with no core edit; the old `_RAW_SOCKET` literal is gone.
- **P4-6 — Deterministic context-window budget (DEEP-4)** *(Amends Phase 4)*. Alongside the token budget (P4-2), bound what gets packed into each prompt: cap tool-output bytes, drop/deterministically-summarize the oldest low-value observations, and keep the ReAct history under a hard size so prompt growth cannot cause silent truncation → the JSON/parse-failure family. **No new LLM pass** — trimming is rule-based. **Verify:** a synthetically huge tool output is truncated deterministically with a visible marker; prompt size stays under the cap across a long loop; no mid-response truncation on the replayed long engagement.
- **P4-7 — Sever the WAF fabricated-confidence override (WAFFP-PLANNING-OVERRIDE, WAFFP-TYPE-MISNOMER)** *(Amends Phase 4)*. Delete the synthesized `0.8` confidence in the WAF fingerprinter/planning path; the WAF signal feeds P4-4 **only as a hypothesis** (test arm), and the detected "type" becomes a **candidate family** (a labelled guess), never a confidence-bearing classification. **Verify:** no code path emits a fabricated fixed confidence; a WAF guess never by itself raises a finding's confidence; P4-4 still fires evasion only on a measured proven-target block.
- **P5-9 — Event-bus late-subscriber delivery (BUS-1)** *(Amends Phase 5)*. Add bounded buffered/replayed delivery per topic (or a durable last-value cache) so a subscriber attaching after an event still receives it. **Verify:** a subscriber registered after an event is emitted still receives it; buffer is bounded and drops oldest, not newest.
- **P5-10 — Frontier pop-loop: wire or delete (FRONTIER-POPLOOP-DEAD)** *(Amends Phase 5)*. Either drive exploitation from the `attack_frontier` pop-loop (consume it) or delete the dead loop + scaffolding. **Default: delete** unless the Phase-4 convergence work commits to consuming it. **Verify:** `grep` shows no dead pop-loop, or the loop demonstrably advances exploitation on a replay.
- **P5-11 — Command-router demotion fix (ROUTER-CMD-DEMOTED)** *(Amends Phase 5)*. Fix or delete the command-router demotion path so a valid command is not silently down-ranked; align routing decisions with the unified `_command_intent_key`. **Verify:** a valid command is not demoted below a degenerate alternative; routing keys on intent, not a stale identity check.
- **P5-12 — Systematic shared-cache lock audit (CONCURRENCY-1)** *(Amends Phase 5)*. One pass over **all** shared mutable caches/dicts touched by multiple agent threads (not just the piecemeal P1-5/P3-4/P2 locks): enumerate each, add a lock or make it thread-local/atomic, add a concurrency regression test. **Verify:** an enumerated list of shared caches each has a documented synchronization strategy; a 10-thread stress test shows no lost/torn updates.
- **P5-13 — CVE source as a pluggable Protocol, leads-only (CVE-1)** *(Amends Phase 5)*. Replace `TechStackRouter.cve_database` with a `CVESource` Protocol (refreshable/pluggable feed); its output can only ever produce **unproven leads** the Evidence spine must confirm — never a proven finding. New CVEs/tech slot in via a feed impl, zero core edits; the static table is deleted. **Verify:** tech-stack matches surface as leads that require an Evidence differential before any confirmed status; a new CVE feed is added without touching `TechStackRouter` core.

### 9.6 Coverage delta (merge into §5 / Appendix A)

The v1.1 rows are already appended to the §5 coverage matrix. Net result: **every ID in the canonical inventory (Appendix D gaps + contract risks + weakly-addressed) now maps to a phase and a change ID.** Phase-count deltas: Phase 0 +4 (P0-0a, P0-0b, RC-6 via P0-4, REPORT-1 via P0-8), Phase 2 +1 (P2-5) + the P2-1 tag amendment, Phase 4 +2 (P4-6, P4-7), Phase 5 +5 (P5-9…P5-13). No phase reordering; all additions respect the existing dependency chain (the two prerequisites land at the very front of Phase 0).

### 9.7 Honest residual (what v1.1 still defers, on purpose)

Two items remain deferred **by design**, now stated explicitly rather than hidden: (1) **enforcing** the `tool_success_tracker` ranking and `reasoning_engine` calibration into live tool selection — both need the tool-selection-loop rework, a separate program; the seams are exposed and clean, only the enforcement is out of scope. (2) The **broad refactor of the 3084-LOC WAF module body** — P4-4/P4-7 correct its *premise and firing surface* (the correctness fix), but shrinking the module itself is data-cleanup deferred to avoid destabilizing the egress path during the correctness work. Neither is a silent cap: both are flagged here and in §9.4.

---

# Appendix A — Coverage matrix (defect ID → change → phase)

*36 defect IDs mapped by the synthesizer in v1.0. The completeness audit (Appendix D) found 12 more UNMAPPED; **all of those are now mapped in v1.1** — see the "*(v1.1)*"-tagged rows in §5 and the closure tables in §9.2–§9.6.*

| Defect ID | Addressed by | Phase |
|---|---|---|
| EVIDENCE-ISPROVEN-FORGEABLE | P0-1 harden Evidence.is_proven() to require a persisted per-type measurement (differential 0<=sim<0.97; artifact control_absent+test_present; oob oob_token) | Phase 0 |
| RC-SUCCESS-DEF / TOOLMGR-1 | P0-9 ToolResult.produced_result(capability) routed through ALL status-finalization sites; delete nmap-banner hack; keep whatweb/curl salvage | Phase 0 |
| EXPLOIT-EMIT-1 | P0-5 delete substring mint branches; genuine paths call ProofLedger.stamp; confirm-gate uses finding_is_proven | Phase 0 |
| WEAPON-SUBSTR-PROOF | P0-6 delete root:x:0/SQL-syntax elifs; route via artifact_reflection differential | Phase 0 |
| WEAPON-NUCLEI-CONFIRM | P0-6 retag failed-PoC nuclei to nuclei_lead/info; remove proven_exploits append | Phase 0 |
| SELFAWARE-OPSSANITY-BYPASS | P0-3 ops-sanity exemption keys on proof token via finding_is_proven; delete substring exemption | Phase 0 |
| VALIDATE-SEVERITY-SUBSTR | P0-3 rewire _validate_severity off 'vuln_proven:'/'confirmed' substring; stamp token before it runs | Phase 0 |
| OBJLEDGER-FALSE-WIN | P0-7 objective_ledger proof_resolver gate; drop severity-in-{high,critical} inclusion | Phase 0 |
| REPORT-SPLIT-SUBSTR | P0-8 reporting _split_two_tier uses finding_is_proven | Phase 0 |
| DEEP-5 | P0-4 _plausible_handoff plausibility gate reusing prune_honeypot_ports | Phase 0 |
| tool-run-to-finding-linkage | P0-10 persist tool_run_id on finding row; get_tool_runs returns id (unblocks proof-anchored learning) | Phase 0 |
| NEW-1 | P1-1 dual-context capability probe; P1-2 enforce_capability escalate-on-raw_socket_via_root or connect_fallback | Phase 1 |
| META-RC-0 | P1-2 deterministic capability gate + P1-3 delete false advisory prose | Phase 1 |
| DEEP-8 | P1-4 unified _command_intent_key (all write/read sites) + P1-5 verdict cache de-poison (full-hash key, TTL/size, lock, no LLM re-verify) | Phase 1 |
| GUARDIAN-ALLOWLIST-1 | P2-2 delete ALLOWED_RECON_TOOLS; deny+scope gate; catalog-membership prose extraction | Phase 2 |
| TRIPLE-REGISTRY-1 / DUAL-REGISTRY-1 / CAPREG-FRAG-2 | P2-1 ToolCatalog + P2-4 generated views over private _RAW_ seeds | Phase 2 |
| TOOLINSTALL-DEAD / CAPREG-GATES-DEAD | P2-3 revive tool_installer as single provisioning entry with live gates 2-7 | Phase 2 |
| NEW-2 | P2-3/P2-4 correct install methods (go/GitHub release) seeded in catalog | Phase 2 |
| NEW-3 | P2-3 Gate-7 symlink root-installed binary onto non-root PATH | Phase 2 |
| NEW-6 | P2-3 install-truth = Gate-7 --version verification; installed never persisted, re-probed per node/session | Phase 2 |
| LEARN-1 | P0-9 produced_result + P3-1 LearningOutcome + P3-2 engagement_analyzer proof-anchored via exact join | Phase 0 + Phase 3 |
| WAFLEARN-KEYSPLIT / WAFLEARN-BATCH-DEAD | P3-3 one record_outcome with normalized tactic key; batch reads get_tool_runs() | Phase 3 |
| ADVISOR-NONATOMIC-SAVE / ADVISOR-WAF-ALLTRUE | P3-4 atomic+debounced save, proven-fed, delete all-True branch, add multi-writer lock/shard | Phase 3 |
| UPGRADE-1 / AUTOUPGRADE-FULLY-INERT | P3-5 TruthGate inside _validate_changes; neutralize both dry_run=False callers; delete _update_tool_metrics (prefer deleting apply path) | Phase 3 |
| RULEGEN-APPEND-LATENT / RULEGEN-MERGE-DEAD | P3-6 id-dedup, dict-shape preserve, atomic write, TruthGate confidence gate | Phase 3 |
| RECORDER-DEAD | P3-8 delete EngagementRecorder (NOT evidence_router; TechStackRouter is live) | Phase 3 |
| RC-4 / DEEP-3 / DEEP-10 | P4-1 bounded/async recovery + P4-2 budget-gated self-correction shed (token budget, single authority) | Phase 4 |
| AIBACKEND-SLEEP-1 / ORCH-TIMEOUT-1 / DEEP-9 | P4-1 cap + await asyncio.sleep/to_thread so asyncio.timeout can cancel mid-recovery; checkpoint runs | Phase 4 |
| DEEP-2 / RC-3 | P4-3 enforced should_continue_trying breaker fed by evasion-mutation-stripped, intent-local progress ledger | Phase 4 |
| RC-2 / RC-1 / DEEP-1 / DEEP-7 | P4-4 egress causality (EGR-1+C4 merged): EgressProbe + attribute_block, per-command went_through_tor, CDN-fronted control, delete _WAF_EXEMPT_TOOLS, demote waf_markers to hypothesis | Phase 4 |
| STEALTH-DEGRADE-1 | P4-5 fail-closed _stealth_leak_guard for any requested stealth incl. raw-socket-under-verified-Tor | Phase 4 |
| PHANTOM-1 / PHANTOM-2 / ARCH-1 | P5-1 delete constraint_engine/finding_scorer/engagement_recorder + EvidenceRouter class; P5-3 vps_optimizer no-ops; P5-8 attack_graph fix-or-delete | Phase 5 |
| CONFIG-FRAG | P5-2 delete unified_config_loader; one ConfigManager with explicit precedence; retire MockConfig | Phase 5 |
| NEW-5 | P5-4 FailureRecord/observe folded into existing failures table; self-safe recorder | Phase 5 |
| OOB-STUB / SMUGGLER-FALSEPOS / CREDFINDER-NO-VALUE / ORIGIN-STUBS | P5-5 WafTechnique Protocol returns Evidence\|None; only is_proven() confirms; non-differential demoted to leads | Phase 5 |
| absence-of-extension-contracts | P5-6 proof-method registry (repointed at core.result_contracts.Evidence) + P5-7 ToolCatalog/LLMBackend Protocols | Phase 5 |

---

# Appendix B — Sequencing & dependencies

Phase 0 is the trunk and must land first: harden Evidence.is_proven() and stand up core/proof.py (ledger as a single-writer table, stamp() as the sole Evidence constructor), plus the honest produced_result() success signal and the tool_run to finding linkage. Everything downstream keys on these. Phase 1 (self-knowledge gates + the one unified intent key and de-poisoned verdict cache) follows because Phase 4 reuses the intent key. Phase 2 (provisioning/registry) is largely independent but sequenced after Phase 1 to avoid colliding base_agent dispatch edits. Phase 3 (learning) needs Phase 0's Evidence, produced_result, and the linkage. Phase 4 (convergence/budget/egress) needs Phase 0 (egress differential is is_proven applied to egress) and Phase 1 (intent ledger). Phase 5 (deletion/config/observability/extension contracts) is last, though a thin slice of the observe()/failures seam may be pulled forward to feed the plausibility gates. The minimal first PR is a tight Phase-0 slice (hardened is_proven + proof.py + stamp-before-severity + rewire objective_ledger and reporting to finding_is_proven + wire the three genuine proof paths and delete the substring mint branches), which makes false COMPROMISED/N-proven reports impossible by construction and degrades only to a truthful under-report.


---

# Appendix C — Residual risks (synthesizer)

1. Held-out TruthGate power: with few tool_runs per engagement the gate is usually unevaluable and defaults to dry-run/inert. Mitigation is a durable cross-engagement proven-outcome ledger; if not built, the safest option is deleting the auto-upgrader apply path entirely rather than shipping a permanently-gated ~1600 LOC.
2. artifact_reflection/OOB proof needs a real control baseline; some call sites (notably weaponization _synthesize_and_execute_poc) may run with no persisted baseline_body, so those artifact leaks fail-closed to leads — a truthful under-report. Confirming a baseline source at every proof call site is required to avoid systematically under-reporting real leaks.
3. EgressProbe depends on a safe, in-scope, CDN/WAF-fronted neutral control endpoint reachable through Tor. If none can be provisioned, classify() returns unknown for the run and egress attribution degrades to today's behavior (either misses real target WAFs or never fires evasion). The unknown->do-not-evade fail-safe bounds the cascade but not the missed-detection risk.
4. Migrating _command_intent_key across all ~25 write and re-compute sites is the single most error-prone edit; a missed write site silently disables dedup and cycle detection, worsening RC-3 convergence — the opposite of intent. Requires an atomic migration with a regression test that a mutated-then-repaired command shares its intent bucket.
5. Provisioning Phase 2 has a wide import surface (TOOL_REGISTRY/ALL_TOOLS/WRAPPER_TOOLS/register_tool consumers). The generated-view migration risks import-cycle/seed-timing bugs and dropped runtime registrations if any direct-mutation site is missed; catalog.json needs atomic locked writes to avoid multi-thread corruption of the source of truth.
6. Bounded AI self-registration is still a new LLM call on the install path; a mis-described tool that keeps missing capability resolution could spin the backend budget unless negative-result caching and the per-session cap hold under real workloads.
7. TechStackRouter is kept (live) but its cve_database is a static CVE table — an inherited zero-hardcoding debt. Until tech-stack findings are routed through the proof registry as leads only, a new tech/CVE will not be handled and the table can silently promote unproven leads if any consumer treats its output as confirmed.
8. strategic_advisor.json and other JSON KBs are written by many agent threads; the added lock/shard must actually cover every writer or the debounced flush can still lose the in-memory delta between flushes on a crash.
9. Async recovery change (await asyncio.sleep/to_thread in ai_backend.query) touches the hottest LLM path; if any except RuntimeError caller re-queries in its own retry loop, the retry storm relocates up one level rather than being eliminated — every catch site of BackendExhausted must be audited for immediate re-query.
10. Observability migration touches base_agent's 94 except clauses under the ReAct hot loop; a sentinel-return vs reraise mismatch at any site can subtly change control flow, and high write volume to the failures table needs the per-engagement cap/rotation to be enforced from day one.

---

# Appendix D — Completeness audit (adversarial)

> **STATUS: CLOSED in v1.1.** This is the audit that drove the v1.1 completeness closure. **Every gap, contract risk, and weakly-addressed item below is now resolved in §9** (orphan IDs → phases, the two spine prerequisites promoted to P0-0a/P0-0b, contract risks resolved, weak items tightened). It is retained verbatim as the historical record of *why* §9 exists — read §9 for the resolutions. The original pre-closure framing ("NOT yet complete… fold these in before calling remediation done") is preserved below as it was written against v1.0.

> An independent auditor checked the plan against the full canonical defect inventory. **This is the most important section for scoping the real work: the plan is strong on the headline false-victory chain but is NOT yet complete against the inventory.** Fold these into the phase plan before calling remediation done.

## Verdict

Strong and correctly prioritized on the headline pathology — the Evidence/proof spine (Phase 0) is sound, the critic overrides (hardened is_proven, stamp-as-sole-constructor, ledger-as-table, produced_result at all finalization sites) are real fixes, and the minimal-first-PR degrades in the safe direction (truthful under-report, never false COMPROMISED). Dependency ordering is coherent and the consolidations genuinely prevent double-edits. However the plan is NOT complete against the inventory: at least a dozen inventoried IDs have no clear coverage (DEEP-4, SEC-1, BUS-1, SANITIZE-1, PARSER-1/2/3, FRONTIER-POPLOOP-DEAD, ROUTER-CMD-DEMOTED, WAFFP-TYPE-MISNOMER, WAFFP-PLANNING-OVERRIDE, STATE-1, REPORT-1, CONCURRENCY-1), and critically the proof spine rests on two layers it never verifies — STATE-1's silent-write-loss persistence and PARSER-1/2/3's parse fidelity — so a green Phase 0 can still lose proof rows or misread a real scan as NO_FINDINGS. It also reintroduces a shared hardcoded failure-marker substring list (HARD_FAIL_MARKERS/looks_like_failure) and deliberately leaves the _RAW_SOCKET/_apply_stealth_routing identity set and the TechStackRouter CVE table as residual hardcoding. Executable as the first program to kill the false-victory chain, but before it can be called a complete remediation the missing IDs must be assigned to phases and the STATE-1/parser dependencies verified rather than assumed.

## Gaps — inventoried defect IDs with NO clear coverage

- DEEP-4 (context bloat/truncation): no phase anywhere manages context-window bloat or truncation; only token-budget spend is addressed (Phase 4), not the prompt/context growth that causes truncation.
- SEC-1 (fake sandbox): the false/ineffective sandbox isolation is never addressed — no phase verifies or fixes execution isolation, a notable omission for an offensive tool.
- BUS-1 (no late-subscriber delivery): the event-bus late-subscriber delivery defect is untouched; no phase references bus/subscription semantics.
- STATE-1 (single-writer/timeout silent write loss): the plan BUILDS the ProofLedger and all learning writes on the state_store single-writer queue but never fixes STATE-1 itself — the spine assumes a persistence layer whose known silent-write-loss is unaddressed.
- SANITIZE-1 (clean_text destroys CR output): not addressed; the plan preserves syntax_learner's input cleaning but never touches the clean_text path that mangles carriage-return output.
- PARSER-1/2/3 (liveness/port parse loss): parsers are never fixed, yet P0-9 produced_result derives success from parsed open_ports/lists — the upstream parse-loss defect is left in place.
- FRONTIER-POPLOOP-DEAD: the dead frontier pop-loop is not mentioned in any phase or the DELETE list.
- ROUTER-CMD-DEMOTED: command-router demotion defect is absent from the matrix and text (only EvidenceRouter/TechStackRouter routing is discussed).
- WAFFP-TYPE-MISNOMER: not addressed anywhere.
- WAFFP-PLANNING-OVERRIDE (synthesized 0.8 confidence): the WAF false-positive planning override that fabricates 0.8 confidence is not clearly severed; WAF learning changes (P3-3/P3-4) do not name it.
- REPORT-1 (launders corrupted findings): only the specific REPORT-SPLIT-SUBSTR symptom is fixed (P0-8); the broader 'reporting launders corrupted findings' path is not audited beyond the two-tier split.
- CONCURRENCY-1 (unlocked shared caches): addressed only piecemeal (one lazy lock P1-5, one shard P3-4, catalog writes P2) — no systematic audit of all shared caches, so unlocked caches likely remain.

## Contract risks — where the plan as written could REINTRODUCE hardcoding / human-in-loop or break a working gate

- STATE-1 dependency: the entire proof spine and all learning writes route through the state_store single-writer queue, but STATE-1's silent-write-loss-on-timeout is never fixed — a lost ledger row silently demotes a genuinely proven finding (safe direction) yet the trust guarantee rests on an unverified persistence layer.
- PARSER-1/2/3 dependency: P0-9 produced_result derives 'success' from parsed open_ports/findings/lists; with the parsers unfixed, a dropped port makes a real scan read NO_FINDINGS — reintroducing a false-negative through an unaddressed upstream defect.
- HARD_FAIL_MARKERS / looks_like_failure (P3-1): introduces a hardcoded substring failure-marker list as a shared source — the same substring-classification pattern the plan condemns, now blessed as canonical.
- Residual hardcoded _RAW_SOCKET set in _apply_stealth_routing: explicitly left out of scope as 'the last identity branch,' so egress/stealth attribution remains keyed on a hardcoded tool identity list — a standing zero-hardcode violation.
- TechStackRouter.cve_database kept as a lead generator: the static stale CVE table (CVE-1) persists in live code, a retained hardcoded table.
- TRIPWIRE-1 pruning wired into the P0-4 plausibility gate: a double-edged pruner can suppress a legitimate handoff on honeypot-adjacent-but-real ports — risk of breaking a currently-working exploitation path.
- AI self-registration (P2-3): adds a net-new bounded LLM call into the provisioning path — acknowledged and capped, but it is new model-in-the-loop where the guardian allowlist previously gated deterministically.
- auto_upgrader 'prefer deleting the apply path entirely' (P3-5): trades UPGRADE-1 corruption for a permanently inert self-upgrade, reducing the very autonomy the program claims to increase — a design tension left unresolved.

## Weakly addressed — mentioned but only vaguely

- RC-6 (blind exploitation on garbage): only indirectly mitigated by the P0-4 _plausible_handoff gate; RC-6 is never named and no explicit pre-exploit garbage/quality gate is specified.
- DEEP-6 (3084-LOC WAF firing on self-403s): the self-403 firing behavior is addressed via P4-4 egress causality, but the oversized WAF module itself and its broader firing logic are not refactored.
- CVE-1 (static stale CVE table): explicitly flagged as inherited debt on TechStackRouter and kept as a lead generator — acknowledged, deferred, not fixed.
- TRACKER-DECISION-DEAD / Pathology-1: P3-7 exposes a clean ranking seam but states enforcement into tool selection is a future change — the dead decision stays dead.
- REASON-ADVISORY: explicitly deferred as a future loop-control/tool-selection change; calibration kept, enforcement not wired.
- ADVISOR-STORE-FRAG: P3-4 adds durability and a lock/shard but does not clearly consolidate the fragmented advisor store.
- HARDCODE-1 (weaponization template-first): P0-6 deletes substring proof elifs but the template-first weaponization ordering itself is not clearly re-architected.
- WAF-TRANSFORM (good-code-wrong-premise): partially handled by demoting waf_markers to a hypothesis (P4-4), but not named or fully reasoned through.
- TRIPWIRE-1 (honeypot pruning double-edged): reused as-is in P0-4 and kept as a strength; its double-edged over-pruning risk is neither mitigated nor bounded.

---

# Appendix E — Dimension verdicts (adversarial critique summary)

| Dimension | Fixes root cause? | Net verdict |
|---|---|---|
| Evidence-first trust spine (the unifying Tier-1 fix) | partial | The design correctly identifies the false-victory chain and its instinct — one shared, recomputed key that every trust consumer reads — is the right root-cause cure. The consumer-side rewiring (CH3-CH6) is accurate to the real code: I confirmed the exact substring branches at exploitation_agent l.312-333 and the confirm-gate _is_proven at l.2258, weaponization's root:x:0/SQL elifs, objective_ledger l.88-107 severity+marker inclusion, and reporting _split_two_tier l.623-626. Severing all of these with finding_is_proven() is real progress. BUT the foundation the whole dimension pivots on is not actually non-forgeable as specified, and it leaves one substring trust-gate in the chain untouched, so the claim 'route EVERY trust decision through a measured, non-forgeable Evidence.is_proven()' is overstated. Three concrete holes: (1) Evidence.is_proven() (verified at result_contracts.py l.660-666) returns True UNCONDITIONALLY for proof_type in ('artifact','oob') and to_dict() discards the control/test measurement — so the touted 'recompute is_proven() from the ledger' guarantee is a no-op for those types, and even 'differential' trusts a similarity_to_baseline float that the constructor sets. (2) CH2's add_finding(evidence=Evidence) and CH3/CH4 explicitly HAND-CONSTRUCT Evidence(proof_type='artifact'/'differential', ...) and pass it in, bypassing ProofRegistry.build/ProofContext entirely — so an emitter can forge proof by writing a dataclass literal exactly as easily as it wrote 'VULN_PROVEN'. Forgery is relocated from a substring to a field, not eliminated. (3) _validate_severity (base_agent l.1200-1216, runs at l.1294 BEFORE the token is stamped) still keys critical/high on `'vuln_proven:' in detail or 'confirmed' in detail` — an unaddressed substring link, and worse, it will CAP a genuinely-proven critical (passed via evidence= but whose detail lacks that literal) down to medium before ops-sanity ever sees the proof. Fix the foundation (stamp must be the sole Evidence constructor from a ProofContext; is_proven must recompute per-type from persisted measurement) and this becomes the correct unifying cure; ship as-is and the spine is bypassable and introduces a severity regression. |
| Deterministic self-knowledge enforcement seam (Pathology 1 / META-RC-0) | partial | The core insight is correct and the diagnosis is verified against the code: the capability probe (base_agent.py:4906-4922) really does measure only the run-context raw_socket and lies by omission about the root path; the prose at 3942-3946 and 5022-5023 really does steer the AI away from the one path that works; tool_manager.py:1499-1517 really does DOWNGRADE (-sS to -sT) instead of escalating; _interpret_outcome (2115) really is keyed on tool+160-char prefix with no lock; dedup (2526) really is exact-sha256. CAP-1 (dual-context probe) and PROSE-1 (delete false advice) are clean, low-risk, and correctly root-cause. HOWEVER three of the six changes have concrete defects that would ship regressions or fail to fire, and two contract-relevant claims are unverified/wrong. Net: adopt CAP-1 + PROSE-1 as-is; CAP-2, EGR-1, DEDUP-1, CACHE-1 each need a specific fix before they are safe. As written this is a symptom-and-root mix, not a clean cure. |
| Autonomy-preserving provisioning + registry unification (Pathology 4 - the no-hardcode heart) | yes | Direction is correct and root-cause-targeted: deleting guardian's ~47-name ALLOWED_RECON_TOOLS (verified as the ONLY live run-gate — the 7-gate installer is confirmed dead, zero production callers) and collapsing three registries into one capability-keyed ToolCatalog is exactly the right seam. Gating on capability + verified-install instead of identity is the real cure, and the surviving denylist genuinely does not cap autonomy. BUT the design ships with several concrete, load-bearing defects that would break its own stated verifications or re-introduce the pathologies it claims to close: (1) CHG-2's proposed l.89 prose-extraction replacement is too loose and breaks the exact test it claims passes; (2) CHG-1 and CHG-4 are mutually contradictory on where authored tool-data lives (bootstrap paradox); (3) persisting a 'measured' installed=True to catalog.json across runs/targets re-creates NEW-6; (4) the shared HARD_BLOCKED_BINARIES conflates install-deny with run-deny and would regress legitimate persistence/post-ex testing; (5) ai_register_from_capability is a new per-novel-tool LLM call, softening the 'zero added LLM passes' claim. Adopt the direction; the synthesizer must fix 1–4 before this is safe to build. |
| Learning-from-proof: feedback-loop integrity (Pathology 3, re-scoped) | partial | The design is well-grounded: I verified almost every defect claim against the live code — status=='success' at engagement_analyzer l.107 and l.281; the WAF keysplit (base_agent l.3045 writes literal "header_mutation" success, l.3250 writes str(tactic) block); non-atomic write_text at strategic_advisor l.73; hardcoded success:True at l.477; run_system_upgrade(dry_run=False) default and the curl/nuclei critical-tool list at auto_upgrader l.208; _update_tool_metrics writing ../tool_metrics.json (l.321); reporting_agent reading the always-empty phase_data['tool_runs'] (populated as [] at l.407). C1/C3/C4/C6/C7/C9 are sound, low-risk, zero-new-LLM-call, hardcoding-reducing changes. BUT two concrete defects block adoption as written, and the headline claim is oversold. (1) C8 asserts intelligence/evidence_router.py is dead and deletes it — it is NOT: exploitation_agent.py l.847 live-imports TechStackRouter from it to seed CVE leads into the (working) hypothesis engine. Deletion silently kills that signal (the caller swallows ImportError, so no crash, but a real capability regression to a clean path). (2) C5's stated fix — flip run_system_upgrade default to dry_run=True — is a near no-op: BOTH live callers pass dry_run=False explicitly (reporting_agent l.365, and orchestrator l.799 → run_incremental_upgrade l.53 which fires after EVERY phase). The design never names the orchestrator per-phase apply path at all; safety rests entirely on the TruthGate + deleting _update_tool_metrics, not on the default. (3) The core promise — "route every learner through Evidence.is_proven()" — is unachievable for the four tool-effectiveness learners: the tool_runs table has no finding_id/hypothesis_id linkage, get_tool_runs doesn't even return a row id, and findings key on (finding_type,target,detail) with no tool/command, so the C2 run→Evidence join can only match coarsely by target and in practice collapses to the cleaned-signal fallback — a static failure-marker heuristic, i.e. still a structural classifier, not a measured differential. Net: a solid, verified de-corruption of the worst symptom (hard-fail false positives) plus real durability/atomicity fixes, but it fixes the Evidence spine only where a proof already exists (the hypothesis path, already clean), and ships two must-fix errors. |
| Loop convergence, budget resilience, and egress causality (the loud cascade) | partial | Directionally correct and largely faithful to the contract: I verified the anchor claims against the live tree — should_continue_trying (strategic_advisor.py:383) and advise_waf_evasion (:250) are genuinely dead (only a test calls the former); waf_markers + _WAF_EXEMPT_TOOLS exist at tool_manager.py:1521-1536; the unbounded recursive recovery sleep is real (ai_backend.py:869-876, depth<3 x recovery_time); the rotate_ip-only stealth guard (base_agent.py:952) and silent-direct routing (:918) are as described; an evasion circuit-breaker already computes the exact exit+hash signature C3 wants to promote (base_agent.py:3169). The design deletes real hardcoded surface (_WAF_EXEMPT_TOOLS), keys gates on capability/evidence not tool identity, and reduces LLM calls under stress — all contract-positive. BUT four load-bearing problems keep it at 'partial': (1) C2 feeds the wrong variable as the token budget — _phase_budget_total is WALL-CLOCK SECONDS (base_agent.py:320), while the real token budget is _phase_token_budget() (:322, config PHASE_TOKEN_BUDGET_*); the design also stands up a parallel budget gate beside the EXISTING is_phase_budget_exhausted() (:339) it never mentions. (2) C1 only MITIGATES ORCH-TIMEOUT-1: agent.run() is awaited on the event loop (orchestrator.py:690-720) and time.sleep() is synchronous, so a capped 300s sleep still blocks the loop and asyncio.timeout still cannot fire during it — the checkpoint/teardown run AFTER the sleep returns, not when the timeout expires. (3) C3's convergence turns entirely on a normalizer the design leaves underspecified at precisely the point that produced 86 evasions — evasion MUTATES the command (proxychains4 prefix at :3236, header/delay mutation), which is why the existing per-cmd_hash breaker never trips; if _remediation_intent doesn't explicitly strip those mutations it fails identically. (4) C5 does not fully fail-close: raw-socket tools (nmap/masscan/dig/naabu) run DIRECT even under VERIFIED Tor (:921-927), yet the guard returns None when Tor is verified (:955), so a stealth run still leaks the real IP on every raw scan — the exact STEALTH-DEGRADE class C5 claims to close. Adopt the strengthenings and it moves to a solid fix. |
| Dead-code deletion, config consolidation, observability, and future-proof extension contracts | partial | Strong on its literal dimension (deletions, config clash, observability seam) — the census claims check out — but it quietly rests the entire trust-routing / future-proof half on an Evidence.is_proven() gate that is itself emitter-gameable, and it never audits or tightens that gate. Verified true: constraint_engine/finding_scorer/engagement_recorder have zero importers (not even test refs); EvidenceRouter+ROUTING_RULES dead at evidence_router.py:9-274 while TechStackRouter (275-444) is live via exploitation_agent.py:847; the two clashing get_config exist (config_loader.py:38 4-arg vs config_manager.py:30 no-arg MockConfig); exactly 3 prod importers (base_agent:26, tool_manager:19, capability_registry:16); base_agent has 94 line-final except clauses; vps_optimizer's 4 no-ops append 'Skipped (WSL)' (110-136) with hardcoded run1/H3 debug channel; attack_graph write-only, reads only in tests. So D-DEL-1/2, D-CONFIG-1, D-VPS-1, D-OBS-1 are accurate and safe. The problem is the seams meant to deliver the 'unifying cure': they are built on a gate that does not enforce measurement, and on a module path that does not exist. Net: adopt the deletions and observability as-is; do NOT ship D-FUT-1/D-FUT-2 until is_proven() is hardened and the Evidence home is corrected. |
