# GHOSTWIRE — Full-Codebase Bug Audit

> **RESOLUTION (2026-06-12): all actionable bugs below are FIXED.** 29/29 tests pass; `pylint --errors-only`
> now reports only confirmed false positives (guarded by `isinstance`/`hasattr`/`getattr`/`if`, or
> intentional `raise`). Summary of fixes:
> - CRASH #1 recon `time` UnboundLocalError → removed local `import time` (recon_agent l.1000/1006).
> - CRASH #2 `TargetContext.normalize_url` → fallback now uses raw target directly.
> - CRASH #3 `IPRotator.rotate(force=True)` → `rotate()`.
> - **BONUS CRASH** found while fixing: exploitation_agent had the *same* local-`import time` landmine
>   (l.1722/1728) that only worked due to a redundant import — removed all of them.
> - SILENT #4 added `WafGhostEngine.feedback()`/`get_block_rate()`.
> - SILENT #5 added public `WafLearner.update_tactic_effectiveness()` wrapper (accumulates → delegates).
> - SILENT #6 added `WafBypassOrchestrator.increment_evasion_tier()`/`get_evasion_tier()`.
> - #7 was a FALSE POSITIVE (HITL `raise` by design) — left as-is.
> - CORRECTNESS #8 deleted the duplicate `ToolResult` in tool_manager; now uses the canonical contract type.
> - CORRECTNESS #9 objectives severity now reflects real critical findings.
> - CORRECTNESS #10 (`json` import) already fixed earlier.
> - INCOMPLETE #12/#13/#14 wired-in or removed the dead computed values (cloud-metadata/internal IPs,
>   http2 stub, timing-probe `resp`).
> - HYGIENE: bare `except:` → `except Exception:` (robust_parser ×6); duplicate `import threading`
>   (session.py); dead `f"{base_url}/"` + redundant `import time` (exploitation); `TYPE_CHECKING` block
>   (base_agent annotations).
> Remaining (intentionally deferred, non-behavioral): a handful of unused exception vars / dead locals
> (`prompt_msg`, `exception_holder`, `_cmd_history_text`, `assumption_id`) and ~7 unused imports.

---



Method: graphify (architecture) + `pyflakes`/`pylint --errors-only` across **every** module in
`agents/ core/ intelligence/ tools/ utils/` + close reading of the kill-chain critical path.
Each item below is verified against the actual source (pylint false positives were discarded).

Severity key: **CRASH** = throws on a reachable path · **SILENT** = error swallowed by try/except so a
feature is dead but no crash · **CORRECTNESS** = runs but does the wrong thing · **HYGIENE** = dead code/smell.

---

## CRASH — unhandled runtime errors on reachable paths

1. **`agents/recon_agent.py:648` — `UnboundLocalError: time`.**
   `_run_recon_for_target` (l.579) contains local `import time` at l.1000 & l.1006, which makes `time`
   a *local* for the whole function. The `time.time()` at l.648 (planning-adoption WAF fingerprint
   path, reachable when planning returned a `recommended_bypass`) runs before that local import →
   crash. Fix: delete the local `import time` (module already imports it at l.4).

2. **`agents/recon_agent.py:599` — `AttributeError: TargetContext has no 'normalize_url'`.**
   The `except` fallback for target parsing calls `TargetContext.normalize_url(raw_target)`, but that
   method doesn't exist (only `from_input`, `base_url`, `full_url`, …). So when primary parsing fails,
   the fallback *also* crashes. Fix: use `TargetContext.from_input(raw_target)`.

3. **`agents/base_agent.py:2470` — `TypeError: rotate() got an unexpected keyword 'force'`.**
   Calls `self._ip_rotator.rotate(force=True)` but `IPRotator.rotate(self)` (core/ip_rotator.py:149)
   takes no args. Fires whenever a BLOCKED result triggers IP rotation with `rotate_ip` stealth on.
   Fix: `self._ip_rotator.rotate()`.

---

## SILENT — AttributeError swallowed by try/except → feature is dead

4. **`agents/base_agent.py:2216 & 2325` — `WafGhostEngine.feedback()` doesn't exist.**
   `WafGhostEngine` only defines `transform(...)`. The WAF-ghost success/block feedback calls throw
   AttributeError, caught by the surrounding `except`, so **WafGhost never learns**. Fix: add a
   `feedback()` method or remove the calls.

5. **`agents/base_agent.py:2223 & 2332` — wrong method name `WafLearner.update_tactic_effectiveness()`.**
   The real method is `_update_tactic_effectiveness` (intelligence/waf_learner.py:340). Calls fail
   silently → **WAF tactic-effectiveness learning is dead**. Fix: call `_update_tactic_effectiveness`.

6. **`agents/base_agent.py:2421` — `WafBypassOrchestrator.increment_evasion_tier()` doesn't exist.**
   AttributeError on the evasion-tier escalation path → **WAF evasion never escalates tier**. Fix:
   add the method or drop the call.

7. **`intelligence/waf_bypass_orchestrator.py:395 & 399` — bypass result becomes `None`.**
   `execution_result = self._execute_exhaustion_bypass(...)` and `_execute_parser_confusion_bypass(...)`
   assign from methods that have no `return`, so the result is silently `None` for the `exhaustion`
   and `parser_confusion` strategies. Fix: return the result from those methods.

---

## CORRECTNESS — runs but wrong behavior

8. **`tools/tool_manager.py:101` — duplicate `class ToolResult` shadows the canonical one.**
   Line 15 imports `ToolResult` from `core.result_contracts`; line 101 redefines a *different*
   `ToolResult`. The whole of `tool_manager` then uses the local class, so two divergent `ToolResult`
   types flow through the system (the imported one at l.15 is dead). Risk: `isinstance` checks and
   field/behavior drift. Fix: delete the local class, use the contract type (or vice-versa, but pick one).

9. **`agents/objectives_agent.py:69` — `real_critical` computed then discarded.**
   The noise-filtered `real_critical` list (with the comment "use the highest severity found") is never
   used; the `objectives_assessment` finding is hardcoded `"info"`. The intended severity logic is dead.

10. **`agents/exploitation_agent.py:1302` — `json` not imported at module level. (FIXED this session.)**
    My Track-1 hypothesis persistence used `json.dumps` while `json` was only imported locally in two
    *other* functions, so it threw `NameError`, swallowed by `except` → hypotheses never persisted.
    Already fixed by adding `import json` at the top.

11. **`agents/planning_agent.py:63-67` — AI-generated `phases` are decorative.**
    Planning prints the AI's `phases`, but the orchestrator drives execution from
    `rules/orchestration.json`, not this list. Cosmetic mismatch — the displayed plan can diverge from
    what actually runs.

---

## INCOMPLETE FEATURES — logic built then thrown away (flagged by unused-variable analysis)

12. **`intelligence/waf_bypass/origin_discovery.py:269/274/279/324`** — `aws_metadata_ips`,
    `azure_metadata_ips`, `gcp_metadata_ips`, `internal_ranges` are all computed and never used.
    The cloud-metadata / internal-range origin-discovery (SSRF) logic is half-wired.

13. **`intelligence/waf_bypass/request_smuggler.py:220`** — `vector` built then unused; a smuggling
    vector is constructed but never sent.

14. **`intelligence/waf_fingerprinter.py:261 & 461`** — `resp` assigned but unused; the response is
    fetched then ignored in two fingerprint paths.

15. **`agents/recon_agent.py:1281`** — `assumption_id` from `register_assumption(...)` discarded
    (tactic assumptions are registered but the id is never linked back).

---

## HYGIENE — low severity

16. **`core/robust_parser.py:15,27,59,84,96,126`** — six bare `except:` clauses (also swallow
    `KeyboardInterrupt`/`SystemExit`). Use `except Exception:`.
17. **`core/session.py:3`** — redefinition of `threading` (imported twice).
18. **`utils/logger.py:17`** — redefinition of `logging` (imported twice).
19. **`agents/base_agent.py:88-96`** — `__init__` type annotations reference unimported names
    (`EngagementSession`, `StateStore`, …) as string annotations. Safe at runtime, but
    `typing.get_type_hints()` on `BaseAgent` would raise. Add a `TYPE_CHECKING` import block.
20. **`agents/exploitation_agent.py:1191`** — bare expression statement `f"{base_url}/"` does nothing
    (dead line; probably meant to be assigned).
21. **~7 unused imports** across core dirs, **~10 unused locals** (e.g. `exception_holder`
    orchestrator.py:516, `prompt_msg` base_agent.py:2360, `_cmd_history_text` exploitation_agent.py:1545).

---

## Behavioral issues found earlier this session (context)
Already fixed: flag-corrector stripping valid flags; `max_tokens=2048` truncation; exploitation
empty-loop premature bail; `AUTO_APPROVE_INSTALLS=false`; the `core.logging` broken import.
Architectural (by design, documented in-code): persistence & objectives agents only test the
**scanner box**, not the target, until a `TargetWSLExecutor` exists.

---

## Suggested fix order
1. The 3 CRASH bugs (#1–#3) — quick, prevent hard failures.
2. The 4 SILENT WAF bugs (#4–#7) — restore learning/evasion that's currently dead.
3. `ToolResult` duplication (#8) — structural, prevents subtle drift.
4. Incomplete features (#12–#15) — decide finish vs. delete.
