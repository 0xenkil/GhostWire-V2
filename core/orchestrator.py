from core.session import EngagementSession
from core.state_store import StateStore
from core.message_bus import MessageBus
from core.scope_enforcer import ScopeEnforcer
from core.ai_backend import AIBackend
from agents.base_agent import BaseAgent
from core.capability_registry import CapabilityRegistry
from core.result_contracts import ResultStatus
from core.vps_optimizer import optimize_vps_before_scan
from tools.tool_manager import ToolManager
from core.health_monitor import HealthMonitor
from agents.planning_agent import PlanningAgent
from agents.recon_agent import ReconAgent
from agents.weaponization_agent import WeaponizationAgent
from agents.exploitation_agent import ExploitationAgent
from agents.persistence_agent import PersistenceAgent
from agents.objectives_agent import ObjectivesAgent
from agents.reporting_agent import ReportingAgent
from agents.validation_agent import ValidationAgent
from intelligence.auto_upgrader import AutoUpgrader
from utils.display import section, info, error, warning, phase_header, phase_complete, phase_spinner, engagement_dashboard, kill_chain_status
from utils.logger import get_logger, configure_log_dir
from config import VPS_DISK_ABORT_PCT, USE_REMOTE_VPS
import json
import time
import traceback
import os
from pathlib import Path

log = get_logger("orchestrator")


def _load_debug_cfg() -> dict:
    try:
        import uuid
        import re
        from config_paths import LOG_DIR

        raw_session = os.getenv("SESSION_ID") or uuid.uuid4().hex[:8]
        # Prevent path traversal by allowing only alphanumeric, dash, and
        # underscore characters
        session_id = re.sub(r'[^A-Za-z0-9_-]', '', raw_session)[:64]
        if not session_id:
            session_id = uuid.uuid4().hex[:8]

        log_file = LOG_DIR / f"debug-{session_id}.log"
        return {"log_file": str(log_file), "session_id": session_id}
    except Exception as e:
        # Log error but provide defaults (non-blocking)
        import sys
        import traceback
        print(f"[WARNING] Failed to load debug config: {e}", file=sys.stderr)
        log.debug(f"Debug config load error details: {traceback.format_exc()}")
        return {"log_file": "debug.log", "session_id": "unknown"}


def _agent_debug_log(location: str, message: str, data: dict,
                     run_id: str = "run1", hypothesis_id: str = "H1"):
    try:
        dbg = _load_debug_cfg()
        Path(dbg["log_file"]).parent.mkdir(parents=True, exist_ok=True)
        with open(dbg["log_file"], "a", encoding="utf-8") as f:
            f.write(json.dumps({
                "sessionId": dbg["session_id"],
                "runId": run_id,
                "hypothesisId": hypothesis_id,
                "location": location,
                "message": message,
                "data": data,
                "timestamp": int(time.time() * 1000),
            }, ensure_ascii=True) + "\n")
    except Exception as e:
        # Log error but don't crash (debug logging is non-blocking)
        import sys
        print(f"[DEBUG] Failed to write debug log: {e}", file=sys.stderr)


class Orchestrator:
    def __init__(self, session: EngagementSession):
        import threading
        self.session = session
        self._lock = threading.Lock()

        # Wire global logging directory
        configure_log_dir(session.results_dir / "logs")

        # Initialize shared infrastructure
        self.store = StateStore(session.db_path)
        self.bus = MessageBus(self.store, session.engagement_id)
        self.scope = ScopeEnforcer(session)
        self.ai = AIBackend(preferred_backend=session.ai_backend)

        # Print AI backend health report at startup
        self._print_backend_health_report()

        self.tools = ToolManager(session, self.store, ai_backend=self.ai)
        self.cap_reg = CapabilityRegistry(
            remote_executor=self.tools.remote, ai_backend=self.ai)
        self.health_monitor = HealthMonitor(self.tools.remote, self.store, getattr(
            self.session, "engagement_id", "global")) if self.tools.remote else None

        # Initialize validation agent first (it has no dependencies on others)
        self.validation = ValidationAgent("validation",
                                          session=session, state_store=self.store, tool_manager=self.tools,
                                          ai_backend=self.ai, message_bus=self.bus, scope_enforcer=self.scope,
                                          capability_registry=self.cap_reg, orchestrator=self
                                          )

        # Initialize all agents with shared infrastructure
        agent_kwargs = dict(
            session=session,
            state_store=self.store,
            tool_manager=self.tools,
            ai_backend=self.ai,
            message_bus=self.bus,
            scope_enforcer=self.scope,
            validation=self.validation,
            capability_registry=self.cap_reg,
            orchestrator=self
        )

        self.agents = {
            "planning": PlanningAgent("planning", **agent_kwargs),
            "recon": ReconAgent("recon", **agent_kwargs),
            "weaponization": WeaponizationAgent("weaponization", **agent_kwargs),
            "exploitation": ExploitationAgent("exploitation", **agent_kwargs),
            "persistence": PersistenceAgent("persistence", **agent_kwargs),
            "objectives": ObjectivesAgent("objectives", **agent_kwargs),
            "reporting": ReportingAgent("reporting", **agent_kwargs),
            "validation": self.validation,
        }

        # Load phase orchestration configuration from rules
        rules_path = Path(__file__).parent.parent / \
            "rules" / "orchestration.json"
        try:
            with open(rules_path, "r") as f:
                orchestration_rules = json.load(f)["phase_orchestration"]

            pentest_rules = orchestration_rules["pentest_mode"]
            redteam_rules = orchestration_rules["redteam_mode"]

            self.phase_order_pentest = pentest_rules["phases"]
            self.phase_order_redteam = redteam_rules["phases"]

            # Merge phase requirements from both modes into unified map
            self.PHASE_REQUIRES = {}
            self.PHASE_REQUIRES.update(pentest_rules["phase_requires"])
            self.PHASE_REQUIRES.update(redteam_rules["phase_requires"])

            # Load blocking statuses (convert null to None for Python)
            blocking_statuses_raw = orchestration_rules["pentest_mode"]["blocking_statuses"]
            self.BLOCKING_STATUSES = {
                None if s is None else s for s in blocking_statuses_raw}

            # Store mode-specific timeouts for later use
            self.phase_timeouts_pentest = pentest_rules["phase_timeouts"]
            self.phase_timeouts_redteam = redteam_rules["phase_timeouts"]

            log.info(f"Loaded orchestration rules from {rules_path}")
        except Exception as e:
            log.error(
                f"Failed to load orchestration rules, falling back to defaults: {e}",
                exc_info=True)
            # Fallback defaults with recon included
            self.phase_order_pentest = [
                "planning", "recon", "exploitation", "reporting"]
            self.phase_order_redteam = [
                "planning",
                "recon",
                "exploitation",
                "weaponization",
                "persistence",
                "objectives",
                "reporting"]
            self.PHASE_REQUIRES = {
                "recon": ["planning"],
                "exploitation": ["recon"],
                "weaponization": ["exploitation"],
                "persistence": ["exploitation"],
                "objectives": ["exploitation"],
                "reporting": ["recon"],
            }
            # Must mirror rules/orchestration.json "blocking_statuses"
            # (error, failure, skipped, validation_error, unknown, null). The old
            # default omitted FAILURE — yet failing phases write ResultStatus.FAILURE
            # (not ERROR) — so on a rules-load failure the dependency gate would fail
            # OPEN and let dependents run after a prerequisite FAILURE.
            self.BLOCKING_STATUSES = {
                ResultStatus.ERROR, ResultStatus.FAILURE,
                ResultStatus.VALIDATION_ERROR, ResultStatus.SKIPPED,
                ResultStatus.UNKNOWN, None}
            self.phase_timeouts_pentest = {
                "planning": 300,
                "recon": 3600,
                "exploitation": 7200,
                "reporting": 600}
            self.phase_timeouts_redteam = {
                "planning": 300,
                "recon": 3600,
                "exploitation": 7200,
                "weaponization": 3600,
                "persistence": 3600,
                "objectives": 3600,
                "reporting": 600}

        # Phase 1: Clean up zombie processes from previous engagements
        if self.tools.remote:
            try:
                self.tools.remote.cleanup_stale_sessions()
            except Exception as e:
                log.warning(f"Zombie cleanup failed (non-fatal): {e}")

            # Phase 1b: Optimize WSL infrastructure before major scans
            try:
                optimize_vps_before_scan(self.tools.remote)
            except Exception as e:
                log.warning(f"WSL optimization failed (non-critical): {e}")

        # Incremental learning engine - runs mid-engagement, not just at report
        # time
        self._upgrader = AutoUpgrader(
            store=self.store,
            rules_dir=str(Path(__file__).parent.parent / "rules"),
        )
        # Phases that trigger a mid-engagement learning cycle
        self._INCREMENTAL_UPGRADE_AFTER = {"recon", "exploitation"}

    def _maybe_requeue_for_revisit(self, completed_phase: str):
        """W5.2 — adaptive phase revisit. If the completed phase set a bounded
        `revisit_request` in the store (a new in-scope surface worth reconning),
        re-queue recon + the dependent phases. Hard-capped to avoid loops.
        """
        eid = self.session.engagement_id
        signal_key = f"{eid}:revisit_request"
        raw = self.store.get(signal_key)
        if not raw:
            return
        # Consume the signal immediately so it can't re-fire.
        try:
            self.store.set(signal_key, "")
        except Exception:
            pass
        try:
            req = json.loads(raw) if isinstance(raw, str) else raw
        except Exception:
            return
        if not isinstance(req, dict) or not req.get("phase"):
            return

        # Hard cap: at most N revisits per engagement (default 1).
        cap = int(os.getenv("MAX_PHASE_REVISITS", "1"))
        self._revisit_count = getattr(self, "_revisit_count", 0)
        if self._revisit_count >= cap:
            log.info(
                f"[REVISIT] '{completed_phase}' requested a recon revisit but the cap "
                f"({cap}) is reached — ignoring. Reason: {str(req.get('reason'))[:120]}")
            return

        revisit_phase = req.get("phase", "recon")
        # Only allow revisiting to an EARLIER phase (a true loop-back), and only
        # phases we actually have agents for.
        if revisit_phase not in self.agents:
            return
        # Re-queue the revisit phase + the phases that depend on it (those after
        # it in the canonical order), front of the queue so it runs next.
        order = self._current_phase_order if hasattr(self, "_current_phase_order") else None
        if order and revisit_phase in order:
            idx = order.index(revisit_phase)
            requeue = [p for p in order[idx:]
                       if p in self.agents and p != "reporting"]
        else:
            requeue = [revisit_phase]
        with self._lock:
            # Avoid duplicating phases already queued ahead.
            for p in reversed(requeue):
                if p not in self.task_queue:
                    self.task_queue.insert(0, p)
        # A loop-back re-runs phases against NEW state, so the per-phase
        # applicability cache (_phase_applicable) is now stale: an optional phase
        # (e.g. persistence) skipped earlier for "no foothold yet" must be free to
        # re-evaluate against the newly-discovered surface. Clear it on revisit.
        self._phase_applicable_cache = {}
        self._revisit_count += 1
        warning(
            f"[REVISIT] {completed_phase} found a new surface — looping back to "
            f"'{revisit_phase}' (revisit {self._revisit_count}/{cap}). "
            f"Reason: {str(req.get('reason'))[:140]}")

    def _print_backend_health_report(self):
        """Print AI backend health status at orchestrator startup."""
        try:
            report = self.ai.get_backend_report()
            section("[*] AI BACKEND STATUS")

            for backend_name, backend_info in report["backends"].items():
                status = backend_info["status"]
                detail = backend_info["detail"]
                icon = backend_info["icon"]

                # Color code the status
                if status == "ONLINE":
                    info(f"  {icon} {backend_name:12} -> ONLINE ({detail})")
                elif status == "EXHAUSTED":
                    warning(
                        f"  {icon} {
                            backend_name:12} -> EXHAUSTED ({detail})")
                elif status == "MISCONFIGURED":
                    warning(
                        f"  {icon} {
                            backend_name:12} -> MISCONFIGURED ({detail})")
                elif status == "NOT_CONFIGURED":
                    error(
                        f"  {icon} {
                            backend_name:12} -> NOT CONFIGURED ({detail})")
                else:
                    error(f"  {icon} {backend_name:12} -> {status} ({detail})")

            # Check if at least one backend is available
            online_count = sum(
                1 for b in report["backends"].values() if b["status"] == "ONLINE")
            if online_count == 0:
                error(
                    "[!] WARNING: No AI backends are ONLINE. Engagement will fail without at least one backend.")
            elif online_count == 1:
                warning(
                    "[!] Only 1 backend available. Ensure primary backend is stable.")
            else:
                info(
                    f"[+] {online_count} backends available. Fallback chain active.")
        except Exception as e:
            log.warning(f"Failed to print backend health report: {e}")

    def pivot(self, next_phase: str):
        """Dynamically append a phase to the task queue for recursive execution."""
        if not hasattr(self, "task_queue"):
            log.warning(
                f"Pivot requested for {next_phase} but task queue is not initialized.")
            return

        # Basic infinite loop prevention
        with self._lock:
            if self._phase_execution_counts.get(next_phase, 0) >= 5:
                log.warning(
                    f"Pivot rejected: {next_phase} has already executed 5 times (avoiding infinite loop).")
                return

            log.info(
                f"Pivoting: dynamically appending {next_phase} to the task queue.")
            self.task_queue.append(next_phase)

    # Safety floor: these phases ALWAYS run and are never subject to the
    # adaptive skip below. This is infrastructure, not attack logic — it
    # guarantees the pipeline can't break itself (recon must feed exploitation,
    # reporting must always close the engagement).
    _MANDATORY_PHASES = {"planning", "recon", "exploitation", "reporting"}

    def _phase_applicable(self, phase_name: str) -> tuple[bool, str]:
        """FENCED adaptiveness: for an OPTIONAL phase, ask the AI whether it's
        worth running against THIS target or is pointless (e.g. 'persistence' /
        'weaponization' on a stateless serverless/CDN site, or with no foothold).

        Hard rules: mandatory phases never reach here; this FAILS OPEN — any
        error, malformed response, or ambiguity RUNS the phase. Cached per phase
        so it costs at most one AI call. The AI decides (no hardcoded per-target
        logic); the code only guarantees a conservative default."""
        cache = getattr(self, "_phase_applicable_cache", None)
        if cache is None:
            cache = self._phase_applicable_cache = {}
        if phase_name in cache:
            return cache[phase_name]

        decision = (True, "default: run")
        try:
            import re
            findings = self.store.get_all_findings(
                self.session.engagement_id) or []
            types: dict = {}
            for f in findings:
                t = (f.get("type") or "").lower()
                if t:
                    types[t] = types.get(t, 0) + 1
            foothold = any(k in types for k in (
                "confirmed_vulnerability", "foothold", "credential",
                "rce", "shell", "exploited"))
            prompt = (
                f"You are planning a {self.session.mode} engagement. Decide if the "
                f"'{phase_name}' phase is worth running against THIS target, or should "
                f"be SKIPPED as inapplicable.\n\n"
                f"Target: {self.session.target}\n"
                f"Findings so far (type:count): {json.dumps(types)}\n"
                f"Foothold/exploit confirmed: {foothold}\n\n"
                f"Skip ONLY if the phase is clearly pointless for this target (e.g. "
                f"persistence/weaponization on a stateless serverless/CDN site, or "
                f"any post-exploitation phase with no foothold). When in doubt, RUN "
                f"it. Output STRICT JSON: {{\"run\": true|false, \"reason\": \"short\"}}")
            resp = self.ai.query(
                "You are a pentest engagement planner. Be conservative — prefer "
                "running phases unless clearly pointless.", prompt)
            m = re.search(r'\{[\s\S]*\}', resp or "")
            if m:
                data = json.loads(m.group(0))
                if data.get("run") is False:
                    decision = (False, str(
                        data.get("reason", "AI: not applicable for this target"))[:160])
                else:
                    decision = (True, str(data.get("reason", "AI: run"))[:160])
        except Exception as e:
            log.debug(f"_phase_applicable failed (defaulting to RUN): {e}")
            decision = (True, "default: run (decision error)")
        cache[phase_name] = decision
        return decision

    async def run(self):
        """
        Execute all phases in order via a dynamic task queue.
        Each phase result is passed via the message bus.
        On any unhandled exception in a phase, log it and continue to next phase.
        """
        phases = (
            self.phase_order_redteam
            if self.session.mode == "redteam"
            else self.phase_order_pentest
        )
        # W5.2 — remember the canonical order so a revisit can re-queue the
        # dependent phases that follow the loop-back point.
        self._current_phase_order = list(phases)

        section(f"LAUNCHING {self.session.mode.upper()} ENGAGEMENT")
        info(f"Tactical ID: {self.session.engagement_id}")
        info(f"Target Node: {self.session.target}")
        info(f"Output Path: {self.session.results_dir}")

        engagement_start_time = time.monotonic()
        phase_metrics = {}  # Track per-phase timing and status for dashboard

        if self.health_monitor:
            self.health_monitor.start()

        self.task_queue = list(phases)
        self._phase_execution_counts = {p: 0 for p in self.agents.keys()}

        try:
            phase_results = {}
            _health_log = []  # Track VPS health across phases

            while True:
                if self.session.shutdown.is_set():
                    break

                with self._lock:
                    if not self.task_queue:
                        break
                    phase_name = self.task_queue.pop(0)
                    self._phase_execution_counts[phase_name] += 1

                agent = self.agents.get(phase_name)
                if not agent:
                    log.warning(
                        f"Phase {phase_name} requested but no agent found. Skipping.")
                    continue

                # ── Proactive Kill-Switch Check ──────────────────────────────
                if self.health_monitor and self.health_monitor.should_abort():
                    health = self.health_monitor.get_latest_health()
                    node_label = "VPS" if USE_REMOTE_VPS else "WSL"
                    reason = f"ABORTED: {node_label} health is critical. Issues: {
                        ', '.join(
                            health.get(
                                'issues',
                                []))}"
                    error(reason)
                    self.store.set_phase_status(
                        self.session.engagement_id, phase_name,
                        ResultStatus.FAILURE.value, reason
                    )
                    phase_results[phase_name] = {"error": reason}
                    break

                # ── Pre-phase VPS health check ───────────────────────────────
                if self.tools.remote:
                    try:
                        health = self.tools.remote.check_vps_health()
                        _health_log.append({"phase": phase_name, **health})

                        node_label = "VPS" if USE_REMOTE_VPS else "WSL"
                        for issue in health.get("issues", []):
                            warning(f"{node_label}: {issue}")

                        # Auto-cleanup if disk is near full
                        if health.get("disk_pct", 0) >= VPS_DISK_ABORT_PCT:
                            self.tools.remote.cleanup_tmp()

                        # Abort if disk is critically full (even after cleanup)
                        if not health.get("healthy", True):
                            health2 = self.tools.remote.check_vps_health()
                            if not health2.get("healthy", True):
                                error(
                                    f"{node_label} disk critically full ({
                                        health2.get(
                                            'disk_pct', '?')}%) "
                                    f"even after cleanup. Skipping {phase_name}."
                                )
                                self.store.set_phase_status(
                                    self.session.engagement_id, phase_name, ResultStatus.FAILURE.value,
                                    f"{node_label} disk full"
                                )
                                phase_results[phase_name] = {
                                    "error": f"{node_label} disk critically full"}
                                continue
                    except Exception as e:
                        node_label = "VPS" if USE_REMOTE_VPS else "WSL"
                        log.debug(
                            f"{node_label} health check failed (non-fatal): {e}")

                # ── Phase dependency check ───────────────────────────────────
                skip_phase = False
                required = self.PHASE_REQUIRES.get(phase_name, [])
                for req_phase in required:
                    req_status = self.store.get_phase_status(
                        self.session.engagement_id, req_phase
                    )
                    blocking_vals = {
                        s.value if hasattr(
                            s, "value") else s for s in self.BLOCKING_STATUSES}
                    if req_status in blocking_vals:
                        # [HARDENING] Even if status is 'error' or 'None', check if phase
                        # produced any usable data before skipping dependents.
                        if self.store.has_findings(
                                self.session.engagement_id, req_phase):
                            info(
                                f"Required phase '{req_phase}' had issues ({req_status}), "
                                f"but produced findings. Continuing to '{phase_name}'."
                            )
                            continue

                        reason = (
                            f"Required phase '{req_phase}' has status '{req_status}' and no findings. "
                            f"Skipping '{phase_name}'."
                        )
                        warning(reason)
                        self.store.set_phase_status(
                            self.session.engagement_id, phase_name,
                            ResultStatus.SKIPPED.value, reason
                        )
                        phase_results[phase_name] = {"error": reason}
                        skip_phase = True
                        break

                if skip_phase:
                    continue

                # ── Adaptive (FENCED) phase applicability ────────────────────
                # Target-shaped execution: let the AI skip an OPTIONAL phase that
                # is pointless for this target (e.g. persistence on a serverless
                # SPA). Mandatory phases (planning/recon/exploitation/reporting)
                # always run; _phase_applicable fails OPEN, so any uncertainty
                # runs the phase — this can only ever PRUNE clearly-dead work,
                # never starve a needed phase.
                if phase_name not in self._MANDATORY_PHASES:
                    _run_it, _why = self._phase_applicable(phase_name)
                    if not _run_it:
                        info(
                            f"[ADAPTIVE] Skipping optional phase '{phase_name}' "
                            f"for this target: {_why}")
                        self.store.set_phase_status(
                            self.session.engagement_id, phase_name,
                            ResultStatus.SKIPPED.value, _why)
                        phase_results[phase_name] = {
                            "skipped": True, "reason": _why}
                        continue

                # ── Agent-level preflight check ──────────────────────────────
                try:
                    can_proceed, preflight_reason = agent._preflight()
                    if not can_proceed:
                        reason = f"Pre-flight failed: {preflight_reason}"
                        warning(f"Phase '{phase_name}': {reason}")
                        self.store.set_phase_status(
                            self.session.engagement_id, phase_name,
                            ResultStatus.SKIPPED.value, reason
                        )
                        phase_results[phase_name] = {"error": reason}
                        continue
                except Exception as e:
                    log.error(
                        f"Pre-flight check EXCEPTION for '{phase_name}': {e}",
                        exc_info=True)
                    reason = f"Pre-flight exception: {str(e)[:200]}"
                    self.store.set_phase_status(
                        self.session.engagement_id, phase_name,
                        ResultStatus.SKIPPED.value, reason
                    )
                    phase_results[phase_name] = {"error": reason}
                    continue

                try:
                    phase_start_time = time.monotonic()
                    # Show kill chain pipeline status
                    completed_statuses = {
                        p: m.get(
                            "status",
                            "unknown") for p,
                        m in phase_metrics.items()}
                    kill_chain_status(
                        list(phases),
                        current_phase=phase_name,
                        completed=completed_statuses)
                    phase_header(phase_name)
                    import threading

                    # ── W1.2: attribute token usage to this phase ────────────
                    try:
                        if hasattr(self.ai, "set_current_phase"):
                            self.ai.set_current_phase(phase_name)
                    except Exception as _ph_err:
                        log.debug(f"set_current_phase failed (non-fatal): {_ph_err}")

                    # ── CHECKPOINT BACKUP ────────────────────────────────────
                    if phase_name in ["exploitation", "weaponization"]:
                        try:
                            checkpoint_dir = self.session.results_dir / "checkpoints"
                            checkpoint_dir.mkdir(parents=True, exist_ok=True)
                            checkpoint_path = checkpoint_dir / \
                                f"test_v7_{phase_name}_{int(time.time())}.db"
                            # Using native sqlite3 backup to prevent corruption
                            # in WAL mode
                            db_path_str = str(
                                self.store.db_path) if self.store.db_path else ""
                            is_file_db = db_path_str and not db_path_str.startswith(
                                "file:") and db_path_str != ":memory:"
                            if is_file_db and Path(db_path_str).exists():
                                import sqlite3
                                try:
                                    dst = sqlite3.connect(checkpoint_path)
                                    self.store.conn.backup(dst)
                                    dst.close()
                                    log.info(
                                        f"Created SQLite checkpoint before {phase_name}: {checkpoint_path}")
                                except sqlite3.Error as e:
                                    log.error(
                                        f"Native SQLite backup failed: {e}")
                        except Exception as e:
                            log.warning(
                                f"Failed to create SQLite checkpoint before {phase_name}: {e}")
                    # ──────────────────────────────────────────────────────────────

                    # ── FIX #7: PHASE VALIDATION GATE ────────────────────────
                    # Check if this phase has necessary prerequisites from
                    # earlier phases
                    if hasattr(agent, "validate_phase_prerequisites"):
                        can_proceed, gate_reason = agent.validate_phase_prerequisites()
                        if not can_proceed:
                            log.warning(
                                f"Phase '{phase_name}' validation GATE FAILED: {gate_reason}")
                            self.store.set_phase_status(
                                self.session.engagement_id, phase_name,
                                ResultStatus.SKIPPED.value, f"Prerequisite gate: {gate_reason}"
                            )
                            phase_results[phase_name] = {
                                "error": f"Gate failed: {gate_reason}"}
                            continue
                    # ──────────────────────────────────────────────────────────────

                    # Phase-level timeout (prevent hangs) - load from rules
                    phase_timeouts = (
                        self.phase_timeouts_redteam if self.session.mode == "redteam"
                        else self.phase_timeouts_pentest
                    )
                    phase_timeout = phase_timeouts.get(phase_name, 1800)

                    if hasattr(agent, "set_phase_deadline"):
                        agent.set_phase_deadline(time.monotonic() + phase_timeout)

                    result = None
                    _agent_debug_log(
                        "core/orchestrator.py:phase_start",
                        "Starting phase run with thread timeout",
                        {"phase": phase_name, "phase_timeout_s": phase_timeout},
                        run_id="run1",
                        hypothesis_id="H1",
                    )

                    import asyncio

                    async def run_agent_async():
                        try:
                            # Support both sync and async agent.run().
                            # P4-1 (ORCH-TIMEOUT-1): a SYNC agent.run() must run in
                            # a WORKER THREAD (asyncio.to_thread), never directly in
                            # the event loop. The old code called agent.run() inline
                            # here, so a blocking sleep inside it (e.g. the AI-backend
                            # recovery wait) pinned the loop and BLINDED the phase
                            # asyncio.timeout below — the deadline could never fire
                            # until the sync call returned. Off-loading to a thread
                            # keeps the loop free to enforce the timeout (the thread
                            # finishes its now-bounded work in the background).
                            import inspect
                            if inspect.iscoroutinefunction(agent.run):
                                res = await agent.run()
                            else:
                                res = await asyncio.to_thread(agent.run)
                            _agent_debug_log(
                                "core/orchestrator.py:run_agent_complete",
                                "Agent task completed",
                                {"phase": phase_name,
                                 "result_type": type(res).__name__},
                                run_id="run1",
                                hypothesis_id="H1",
                            )
                            return res
                        except Exception as e:
                            import traceback
                            traceback.print_exc()
                            _agent_debug_log(
                                "core/orchestrator.py:run_agent_exception",
                                "Agent task raised exception",
                                {"phase": phase_name, "error": str(e)[:200]},
                                run_id="run1",
                                hypothesis_id="H1",
                            )
                            raise e

                    try:
                        with phase_spinner(phase_name):
                            async with asyncio.timeout(phase_timeout + 60):
                                async with asyncio.TaskGroup() as tg:
                                    task = tg.create_task(run_agent_async())
                            result = task.result()
                    except TimeoutError:
                        reason = f"Phase '{phase_name}' exceeded {phase_timeout}s timeout and was aborted."
                        _agent_debug_log(
                            "core/orchestrator.py:phase_timeout_branch",
                            "Timeout branch entered via asyncio.timeout",
                            {"phase": phase_name, "thread_alive": False},
                            run_id="run1",
                            hypothesis_id="H1",
                        )
                        error(reason)
                        self.store.set_phase_status(
                            self.session.engagement_id, phase_name,
                            ResultStatus.TIMEOUT.value, reason
                        )
                        phase_results[phase_name] = {
                            "error": reason, "timeout": True}
                        phase_duration = time.monotonic() - phase_start_time
                        all_db_findings = self.store.get_all_findings(
                            self.session.engagement_id)
                        findings_count = sum(
                            1 for f in all_db_findings if f.get("phase") == phase_name)
                        phase_complete(
                            phase_name, "timeout", phase_duration, findings_count)
                        phase_metrics[phase_name] = {
                            "status": "timeout",
                            "duration": phase_duration,
                            "findings": findings_count}
                        continue

                    # ── Boundary Validation ──────────────────────────────────
                    from core.result_contracts import ResultValidator
                    result = ResultValidator.enforce_boundary(
                        result, phase_name, "phase_result", log)

                    phase_results[phase_name] = result
                    phase_duration = time.monotonic() - phase_start_time
                    all_db_findings = self.store.get_all_findings(
                        self.session.engagement_id)
                    findings_count = sum(
                        1 for f in all_db_findings if f.get("phase") == phase_name)

                    actual_status = result.status.value if hasattr(
                        result.status, "value") else str(result.status)
                    self.store.set_phase_status(
                        self.session.engagement_id, phase_name, actual_status,
                        result.error_message or f"Completed with status {actual_status}"
                    )

                    phase_complete(
                        phase_name,
                        actual_status,
                        phase_duration,
                        findings_count)
                    phase_metrics[phase_name] = {
                        "status": actual_status,
                        "duration": phase_duration,
                        "findings": findings_count}

                    # ── W5.2: ADAPTIVE PHASE REVISIT (chevron, not one-way) ──
                    # An agent (typically exploitation) may discover a new attack
                    # surface the Target Model didn't cover — a fresh in-scope
                    # subdomain/host/auth surface. When it sets a bounded revisit
                    # request, re-queue a scoped recon (then the dependent phases)
                    # so the engine loops back instead of pressing on blind.
                    try:
                        self._maybe_requeue_for_revisit(phase_name)
                    except Exception as _rv_err:
                        log.debug(f"phase-revisit check failed (non-fatal): {_rv_err}")

                    # ── Shift-left learning: incremental upgrade ─────────────
                    if phase_name in self._INCREMENTAL_UPGRADE_AFTER:
                        eng_id = self.session.engagement_id
                        upgrader_ref = self._upgrader

                        def _bg_upgrade(eid=eng_id, ph=phase_name,
                                        up=upgrader_ref):
                            try:
                                up.run_incremental_upgrade(eid, after_phase=ph)
                            except Exception as _ue:
                                log.warning(
                                    f"Incremental upgrade after '{ph}' failed (non-fatal): {_ue}")
                        t_up = threading.Thread(
                            target=_bg_upgrade, daemon=True, name=f"upgrader-{phase_name}")
                        t_up.start()
                        info(
                            f"[Learning] Incremental upgrade triggered in background after '{phase_name}'.")

                except Exception as e:
                    # The phase runs inside an asyncio.TaskGroup, so a normal
                    # agent exception arrives WRAPPED in an ExceptionGroup whose
                    # str() is the useless "unhandled errors in a TaskGroup (N
                    # sub-exception(s))". Storing that as the phase failure reason
                    # hid the ACTUAL error from logs/report (why a crashed phase
                    # looked like a generic failure). Unwrap to the leaf cause.
                    _leaf = e
                    while isinstance(_leaf, BaseExceptionGroup) and _leaf.exceptions:
                        _leaf = _leaf.exceptions[0]
                    err_msg = f"{type(_leaf).__name__}: {_leaf}" if str(_leaf) else repr(_leaf)
                    phase_results[phase_name] = {
                        "phase": phase_name,
                        "status": ResultStatus.FAILURE,
                        "error_message": err_msg,
                        "exception_traceback": traceback.format_exc()
                    }
                    self.store.set_phase_status(
                        self.session.engagement_id, phase_name,
                        ResultStatus.FAILURE.value, err_msg
                    )

                    # Still enforce boundary even on failure to ensure
                    # structure
                    from core.result_contracts import ResultValidator
                    phase_results[phase_name] = ResultValidator.enforce_boundary(
                        phase_results[phase_name], phase_name, "phase_result", log
                    )

                    phase_duration = time.monotonic() - phase_start_time
                    all_db_findings = self.store.get_all_findings(
                        self.session.engagement_id)
                    findings_count = sum(
                        1 for f in all_db_findings if f.get("phase") == phase_name)
                    phase_complete(
                        phase_name,
                        "error",
                        phase_duration,
                        findings_count)
                    phase_metrics[phase_name] = {
                        "status": "error",
                        "duration": phase_duration,
                        "findings": findings_count}

                    # Handle reporting specially - don't kill the app if report
                    # format fails
                    if phase_name == "reporting":
                        warning(
                            "Reporting phase failed. Attempting to save raw collected data...")
                        self._save_partial_results(phase_results)
                        continue  # Already last phase anyway

                    # For other phases, we continue to the next one

        except Exception as e:
            error(f"FATAL ERROR in engagement: {e}")
            log.critical(traceback.format_exc())
        finally:
            if self.health_monitor:
                self.health_monitor.stop()

            # ── Final Engagement Dashboard ────────────────────────────────
            total_duration = time.monotonic() - engagement_start_time
            engagement_dashboard(
                phases=phase_metrics,
                total_duration_s=total_duration,
                engagement_id=self.session.engagement_id,
                target=self.session.target,
            )

            # ── Post-engagement: save health summary + cleanup ────────────
            self._save_health_summary(phase_results, _health_log)

            # Final zombie cleanup - guard against VPS disconnect during long
            # phases
            try:
                if self.tools.remote and hasattr(
                        self.tools.remote, 'is_active') and self.tools.remote.is_active():
                    self.tools.remote.cleanup_stale_sessions()
            except Exception as _cleanup_err:
                log.debug(
                    f"Post-engagement cleanup skipped (VPS may have disconnected): {_cleanup_err}")

            self.store.close()

        return phase_results

    def _save_health_summary(self, phase_results: dict, health_log: list):
        """Save engagement health metrics for post-mortem analysis."""
        try:
            import json

            # Collect per-agent resilience stats
            agent_stats = {}
            for name, agent in self.agents.items():
                tls_blocked = getattr(agent, "_tls_blocked_hosts", {})
                findings = getattr(agent, "_findings", [])
                dedup_counts = getattr(agent, "_finding_dedup_counts", {})
                agent_stats[name] = {
                    "tls_blocked_hosts": list(tls_blocked.keys()),
                    "findings_count": len(findings),
                    "dedup_suppressed": sum(dedup_counts.values()) if dedup_counts else 0,
                }

            summary = {
                "engagement_id": self.session.engagement_id,
                "target": self.session.target,
                "vps_health_log": health_log,
                "agent_stats": agent_stats,
                "phases_errored": [
                    p for p, r in phase_results.items()
                    if isinstance(r, dict) and "error" in r
                ],
            }

            path = self.session.results_dir / "logs" / "health_summary.json"
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(
                json.dumps(
                    summary,
                    indent=2,
                    default=str),
                encoding="utf-8")
            info(f"Health summary saved: {path}")
        except Exception as e:
            log.error(f"Failed to save health summary: {e}")

    def _save_partial_results(self, phase_results: dict):
        """Emergency save of raw results if the reporting phase fails."""
        try:
            import json
            backup_path = self.session.results_dir / "report" / "emergency_results.json"
            backup_path.parent.mkdir(parents=True, exist_ok=True)
            backup_path.write_text(
                json.dumps(
                    phase_results,
                    indent=2,
                    default=str),
                encoding="utf-8")
            info(f"Emergency results saved to: {backup_path}")
        except Exception as e:
            log.error(f"Failed to save emergency results: {e}")


class OrchestratorAgent(BaseAgent):
    def __init__(self, name: str = "orchestrator_agent", **kwargs):
        super().__init__(name, **kwargs)
        # Import specialists lazily to avoid circular imports
        from agents.specialists import ReconSpecialist, ExploitSpecialist, ResearchSpecialist
        self.specialists = {
            "recon": ReconSpecialist("recon_specialist",
                                     session=self.session, state_store=self.store, tool_manager=self.tools,
                                     ai_backend=self.ai, message_bus=self.bus, scope_enforcer=self.scope,
                                     validation=self.validation, capability_registry=self.cap_reg, orchestrator=self.orchestrator
                                     ),
            "exploit": ExploitSpecialist("exploit_specialist",
                                         session=self.session, state_store=self.store, tool_manager=self.tools,
                                         ai_backend=self.ai, message_bus=self.bus, scope_enforcer=self.scope,
                                         validation=self.validation, capability_registry=self.cap_reg, orchestrator=self.orchestrator
                                         ),
            "research": ResearchSpecialist("research_specialist",
                                           session=self.session, state_store=self.store, tool_manager=self.tools,
                                           ai_backend=self.ai, message_bus=self.bus, scope_enforcer=self.scope,
                                           validation=self.validation, capability_registry=self.cap_reg, orchestrator=self.orchestrator
                                           ),
        }

    async def delegate_to_specialist(
            self, agent_role: str, subtask_context: str) -> dict:
        self.log.info(
            f"Delegating to specialist '{agent_role}' with subtask: {subtask_context}")
        specialist = self.specialists.get(agent_role)
        if not specialist:
            return {"status": "error",
                    "error": f"Unknown specialist role: {agent_role}"}

        # Run specialist
        import inspect
        try:
            res_or_coro = specialist.run(subtask_context)
            if inspect.isawaitable(res_or_coro):
                return await res_or_coro
            else:
                return res_or_coro
        except Exception as e:
            self.log.error(f"Specialist execution failed: {e}")
            return {"status": "error", "error": str(e)}

    async def run(self, objective: str = None) -> dict:
        if not objective:
            objective = self.session.target

        self.log.info(
            f"OrchestratorAgent starting with objective: {objective}")
        # Decompose objective using AI
        prompt = (
            f"Objective: {objective}\n\n"
            "Decompose this high-level offensive security objective into a list of sequential subtasks for specialists.\n"
            "Specialist roles available:\n"
            "- recon: For port scanning, domain/subdomain discovery, and probing.\n"
            "- exploit: For SQL injection, payload generation, brute force, and initial access.\n"
            "- research: For web searches, reading documentation, and analyzing files.\n\n"
            "Return a JSON array of subtasks, ordered logically. Each subtask MUST have the following format:\n"
            "{\n"
            "  \"role\": \"recon\" | \"exploit\" | \"research\",\n"
            "  \"task\": \"detailed description of the specific subtask\"\n"
            "}\n"
            "Output ONLY the JSON array."
        )

        try:
            ai_resp = self.think(prompt, mode="nano")
            ai_resp = ai_resp.strip()
            if ai_resp.startswith("```json"):
                ai_resp = ai_resp[7:]
            if ai_resp.startswith("```"):
                ai_resp = ai_resp[3:]
            if ai_resp.endswith("```"):
                ai_resp = ai_resp[:-3]
            ai_resp = ai_resp.strip()

            from core.robust_parser import extract_json_list
            subtasks = extract_json_list(ai_resp)
        except Exception as e:
            self.log.error(f"Failed to decompose task: {e}")
            subtasks = [
                {"role": "recon",
                 "task": f"Scan open ports and services for target: {objective}"},
                {"role": "exploit",
                 "task": f"Look for exploitable vulnerabilities on target: {objective}"}
            ]

        self.log.info(
            f"Decomposed objective into {
                len(subtasks)} subtasks: {subtasks}")
        findings = []

        for i, subtask in enumerate(subtasks):
            role = subtask.get("role")
            task_desc = subtask.get("task")
            self.log.info(
                f"Executing subtask {i + 1}/{len(subtasks)}: [{role}] {task_desc}")

            res = await self.delegate_to_specialist(role, task_desc)
            findings.append({"subtask": subtask, "result": res})

            if isinstance(res, dict) and res.get("status") == "error":
                self.log.warning(f"Subtask failed: {res.get('error')}")

        return {"status": "complete", "findings": findings}
