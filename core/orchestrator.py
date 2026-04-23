from core.session import EngagementSession
from core.state_store import StateStore
from core.message_bus import MessageBus
from core.scope_enforcer import ScopeEnforcer
from core.ai_backend import AIBackend
from tools.tool_manager import ToolManager
from agents.planning_agent import PlanningAgent
from agents.recon_agent import ReconAgent
from agents.weaponization_agent import WeaponizationAgent
from agents.exploitation_agent import ExploitationAgent
from agents.persistence_agent import PersistenceAgent
from agents.objectives_agent import ObjectivesAgent
from agents.reporting_agent import ReportingAgent
from utils.display import section, info, error, warning, success
from utils.logger import get_logger, configure_log_dir
from config import USE_REMOTE_VPS

log = get_logger("orchestrator")

class Orchestrator:
    def __init__(self, session: EngagementSession):
        self.session = session
        
        # Wire global logging directory
        configure_log_dir(session.results_dir / "logs")

        # Initialize shared infrastructure
        self.store = StateStore(session.db_path)
        self.bus = MessageBus(self.store, session.engagement_id)
        self.scope = ScopeEnforcer(session)
        self.ai = AIBackend(preferred_backend=session.ai_backend)

        self.tools = ToolManager(session, self.store, ai_backend=self.ai)

        # Initialize all agents with shared infrastructure
        agent_kwargs = dict(
            session=session,
            state_store=self.store,
            tool_manager=self.tools,
            ai_backend=self.ai,
            message_bus=self.bus,
            scope_enforcer=self.scope
        )

        self.agents = {
            "planning":       PlanningAgent("planning",       **agent_kwargs),
            "recon":          ReconAgent("recon",              **agent_kwargs),
            "weaponization":  WeaponizationAgent("weaponization", **agent_kwargs),
            "exploitation":   ExploitationAgent("exploitation", **agent_kwargs),
            "persistence":    PersistenceAgent("persistence",  **agent_kwargs),
            "objectives":     ObjectivesAgent("objectives",    **agent_kwargs),
            "reporting":      ReportingAgent("reporting",      **agent_kwargs),
        }

        # Pentest mode runs a subset of phases
        self.phase_order_pentest = [
            "planning", "recon", "exploitation", "reporting"
        ]
        self.phase_order_redteam = [
            "planning", "recon", "exploitation", "weaponization",
            "persistence", "objectives", "reporting"
        ]

        # Phase dependency map: {phase: [required_phases]}
        # If a required phase has a blocking status, the dependent phase is skipped.
        self.PHASE_REQUIRES = {
            "exploitation": ["recon"],
            "weaponization": ["exploitation"],
            "persistence":  ["exploitation"],
            "objectives":   ["exploitation"],
            "reporting":    ["recon"],
        }
        self.BLOCKING_STATUSES = {"error", "preflight_skipped", "skipped", None}

        # Phase 1: Clean up zombie processes from previous engagements
        if USE_REMOTE_VPS and self.tools.remote:
            try:
                self.tools.remote.cleanup_stale_sessions()
            except Exception as e:
                log.warning(f"Zombie cleanup failed (non-fatal): {e}")

    def run(self):
        """
        Execute all phases in order. Each phase result is passed via the message bus.
        On any unhandled exception in a phase, log it and continue to next phase.
        """
        phases = (
            self.phase_order_redteam
            if self.session.mode == "redteam"
            else self.phase_order_pentest
        )

        section(f"STARTING {self.session.mode.upper()} ENGAGEMENT")
        info(f"Engagement ID: {self.session.engagement_id}")
        info(f"Target: {self.session.target}")
        info(f"Results: {self.session.results_dir}")

        phase_results = {}
        _health_log = []  # Track VPS health across phases

        for phase_name in phases:
            agent = self.agents[phase_name]

            # ── Pre-phase VPS health check ───────────────────────────────
            if USE_REMOTE_VPS and self.tools.remote:
                try:
                    health = self.tools.remote.check_vps_health()
                    _health_log.append({"phase": phase_name, **health})

                    for issue in health.get("issues", []):
                        warning(f"VPS: {issue}")

                    # Auto-cleanup if disk is near full
                    if health["disk_pct"] >= 90:
                        self.tools.remote.cleanup_tmp()

                    # Abort if disk is critically full (even after cleanup)
                    if not health["healthy"]:
                        health2 = self.tools.remote.check_vps_health()
                        if not health2["healthy"]:
                            error(
                                f"VPS disk critically full ({health2['disk_pct']}%) "
                                f"even after cleanup. Skipping {phase_name}."
                            )
                            self.store.set_phase_status(
                                self.session.engagement_id, phase_name, "error",
                                "VPS disk full"
                            )
                            phase_results[phase_name] = {"error": "VPS disk critically full"}
                            continue
                except Exception as e:
                    log.debug(f"VPS health check failed (non-fatal): {e}")

            # ── Phase dependency check ───────────────────────────────────
            skip_phase = False
            required = self.PHASE_REQUIRES.get(phase_name, [])
            for req_phase in required:
                req_status = self.store.get_phase_status(
                    self.session.engagement_id, req_phase
                )
                if req_status in self.BLOCKING_STATUSES:
                    reason = (
                        f"Required phase '{req_phase}' has status '{req_status}'. "
                        f"Skipping '{phase_name}'."
                    )
                    warning(reason)
                    self.store.set_phase_status(
                        self.session.engagement_id, phase_name,
                        "preflight_skipped", reason
                    )
                    phase_results[phase_name] = {"error": reason}
                    skip_phase = True
                    break

            if skip_phase:
                continue

            # ── Agent-level preflight check ──────────────────────────────
            try:
                can_proceed, preflight_reason = agent._preflight()
                if not can_proceed:
                    reason = f"Pre-flight failed: {preflight_reason}"
                    warning(f"Phase '{phase_name}': {reason}")
                    self.store.set_phase_status(
                        self.session.engagement_id, phase_name,
                        "preflight_skipped", reason
                    )
                    phase_results[phase_name] = {"error": reason}
                    continue
            except Exception as e:
                log.warning(f"Pre-flight check failed for '{phase_name}': {e}")

            try:
                log.info(f"Starting phase: {phase_name}")
                result = agent.run()
                phase_results[phase_name] = result
                log.info(f"Phase '{phase_name}' completed successfully.")
            except Exception as e:
                log.error(f"Phase '{phase_name}' encountered an unhandled error: {e}", exc_info=True)
                error(f"Phase '{phase_name}' failed: {e}. Continuing to next phase.")
                self.store.set_phase_status(
                    self.session.engagement_id, phase_name, "error", str(e)
                )
                phase_results[phase_name] = {"error": str(e)}

                # Handle reporting specially - don't kill the app if report format fails
                if phase_name == "reporting":
                    warning("Reporting phase failed. Attempting to save raw collected data...")
                    self._save_partial_results(phase_results)
                    continue # Already last phase anyway
                
                # For other phases, we continue to the next one

        # ── Post-engagement: save health summary + cleanup ────────────
        self._save_health_summary(phase_results, _health_log)

        # Final zombie cleanup
        if USE_REMOTE_VPS and self.tools.remote:
            try:
                self.tools.remote.cleanup_stale_sessions()
            except Exception:
                pass

        self.store.close()
        return phase_results

    def _save_health_summary(self, phase_results: dict, health_log: list):
        """Save engagement health metrics for post-mortem analysis."""
        try:
            import json

            # Collect per-agent resilience stats
            agent_stats = {}
            for name, agent in self.agents.items():
                agent_stats[name] = {
                    "tls_blocked_hosts": list(agent._tls_blocked_hosts.keys()),
                    "findings_count": len(agent._findings),
                    "dedup_suppressed": sum(agent._finding_dedup_counts.values())
                        if agent._finding_dedup_counts else 0,
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
            path.write_text(json.dumps(summary, indent=2, default=str), encoding="utf-8")
            info(f"Health summary saved: {path}")
        except Exception as e:
            log.error(f"Failed to save health summary: {e}")

    def _save_partial_results(self, phase_results: dict):
        """Emergency save of raw results if the reporting phase fails."""
        try:
            import json
            backup_path = self.session.results_dir / "report" / "emergency_results.json"
            backup_path.parent.mkdir(parents=True, exist_ok=True)
            backup_path.write_text(json.dumps(phase_results, indent=2, default=str), encoding="utf-8")
            info(f"Emergency results saved to: {backup_path}")
        except Exception as e:
            log.error(f"Failed to save emergency results: {e}")
