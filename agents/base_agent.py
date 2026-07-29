"""
base_agent.py - Ghostwire V6 Autonomous ReAct Agent (merged with V5 compat)
"""
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Optional, TYPE_CHECKING
from utils.logger import get_logger
from utils.display import agent_msg
from core.result_contracts import ToolResult, ResultStatus, PhaseResult
from tools.tool_registry import VIRTUAL_TOOLS, HTTP_TOOLS
import re
import json
import os
import time
import time as _time_module
import threading
from utils.sanitizer import clean_text
from utils.validator import is_valid_target
from utils.guardian import block_or_repair
import requests
from core.safe_executor import should_retry, classify_unrepairable
from core.ip_rotator import IpRotator
from core.waf_ghost_engine import WafGhostEngine
from intelligence.waf_evasion_engine import WafEvasionEngine
from intelligence.tool_success_tracker import ToolSuccessTracker
from core.config_manager import get_config
import posixpath
import config_paths

if TYPE_CHECKING:
    # Imported only for the forward-ref type annotations in __init__ below.
    # Kept under TYPE_CHECKING to avoid runtime circular imports.
    from core.session import EngagementSession
    from core.state_store import StateStore
    from tools.tool_manager import ToolManager
    from core.ai_backend import AIBackend
    from core.message_bus import MessageBus
    from core.scope_enforcer import ScopeEnforcer
    from core.orchestrator import Orchestrator
    from agents.validation_agent import ValidationAgent
import shlex
import hashlib
from intelligence.waf_bypass_orchestrator import WafBypassOrchestrator
from intelligence.waf_learner import WafLearner
from intelligence.self_awareness_module import SelfAwarenessModule
from intelligence.structured_analyzer import StructuredAnalyzer
from intelligence.reasoning_engine import ReasoningEngine
from intelligence.strategic_advisor import StrategicAdvisor
from intelligence.syntax_learner import SyntaxLearner
from core.attack_graph import AttackGraph

# ── V6 imports ──
from core.target_context import TargetContext
from core.capability_registry import CapabilityRegistry, RiskLevel

# Load config once at module level
config = get_config()
# USE_REMOTE_VPS removed as execution is always via WSL
CURL_TLS_FLAGS = "--tls1.2 --tlsv1.2"  # Default TLS flags
STEALTH_HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
}
TLS_BREAKER_BACKOFF_SECS = 60
TLS_BREAKER_MAX_RETRIES = 3
POST_HEAVY_SCAN_COOLDOWN = 90
NETWORK_UNFIXABLE_EXITS = {3, 6, 7, 28, 35, 52, 56}
MAX_RESPONSE_SIZE = 1048576  # 1MB
RATE_LIMIT_INITIAL_BACKOFF = config.timeout.rate_limit_initial_backoff
RATE_LIMIT_MAX_BACKOFF = config.timeout.rate_limit_max_backoff
HOST_MAX_TOTAL_ERRORS = 10
TOOL_DEFAULT_TIMEOUT = config.timeout.tool_default
TOOL_VERIFY_TIMEOUT = config.timeout.tool_verify


class ReActAction:
    """An action the AI wants to take in the ReAct loop."""

    def __init__(self, capability: str, target_url: str,
                 params: dict, reason: str = ""):
        self.capability = capability
        self.target_url = target_url
        self.params = params
        self.reason = reason
        self.result = None

    def to_dict(self) -> dict:
        return {
            "capability": self.capability,
            "target_url": self.target_url,
            "params": self.params,
            "reason": self.reason,
            "result_summary": str(self.result)[:200] if self.result else None,
        }


class BaseAgent(ABC):
    def __init__(
        self,
        name: str,
        session: "EngagementSession",
        state_store: "StateStore",
        tool_manager: "ToolManager",
        ai_backend: "AIBackend",
        message_bus: "MessageBus",
        scope_enforcer: "ScopeEnforcer",
        validation: Optional["ValidationAgent"] = None,
        capability_registry: Optional["CapabilityRegistry"] = None,
        orchestrator: Optional["Orchestrator"] = None
    ) -> None:
        self.name = name
        self.session = session
        self.store = state_store
        self.tools = tool_manager
        self.ai = ai_backend
        self.bus = message_bus
        self.scope = scope_enforcer
        self.validation = validation
        self.orchestrator = orchestrator
        self.cap_registry = capability_registry

        self.attack_graph = AttackGraph(self.store)

        # ── V6 Agent Communication ──
        self.log = get_logger(f"agent.{name}")
        self._findings = []
        self._findings_seen: set = set()
        self._findings_lock = threading.Lock()
        self._finding_dedup_counts = {}
        self._tls_blocked_hosts = {}
        self._host_rate_limits = {}
        self._tool_timeout_history = {}
        self._host_error_counts = {}
        self._recent_failures = []

        # ── V6 Anti-Timeout Intelligence ──
        # cmd_hash -> {ts: float, status: str}
        self._command_history: dict[str, dict] = {}
        # "tool@target" -> consecutive fails
        self._tool_failure_counts: dict[str, int] = {}
        # "tool@target" banned permanently
        self._tool_ban_list: set[str] = set()
        # tools that have had --help checked
        self._tools_validated: set[str] = set()

        # ── FIX #6: Persistent Repair History ──
        # cmd_hash -> [error1, error2, ...]
        self._repair_attempts_history: dict[str, list] = {}
        # error_pattern -> successful_strategy
        self._successful_repair_strategies: dict[str, str] = {}
        # "tool@target" -> current timeout multiplier
        self._timeout_escalation: dict[str, int] = {}
        # hashes of AI-suggested repairs already tried
        self._repaired_cmds: set[str] = set()
        # V6: Cross-phase nuclei stealth counter
        self._nuclei_timeout_count = 0
        #   Purpose: prevents the identical-repair loop where two different original
        #   failures produce the same AI suggestion. Without this, the loop fires the
        # same broken repair repeatedly because each original has a different
        # hash.

        # ── V6 additions ──
        # Capability registry (auto-construct if orchestrator hasn't passed
        # one)
        if capability_registry is None:
            ssh = getattr(tool_manager, "remote", None)
            capability_registry = CapabilityRegistry(
                remote_executor=ssh, ai_backend=ai_backend)
        self.cap_reg = capability_registry
        self._react_history = []
        self._max_react_iterations = 20
        self._max_repeat_failures = 3

        # Seed persistent memory
        try:
            if state_store:
                xf = state_store.get_cross_engagement_failures(limit=10)
                for rec in xf:
                    snippet = (
                        f"[HISTORY] tool={rec.get('tool', '?')} "
                        f"error={rec.get('error_type', '?')} "
                        f"avoid={rec.get('avoid_next', '?')[:80]}"
                    )
                    self._recent_failures.append(snippet)

            # Also load from local persistent storage (V6 addition)
            history_file = config_paths.FAILURE_HISTORY_FILE
            if history_file.exists():
                try:
                    local_hist = json.loads(history_file.read_text())
                    if isinstance(local_hist, dict):
                        # ONLY load escalation config, DO NOT load recent_failures or tool_failure_counts
                        # Banning tools globally across engagements breaks
                        # fresh targets!
                        self._timeout_escalation = local_hist.get(
                            "timeout_escalation", {})
                        self._nuclei_timeout_count = local_hist.get(
                            "nuclei_timeout_count", 0)
                except Exception as e:
                    self.log.error(
                        f"CRITICAL: Failed to parse local failure history: {e}",
                        exc_info=True)
                    raise

        except Exception as e:
            self.log.debug(f"Failed to load cross-engagement failures: {e}")

        # ── V6 CROSS-PHASE DATA LOADING: Restore state from StateStore ───────
        try:
            if state_store and session and hasattr(session, "engagement_id"):
                # Load nuclei timeout count
                ntc = state_store.get(
                    f"{session.engagement_id}:nuclei_timeout_count")
                if ntc is not None:
                    try:
                        self._nuclei_timeout_count = int(ntc)
                        self.log.info(
                            f"[STEALTH] Restored nuclei timeout count: {
                                self._nuclei_timeout_count}")
                    except (ValueError, TypeError) as _ntc_err:
                        self.log.warning(
                            f"[STEALTH] Invalid nuclei timeout count value '{ntc}': {_ntc_err}")

                # Load bans
                raw_bans = state_store.get(
                    f"{session.engagement_id}:tool_bans")
                if raw_bans:
                    if isinstance(raw_bans, str):
                        loaded_bans = json.loads(raw_bans)
                    else:
                        loaded_bans = list(raw_bans)
                    for ban in loaded_bans:
                        self._tool_ban_list.add(str(ban))
                    if loaded_bans:
                        self.log.info(
                            f"[TOOL BAN] Loaded {
                                len(loaded_bans)} persistent ban(s) from previous phase: {loaded_bans}")
        except Exception as _load_err:
            self.log.debug(
                f"Failed to load persistent cross-phase data: {_load_err}")
        # ─────────────────────────────────────────────────────────────────────────────

        # Metrics Tracking (Resilient to None session)
        metrics_path = config_paths.TOOL_METRICS_FILE
        if session and hasattr(session, 'results_dir'):
            results_dir = Path(
                session.results_dir) if isinstance(
                session.results_dir,
                str) else session.results_dir
            metrics_path = results_dir / "tool_metrics.json"

        self.tool_tracker = ToolSuccessTracker(db_path=metrics_path)

        self._ssh = getattr(self.tools, "remote", None) if self.tools else None
        self.use_remote_vps = get_config().vps.use_remote_vps
        self.node_label = "VPS" if self.use_remote_vps else "WSL"
        self._stealth = getattr(
            self.session,
            "stealth_config",
            {}) if self.session else {}
        self._infra_rules = self._get_infra_rules()

        self._ip_rotator: IpRotator | None = None
        if self._stealth.get("rotate_ip"):
            if self.tools.ensure_installed("tor"):
                self._ip_rotator = IpRotator(
                    remote_executor=self._ssh, rules=self._infra_rules)
                self._ip_rotator.ensure_tor_ready()
            else:
                self.log.warning(
                    "IP rotation requested but 'tor' installation failed. Continuing without rotation.")

        self._waf_ghost: WafGhostEngine | None = None
        if self._stealth.get("ghost_mode"):
            self._waf_ghost = WafGhostEngine(
                remote_executor=self._ssh, rules=self._infra_rules)

        self._waf_evasion = WafEvasionEngine()
        self._waf_orchestrator = WafBypassOrchestrator(
            state_store=self.store
        )
        self._waf_learner = WafLearner()

        # ── Unified Intelligence Layer ──
        self.analyzer = StructuredAnalyzer(ai_backend=self.ai)
        self.reasoning = ReasoningEngine(
            ai_backend=self.ai, state_store=self.store)
        self.awareness = SelfAwarenessModule(state_store=self.store)
        self.advisor = StrategicAdvisor(
            state_store=self.store, ai_backend=self.ai)
        self.syntax_learner = SyntaxLearner()
        self._syntax_ctx_cache = None
        # Researcher brain: proposes NOVEL, testable vuln hypotheses from observed
        # evidence and validates PoCs (see intelligence/hypothesis_engine.py).
        from intelligence.hypothesis_engine import HypothesisEngine
        self.hypothesis_engine = HypothesisEngine(
            ai_backend=self.ai, state_store=self.store, logger=self.log)

        # Seed advisor with current engagement context
        if self.session and hasattr(self.session, "engagement_id"):
            try:
                self.advisor.set_engagement_context(
                    self.session.engagement_id,
                    getattr(self.session, "target", ""),
                    getattr(self.session, "tech_stack", None) or [],
                )
            except Exception as _ctx_err:
                self.log.debug(f"Failed to seed advisor context: {_ctx_err}")

        self._target_mutation_levels = {}
        if self.bus:
            self.bus.subscribe(self.name, self._on_message)

    def set_phase_deadline(self, deadline: float):
        """Set the absolute deadline timestamp for the current phase execution."""
        import time as _t
        self._phase_deadline = deadline
        # Remember the TOTAL phase budget so a single command's repair/evasion
        # loop can be capped to a FRACTION of it — no one stuck command may
        # consume the whole phase (the 67-min gobuster-eats-recon cascade).
        self._phase_budget_total = max(1.0, deadline - _t.monotonic())

    def _phase_token_budget(self) -> int:
        """Resolve the token budget for this agent's phase (0 = unlimited)."""
        try:
            from config_thresholds import (
                PHASE_TOKEN_BUDGET_RECON,
                PHASE_TOKEN_BUDGET_EXPLOITATION,
                PHASE_TOKEN_BUDGET_DEFAULT,
            )
        except Exception:
            return 0
        name = (getattr(self, "name", "") or "").lower()
        if name == "recon":
            return PHASE_TOKEN_BUDGET_RECON
        if name == "exploitation":
            return PHASE_TOKEN_BUDGET_EXPLOITATION
        return PHASE_TOKEN_BUDGET_DEFAULT

    def is_phase_budget_exhausted(self) -> bool:
        """W1.2 circuit breaker — True when this phase has burned its token budget.

        Agent loops call this to stop issuing new AI calls before a repair/retry
        storm drains the whole Groq TPD. Returns False when budget is 0/unset or
        the backend doesn't expose usage tracking, so it can only ever help.
        """
        budget = self._phase_token_budget()
        if not budget or budget <= 0:
            return False
        try:
            if not hasattr(self.ai, "is_phase_budget_exceeded"):
                return False
            return self.ai.is_phase_budget_exceeded((getattr(self, "name", "") or ""), budget)
        except Exception as e:
            self.log.debug(f"Phase budget check failed (non-fatal): {e}")
            return False

    # ── WS3 / W3.3 / W3.5 — HITL-gated authorization (uniform ROE model) ──────
    def request_hitl_authorization(self, action_name: str, description: str,
                                   covering_roe_flags: list | None = None) -> bool:
        """Single authorization model for any action beyond passive recon.

        Within standing ROE → autonomous (return True). Beyond ROE → escalate to
        the operator and ask; in non-interactive batch mode the safe default is
        DENY (skip the action), exactly like the existing WAF-attack HITL gate.
        No new per-feature on/off flags — the operator's start-of-engagement ROE
        plus a real-time prompt are the whole policy.
        """
        roe = getattr(self.session, "rules_of_engagement", {}) or {}
        for flag in (covering_roe_flags or []):
            if roe.get(flag):
                self.log.info(
                    f"[ROE] '{action_name}' is covered by standing ROE ({flag}=true) — proceeding.")
                return True

        # Beyond standing ROE → escalate. Use an interactive approver if wired.
        self.log.warning(
            f"[HITL GATE] '{action_name}' exceeds standing ROE. {description}")
        approver = getattr(self.session, "hitl_approver", None)
        if callable(approver):
            try:
                decision = bool(approver(action_name, description))
                self.log.warning(
                    f"[HITL GATE] Operator {'APPROVED' if decision else 'DENIED'} '{action_name}'.")
                return decision
            except Exception as _ae:
                self.log.debug(f"HITL approver error (treated as deny): {_ae}")
                return False
        self.log.error(
            f"[HITL GATE] '{action_name}' requires operator approval but no interactive "
            "approver is available (batch mode). Skipping this action (safe default).")
        return False

    def acquire_auth_session(self, base_url: str, login_url: str = "",
                             credentials: dict | None = None,
                             mode: str = "form",
                             success_markers: list | None = None):
        """W3.3 — acquire an authenticated AppSession, HITL-gated.

        Logging in / registering on the target exceeds passive recon, so it is
        gated through `request_hitl_authorization` (covered by `allow_exploitation`
        or `allow_brute_force`, else the operator is asked). Returns an
        authenticated `AppSession` on success, else None. Mechanism is AI-driven:
        the caller supplies the discovered login endpoint + credential map.
        """
        from core.app_session import AppSession

        if not self.request_hitl_authorization(
                action_name="authenticate to target",
                description=(f"The engine wants to log in at {login_url or base_url} to reach the "
                             "authenticated attack surface (API/IDOR/BOLA)."),
                covering_roe_flags=["allow_exploitation", "allow_brute_force"]):
            return None

        proxies = None
        try:
            sess = AppSession(base_url=base_url, proxies=proxies)
            creds = credentials or {}
            ok = False
            if mode == "json":
                ok = sess.login_json(login_url or base_url, creds)
            else:
                ok = sess.login_form(login_url or base_url, creds,
                                     success_markers=success_markers)
            if ok and sess.authenticated:
                self.log.info(
                    f"[AUTH] Acquired authenticated session ({sess.identity_label}) "
                    f"on {base_url}: {sess.snapshot()}")
                return sess
            self.log.warning(f"[AUTH] Login attempt did not establish a session on {base_url}.")
            return None
        except Exception as _le:
            self.log.warning(f"[AUTH] acquire_auth_session failed (non-fatal): {_le}")
            return None

    def request_phase_revisit(self, phase: str, reason: str) -> None:
        """W5.2 — ask the orchestrator to loop back to an earlier phase because a
        new attack surface was discovered (e.g. new in-scope subdomains/hosts the
        Target Model didn't cover). The orchestrator consumes this once and is
        hard-capped, so it cannot loop. Safe no-op if state store is unavailable.
        """
        try:
            import json as _json
            self.store.set(
                f"{self.session.engagement_id}:revisit_request",
                _json.dumps({"phase": phase, "reason": reason[:300],
                             "by": getattr(self, "name", "")}))
            self.log.info(f"[REVISIT REQUEST] → '{phase}': {reason[:120]}")
        except Exception as _rr_err:
            self.log.debug(f"request_phase_revisit failed (non-fatal): {_rr_err}")

    def should_abort(self) -> bool:
        """
        Check if the engagement should be aborted due to critical VPS health issues.
        Consults the global state updated by the HealthMonitor.
        """
        try:
            engagement_id = self.session.engagement_id if hasattr(
                self, "session") and self.session else "global"
            health = self.store.get_global_data("vps_health", engagement_id)
            if health and not health.get("healthy", True):
                self.log.error(
                    f"ABORT SIGNAL: {
                        self.node_label} health critical. Issues: {
                        ', '.join(
                            health.get(
                                'issues',
                                []))}")
                return True
        except Exception as e:
            self.log.debug(f"Failed to check health abort status: {e}")
        return False

    def validate_phase_prerequisites(self) -> tuple[bool, str]:
        """
        FIX #7: Enhanced Phase Validation Gates
        Verify that current phase has necessary prerequisites from previous phases.
        Checks not just existence but also DATA VALIDITY.

        Returns: (can_proceed: bool, reason: str)
        """
        if not self.store or not self.session or not hasattr(
                self.session, "engagement_id"):
            return True, ""  # Can't validate without store, assume okay

        phase = self.name.lower()

        # ── EXPLOITATION requires: Open ports, subdomains, or directories from Recon ──
        if phase == "exploitation":
            recon_data = self.store.get_phase_data(
                self.session.engagement_id, "recon")

            # If recon_data is missing (due to a crash), reconstruct it from
            # findings table
            if recon_data is None or not isinstance(recon_data, dict):
                findings = self.store.get_all_findings(
                    self.session.engagement_id)
                if not findings:
                    return False, "Recon phase data missing or corrupted and no findings exist"
                recon_data = {}
                open_ports, subdomains, dirs, endpoints = [], [], [], []
                for f in findings:
                    t = f.get("type", "")
                    tgt = f.get("target")
                    if not tgt:
                        continue
                    if "port" in t:
                        open_ports.append(tgt)
                    elif "subdomain" in t:
                        subdomains.append(tgt)
                    elif "directory" in t:
                        dirs.append(tgt)
                    elif "endpoint" in t:
                        endpoints.append(tgt)
                recon_data["open_ports"] = open_ports
                recon_data["subdomains"] = subdomains
                recon_data["directories"] = dirs
                recon_data["endpoints"] = endpoints
                self.store.set_phase_data(
                    self.session.engagement_id, "recon", recon_data)

            open_ports = recon_data.get(
                "open_ports") or recon_data.get("ports_found")
            subdomains = recon_data.get("subdomains", [])
            dirs = recon_data.get("directories", [])
            endpoints = recon_data.get("endpoints", [])

            has_ports = isinstance(open_ports, list) and len(open_ports) > 0
            has_subs = isinstance(subdomains, list) and len(subdomains) > 0
            has_dirs = isinstance(dirs, list) and len(dirs) > 0
            has_endpoints = isinstance(endpoints, list) and len(endpoints) > 0

            has_db_findings = self.store.has_findings(
                self.session.engagement_id, "recon")

            if not any([has_ports, has_subs, has_dirs,
                       has_endpoints, has_db_findings]):
                return False, "No usable targets (ports, subdomains, directories) discovered in Recon"

            self.log.info(
                "[GATE] Exploitation prerequisites met. Usable data discovered.")
            return True, ""

        # ── PERSISTENCE requires: Exploitation completed ──
        if phase == "persistence":
            exploit_data = self.store.get_phase_data(
                self.session.engagement_id, "exploitation")

            # Check 1: Data exists
            if exploit_data is None:
                return False, "Exploitation phase not completed"

            # Check 2: Data is correct type
            if not isinstance(exploit_data, dict):
                return False, f"Exploitation data corrupted: {type(exploit_data).__name__}"

            # We no longer strictly require shell_access, as persistence can run against web vulnerabilities
            # and credentials discovered during exploitation.
            self.log.info(
                "[GATE] Persistence prerequisites met: Exploitation completed")
            return True, ""

        # ── REPORTING requires: Findings from prior phases ──
        if phase == "reporting":
            all_findings = self.store.get_all_findings(
                self.session.engagement_id) or []

            # Check 1: Findings is correct type
            if not isinstance(all_findings, list):
                return False, f"Findings corrupted: {type(all_findings).__name__}"

            # Check 2: Validate finding structure (first few)
            for finding in all_findings[:3]:
                if not isinstance(finding, dict):
                    return False, f"Finding entry corrupted: {type(finding).__name__}"
                if not finding.get("type") or not finding.get("detail"):
                    return False, f"Finding missing required fields: {finding}"

            if not all_findings or len(all_findings) == 0:
                return False, "No findings recorded (engagement may be complete but nothing to report)"

            self.log.info(
                f"[GATE] Reporting prerequisites met: {
                    len(all_findings)} finding(s) valid")
            return True, ""

        # Default: all other phases can proceed
        return True, ""

    def _on_message(self, from_agent: str, payload: dict):
        self.log.debug(f"Message from {from_agent}: {str(payload)[:200]}")
        self._handle_message(from_agent, payload)

    def _provision_target_wordlist(
            self, recon_data: dict = None, phase: str = "recon") -> str | None:
        """
        V6 Autonomous Wordlist Provisioning.
        Uses AI to prescribe a highly-targeted wordlist or generate a micro-wordlist
        based on the discovered technology stack, completely removing hardcoded fallback URLs.
        """
        tech_context = ""
        if recon_data:
            findings = self.store.get_all_findings(self.session.engagement_id)
            tech_stack = [f["detail"]
                          for f in findings if f["type"] == "tech_stack"]
            tech_context = f"Tech Stack: {', '.join(tech_stack)}"

        # Autonomous environment context
        env_snapshot = self._get_environment_snapshot()
        env_context = f"--- RUNTIME ENVIRONMENT ---\n{env_snapshot}\n\n" if env_snapshot else ""

        # Phase-aware instruction
        phase_instructions = ""
        if phase == "recon":
            phase_instructions = "PHASE: RECON. Goal is rapid, broad discovery without timing out. You MUST keep the wordlist extremely SMALL and high-signal (50-200 entries max). Save deep fuzzing for later."
        else:
            phase_instructions = "PHASE: EXPLOITATION. Goal is deep, targeted fuzzing. You may fetch larger, comprehensive wordlists specific to the discovered tech stack, APIs, or parameters to find hidden vulnerabilities."

        prompt = f"""{env_context}### CONTEXT
We need a wordlist for web directory/file brute-forcing (e.g., gobuster, ffuf).
{tech_context}
Target: {self.session.target}

### MISSION
You are an autonomous offensive AI. Determine the absolute BEST wordlist approach.
WAF PRESENCE: High probability. DO NOT USE massive generic lists (e.g. dirb_common with 60k words) as they will get blocked instantly.
{phase_instructions}

You MUST choose one of two options and return a STRICT JSON response. No markdown wrappers.

Option 1 (Generate - RECOMMENDED): Generate a highly-targeted micro-wordlist (50-500 entries max) specific to the tech stack (e.g., WordPress config files, specific API endpoints).
Option 2 (Fetch): Provide a one-liner bash command to download a highly-relevant, SMALL wordlist from a reliable source to '{config_paths.WSL_TEMP_DIR}/ai_wordlist.txt'.

### RESPONSE SCHEMA
{{
  "type": "fetch" | "generate",
  "bash_command": "curl -sL https://... -o {config_paths.WSL_TEMP_DIR}/ai_wordlist.txt" (if fetch),
  "wordlist": ["/admin", "/api/v1", ".env", "wp-config.php.bak"] (if generate)
}}
"""
        # BUG FIX: Never use pathlib.Path for WSL paths - Path() on Windows converts
        # forward slashes to backslashes, producing \\tmp\\antigravity\\ai_wordlist.txt
        # which is invalid on the Linux WSL. Always use posixpath for remote
        # paths.
        target_path = posixpath.join(
            config_paths.WSL_TEMP_DIR,
            "ai_wordlist.txt") if self.tools.remote else str(
            Path(
                self.session.results_dir) /
            "raw" /
            "ai_wordlist.txt")

        # Cache per phase: provisioning is an AI call + remote writes, but the
        # list is identical for every {WORDLIST} command in a phase. Re-running
        # it each time burned tokens (feeding backend exhaustion) for nothing.
        if not hasattr(self, "_provisioned_wordlist"):
            self._provisioned_wordlist = {}
        if self._provisioned_wordlist.get(phase):
            return self._provisioned_wordlist[phase]

        try:
            # nano: the prompt already carries its own env + tech context, so the
            # full-mode env/awareness/advisor injection is pure waste (and double-
            # injects the environment).
            ai_resp = self.think(prompt, mode="nano").strip()
            # Clean possible markdown JSON wrappers
            if ai_resp.startswith("```json"):
                ai_resp = ai_resp[7:]
            if ai_resp.startswith("```"):
                ai_resp = ai_resp[3:]
            if ai_resp.endswith("```"):
                ai_resp = ai_resp[:-3]
            ai_resp = ai_resp.strip()

            data = json.loads(ai_resp, strict=False)
            action_type = data.get("type")

            if action_type == "fetch" and data.get("bash_command"):
                cmd = data["bash_command"]
                self.log.info(f"[AI WORDLIST] Executing fetch command: {cmd}")
                if self.tools.remote:
                    # RC-7 FIX: Ensure parent directory exists before fetching
                    parent_dir = posixpath.dirname(target_path)
                    self.tools.remote.execute(f"mkdir -p {parent_dir}")
                    ec, out, err = self.tools.remote.execute(
                        cmd, timeout=TOOL_DEFAULT_TIMEOUT)
                    if ec != 0:
                        self.log.warning(f"Wordlist fetch failed: {err}")
                        return None
                else:
                    import subprocess
                    subprocess.run(
                        cmd,
                        shell=True,
                        timeout=TOOL_DEFAULT_TIMEOUT,
                        capture_output=True)

            elif action_type == "generate" and data.get("wordlist"):
                words = data["wordlist"]
                self.log.info(
                    f"[AI WORDLIST] Generating micro-wordlist with {len(words)} entries.")
                if self.tools.remote:
                    # RC-7 FIX: Create the parent directory before writing.
                    # Without mkdir -p, echo >> fails silently when
                    # /tmp/antigravity/ doesn't exist.
                    parent_dir = posixpath.dirname(target_path)
                    self.tools.remote.execute(f"mkdir -p {parent_dir}")
                    # Write in chunks to avoid command line length limits
                    chunk_size = 20
                    self.tools.remote.execute(
                        f"rm -f {target_path}")  # Ensure fresh file
                    for i in range(0, len(words), chunk_size):
                        chunk = "\n".join(words[i:i + chunk_size])
                        safe_chunk = shlex.quote(chunk + "\n")
                        self.tools.remote.execute(
                            f"echo -n {safe_chunk} >> {target_path}")
                else:
                    import os
                    os.makedirs(os.path.dirname(target_path), exist_ok=True)
                    with open(target_path, "w", encoding="utf-8") as f:
                        f.write("\n".join(words) + "\n")
            else:
                self.log.warning(
                    f"AI returned invalid wordlist schema: {data}")
                return None

            # Verification Step
            if self.tools.remote:
                ec, out, _ = self.tools.remote.execute(
                    f"[ -s {target_path} ] && wc -l < {target_path}")
                if ec == 0 and out.strip().isdigit() and int(out.strip()) >= 5:
                    self.log.info(
                        f"[AI WORDLIST] Provisioned successfully at {target_path}")
                    self._provisioned_wordlist[phase] = target_path
                    return target_path
            else:
                import os
                if os.path.exists(target_path) and os.path.getsize(
                        target_path) > 10:
                    self.log.info(
                        f"[AI WORDLIST] Provisioned successfully at {target_path}")
                    self._provisioned_wordlist[phase] = target_path
                    return target_path

        except Exception as e:
            self.log.error(f"AI Wordlist provisioning failed: {e}")

        return None

    def _provision_target_wordlist_async(
            self, recon_data: dict = None, max_retries: int = 3, phase: str = "recon") -> str | None:
        """
        Provision wordlist with retry logic and exponential backoff.
        Handles network timeouts and transient failures gracefully.
        """
        import time

        for attempt in range(max_retries):
            try:
                wordlist_path = self._provision_target_wordlist(
                    recon_data, phase=phase)

                if wordlist_path is None:
                    self.log.warning(
                        f"[ASYNC WORDLIST] Attempt {
                            attempt + 1}/{max_retries}: provisioning returned None")
                    if attempt < max_retries - 1:
                        wait_time = 2 ** attempt  # Exponential backoff: 1s, 2s, 4s
                        self.log.info(
                            f"[ASYNC WORDLIST] Waiting {wait_time}s before retry...")
                        time.sleep(wait_time)
                    continue

                # Verify file exists and has content
                if self.tools.remote and hasattr(self.tools.remote, 'execute'):
                    size_code, size_out, _ = self.tools.remote.execute(
                        f"wc -c < {wordlist_path}", timeout=TOOL_DEFAULT_TIMEOUT)
                    if size_code == 0 and size_out.strip().isdigit():
                        file_size = int(size_out.strip())
                        if file_size > 0:
                            self.log.info(
                                f"[ASYNC WORDLIST] Successfully provisioned wordlist: {wordlist_path} ({file_size} bytes)")
                            return wordlist_path
                else:
                    # Local verification
                    import os
                    if os.path.exists(wordlist_path) and os.path.getsize(
                            wordlist_path) > 0:
                        self.log.info(
                            f"[ASYNC WORDLIST] Successfully provisioned wordlist: {wordlist_path}")
                        return wordlist_path

                self.log.warning(
                    f"[ASYNC WORDLIST] Attempt {
                        attempt + 1}/{max_retries}: file verification failed")
                if attempt < max_retries - 1:
                    wait_time = 2 ** attempt
                    self.log.info(
                        f"[ASYNC WORDLIST] Waiting {wait_time}s before retry...")
                    time.sleep(wait_time)

            except Exception as e:
                self.log.warning(
                    f"[ASYNC WORDLIST] Attempt {
                        attempt + 1}/{max_retries} exception: {e}")
                if attempt < max_retries - 1:
                    wait_time = 2 ** attempt
                    self.log.info(
                        f"[ASYNC WORDLIST] Waiting {wait_time}s before retry...")
                    time.sleep(wait_time)

        # All retries exhausted, fall back to micro-wordlist
        self.log.warning(
            "[ASYNC WORDLIST] All provisioning attempts failed, generating micro-wordlist as fallback")
        return self._generate_micro_wordlist("generic")

    def _generate_micro_wordlist(self, tool: str = "generic") -> str | None:
        """Generate a minimal but useful wordlist for when provisioning fails."""
        import time

        common_words = [
            "admin", "root", "test", "api", "app", "config", "debug", "files",
            "upload", "download", "login", "user", "pass", "secret", "data",
            "backup", "sql", "wp-admin", "administrator", "index", "home",
            "about", "contact", "portfolio", "blog", "media", "static",
            ".env", ".git", ".gitignore", "package.json", "web.config",
            "config.php", "settings.py", "application.yml", "dockerfile"
        ]

        try:
            import posixpath
            target_path = posixpath.join(
                config_paths.VPS_TEMP_DIR, f"micro_wordlist_{int(time.time())}.txt")

            content = "\n".join(common_words)

            if self.tools.remote and hasattr(self.tools.remote, 'execute'):
                # RC-7 FIX: Ensure parent directory exists before writing
                # micro-wordlist
                parent_dir = posixpath.dirname(target_path)
                self.tools.remote.execute(
                    f"mkdir -p {parent_dir}",
                    timeout=TOOL_DEFAULT_TIMEOUT)
                cmd = f"cat > {target_path} << 'EOF'\n{content}\nEOF"
                returncode, _, stderr = self.tools.remote.execute(
                    cmd, timeout=TOOL_DEFAULT_TIMEOUT)

                if returncode == 0:
                    self.log.info(
                        f"[MICRO WORDLIST] Generated at {target_path} ({
                            len(common_words)} entries)")
                    return target_path
                else:
                    self.log.error(
                        f"[MICRO WORDLIST] Failed to write: {stderr}")
                    return None
            else:
                # Local fallback
                import os
                os.makedirs(os.path.dirname(target_path), exist_ok=True)
                with open(target_path, "w", encoding="utf-8") as f:
                    f.write("\n".join(common_words) + "\n")
                self.log.info(
                    f"[MICRO WORDLIST] Generated locally at {target_path} ({
                        len(common_words)} entries)")
                return target_path

        except Exception as e:
            self.log.error(f"[MICRO WORDLIST] Failed to generate: {e}")
            return None

    def _handle_message(self, from_agent: str, payload: dict):
        pass

    @abstractmethod
    async def run(self) -> dict:
        """Execute the agent phase (to be implemented by subclass)."""

    def _load_rules(self, rule_name: str) -> dict:
        rule_path = config_paths.RULES_DIR / f"{rule_name}.json"
        if rule_path.exists():
            try:
                return json.loads(rule_path.read_text(encoding="utf-8"))
            except Exception as e:
                self.log.error(f"Failed to load rules {rule_name}: {e}")
        return {}

    def _get_infra_rules(self) -> dict:
        return self._load_rules("infrastructure")

    def rotate_tor_ip(self) -> bool:
        """
        Trigger a Tor identity rotation if the rotator is initialized.
        Used to evade WAF/IDS after heavy scanning or blocks.
        """
        if self._ip_rotator:
            success = self._ip_rotator.rotate()
            if success:
                self.log.info("[STEALTH] IP rotated successfully.")
            return success
        self.log.debug("IP rotation requested but rotator is not initialized.")
        return False

    def _apply_stealth_routing(self, tool: str, command: str) -> str:
        """UNIVERSAL stealth: route a tool's traffic through Tor (proxychains4)
        when Tor is verified active, so the engine never connects to the target
        from the real IP. Previously the engine only ROTATED the Tor circuit but
        never actually sent tool traffic through it (build_proxychains_cmd was
        unused) — the rotation was cosmetic and every tool leaked the real IP.

        Raw-socket tools (nmap/masscan/dig/naabu) are left DIRECT: SOCKS can't
        carry raw packets, and a TCP-connect scan through Tor reports every port
        'open' (a known artifact — see the recon unreliable-scan guard). For true
        stealth those should be minimized; HTTP/TCP tools are fully proxied.
        """
        try:
            rot = getattr(self, "_ip_rotator", None)
            if not rot or not getattr(rot, "_tor_verified", False):
                return command
            if "proxychains" in command:
                return command
            _RAW_SOCKET = {"nmap", "masscan", "dig", "naabu",
                           "fping", "ping", "traceroute", "hping3"}
            if (tool or "").lower() in _RAW_SOCKET:
                self.log.debug(
                    f"[STEALTH] {tool} is a raw-socket tool — cannot route through Tor SOCKS; "
                    "running direct.")
                return command
            wrapped = rot.build_proxychains_cmd(command)
            if wrapped != command:
                self.log.info(f"[STEALTH] Routing {tool} traffic through Tor (proxychains4).")
            return wrapped
        except Exception as _se:
            self.log.debug(f"stealth routing skipped (non-fatal): {_se}")
            return command

    # Local/util tools that make NO network connection — never a leak risk.
    _STEALTH_LOCAL_TOOLS = {
        "grep", "awk", "cut", "tee", "jq", "cat", "echo", "printf", "sed",
        "sort", "uniq", "tr", "wc", "xargs", "head", "tail", "ls", "find",
        "test", "id", "whoami", "pwd", "cd", "uname"}

    def _stealth_leak_guard(self, tool: str, command: str):
        """Fail-CLOSED opsec gate (GAP-2 fix). If anonymity was REQUESTED
        (stealth rotate_ip) but Tor is NOT verified working, a network tool would
        otherwise run DIRECT and leak the operator's REAL IP to the target —
        `_apply_stealth_routing` silently returns the command unwrapped in that
        case. Block it LOUDLY instead of de-anonymizing the operator behind their
        back. Returns a BLOCKED ToolResult to abort the run, or None to allow.
        Opt out with stealth_config['allow_direct_on_tor_fail'] = True.
        """
        try:
            if not (self._stealth or {}).get("rotate_ip"):
                return None  # anonymity not requested — nothing to protect
            rot = getattr(self, "_ip_rotator", None)
            if rot and getattr(rot, "_tor_verified", False):
                return None  # Tor verified — routing will happen, no leak
            # `_tor_verified` flips to False transiently — a rotation forces a
            # re-verify, a circuit hiccups. Don't permanently brick the whole
            # phase (block EVERY command) on a recoverable state: try ONCE to
            # bring Tor back. ensure_tor_ready short-circuits instantly if Tor is
            # genuinely disabled, so this doesn't add latency on real failure.
            if rot is not None:
                try:
                    if rot.ensure_tor_ready():
                        return None  # recovered — routing will happen, no leak
                except Exception:
                    pass
            if (self._stealth or {}).get("allow_direct_on_tor_fail"):
                return None  # operator explicitly accepts running direct
            _t = (tool or "").lower()
            _c = (command or "").lower()
            # Local commands and --help/--version probes make no network request.
            if (_t in self._STEALTH_LOCAL_TOOLS
                    or "--help" in _c or "--version" in _c or " -version" in _c):
                return None
            reason = (
                "OPSEC FAIL-CLOSED: anonymity (Tor) was requested (rotate_ip) but "
                f"Tor is not verified working — running '{tool}' would leak your "
                "REAL IP to the target. Blocked. Restart/fix Tor, or set stealth "
                "allow_direct_on_tor_fail=true to knowingly run direct.")
            self.log.error(f"[STEALTH FAIL-CLOSED] {reason}")
            return ToolResult(tool=tool, command=command, stdout="", stderr=reason,
                              exit_code=-1, duration_seconds=0,
                              status=ResultStatus.BLOCKED)
        except Exception as _sg:
            # A guard failure must not crash the run; default to the existing
            # (pre-fix) behaviour rather than blocking everything on a bug.
            self.log.debug(f"stealth leak guard error (allowing): {_sg}")
            return None

    def _track_and_return(self, result: ToolResult):
        self._track_failure(result)
        return result

    def _metric_target_type(self) -> str:
        """Coarse target classification used to bucket effectiveness metrics."""
        try:
            if self.session and hasattr(self.session, "target"):
                t = str(self.session.target).lower()
                if "wordpress" in t or "wp-" in t:
                    return "wordpress"
                if "apache" in t:
                    return "apache"
                if "nginx" in t:
                    return "nginx"
                if "cloudflare" in t or "cdn" in t:
                    return "cdn"
                return "generic"
        except Exception as _e:
            self.log.debug(f"metric target-type classify failed: {_e}")
        return "unknown"

    def _record_tool_metric(self, result: ToolResult, success: bool = None):
        """Feed one tool run into the effectiveness tracker.

        Previously the tracker was only ever called from the failure path with a
        hardcoded success=False and no duration, so EVERY tool showed a 0%
        success rate and total_time 0.0 — both inflating the perceived failure
        rate and poisoning the 'TOOL EFFECTIVENESS (this session)' data fed back
        into the prompt. This records true successes, durations, partial
        successes (a tool that produced useful output despite a WAF counts as a
        success), and WAF blocks as their own bucket."""
        try:
            tracker = getattr(self, "tool_tracker", None)
            if not tracker:
                return
            tool_name = getattr(result, "tool", None) or "unknown"
            status_val = (
                result.status.value if hasattr(result.status, "value")
                else str(result.status)).lower()
            waf_blocked = status_val in ("blocked", "waf_blocked")
            if success is None:
                success = bool(getattr(result, "success", False)) or status_val in (
                    "success", "partial_success", "partial")
            duration = float(getattr(result, "duration_seconds", 0.0) or 0.0)
            tracker.log_tool_result(
                tool=tool_name,
                success=success,
                duration=duration,
                waf_blocked=waf_blocked,
                target_type=self._metric_target_type(),
            )
        except Exception as _e:
            self.log.debug(f"tool metric record failed: {_e}")

    def _track_failure(self, result: ToolResult):
        if not result or result.status == ResultStatus.SUCCESS:
            return
        err_snippet = str(result.stderr or result.stdout)[:150].strip()
        tool_name = result.tool or "unknown"
        # V6: Consistent snippet format so safe_run_tool can detect it
        ctx = f"[SESSION] tool={tool_name} status={
            result.status} | err={err_snippet}"

        if not self._recent_failures or self._recent_failures[-1] != ctx:
            self._recent_failures.append(ctx)
            if len(self._recent_failures) > 20:  # Increased history
                self._recent_failures.pop(0)

            # Increment failure counts for proactive learning
            host = self._extract_host(result.command) or "unknown"
            fail_key = f"{tool_name}@{host}"
            self._tool_failure_counts[fail_key] = self._tool_failure_counts.get(
                fail_key, 0) + 1

            # When a tool gets STUCK (repeated failures on the same host), have
            # the reasoning engine analyze WHY — once, at the threshold — and
            # upgrade the failure memory from a raw error string to a reasoned
            # verdict. _recent_failures is already injected into the AI's next
            # decision prompt, so this gives it the human "flag changes won't
            # help here — pivot" signal instead of letting it retry forever.
            if (self._tool_failure_counts[fail_key] == 3
                    and getattr(self, "reasoning", None)):
                try:
                    verdict = self.reasoning.analyze_tool_failure(
                        tool_name, result.command or "",
                        result.stderr or "", result.stdout or "") or {}
                    rc = verdict.get("root_cause")
                    if rc and rc != "Unknown":
                        if verdict.get("is_approach_wrong"):
                            piv = verdict.get("suggested_pivot") \
                                or "abandon this approach and pivot"
                            self._recent_failures.append(
                                f"[ANALYSIS] {tool_name} stuck on {host}: {rc}. "
                                f"Flag changes will NOT help — PIVOT: {piv}")
                        else:
                            act = verdict.get("suggested_action") or "adjust parameters"
                            self._recent_failures.append(
                                f"[ANALYSIS] {tool_name} on {host}: {rc}. Try: {act}")
                except Exception as _e:
                    self.log.debug(f"failure-analysis wiring failed: {_e}")

            try:
                self.store.record_failure_pattern(
                    engagement_id=self.session.engagement_id,
                    agent_id=self.name,
                    tool=result.tool or "unknown",
                    error_type=result.status.value if hasattr(
                        result.status, "value") else str(result.status),
                    command=result.command,
                    stderr=result.stderr,
                    root_cause=ctx,
                    severity="warning" if result.status in (
                        ResultStatus.TIMEOUT, ResultStatus.BLOCKED) else "error",
                    avoid_next=f"Avoid {
                        result.tool or 'unknown'} if it consistently fails",
                )

                # Persist to local failure history file as backup for
                # cross-session learning
                history_file = config_paths.FAILURE_HISTORY_FILE
                local_data = {
                    "recent_failures": [],
                    "tool_failure_counts": {},
                    "timeout_escalation": {}}
                if history_file.exists():
                    try:
                        local_data = json.loads(history_file.read_text())
                        if isinstance(local_data, list):  # Migrate old format
                            local_data = {
                                "recent_failures": [
                                    f"tool={
                                        r.get('tool')} status={
                                        r.get('status')}" for r in local_data],
                                "tool_failure_counts": {},
                                "timeout_escalation": {}}
                    except Exception as e:
                        # Self-heal: a corrupt history file must NOT keep raising
                        # (it was caught one level up and the file was never
                        # rewritten, so it stayed corrupt and re-logged CRITICAL
                        # on every failure for the rest of the run). Reset to
                        # defaults so the next write below overwrites the bad file.
                        self.log.warning(
                            f"Failure-history JSON unreadable ({e}); resetting to "
                            f"defaults (self-heal).")
                        local_data = {
                            "recent_failures": [],
                            "tool_failure_counts": {},
                            "timeout_escalation": {}}

                # Update recent failures
                recent = local_data.get("recent_failures", [])
                recent.append(ctx)
                local_data["recent_failures"] = recent[-50:]

                # Update counts
                local_data["tool_failure_counts"] = self._tool_failure_counts
                local_data["timeout_escalation"] = self._timeout_escalation
                local_data["nuclei_timeout_count"] = self._nuclei_timeout_count

                history_file.write_text(json.dumps(local_data, indent=2))

                # Also persist nuclei count to StateStore for cross-phase
                # persistence
                if self.store and self.session and hasattr(
                        self.session, "engagement_id"):
                    self.store.set(f"{self.session.engagement_id}:nuclei_timeout_count", str(
                        self._nuclei_timeout_count))

            except Exception as e:
                self.log.debug(f"Failed to persist failure pattern: {e}")

        # Log to tool tracker. success=None lets the recorder classify from the
        # result status, so a partial_success that lands here is still counted
        # as a success (it produced useful output) rather than a flat failure.
        try:
            self._record_tool_metric(result, success=None)
        except Exception as e2:
            self.log.debug(f"Failed to log tool failure: {e2}")

    def _validate_severity(self, finding_type: str,
                           detail: str, proposed_severity: str) -> str:
        # Standardize inputs
        finding_type = str(finding_type).strip().lower()
        detail_lower = str(detail).lower()
        severity = str(proposed_severity).strip().lower()

        # Valid severity values whitelist
        if severity not in {"info", "low", "medium", "high", "critical"}:
            severity = "info"

        # Subdomains carry asset severity rankings directly from semantic
        # scoring, bypass verification checks
        if finding_type == "subdomain":
            return severity

        # Define max severities
        # missing_header, ssl_observation, tech_stack -> max severity: info
        if any(k in finding_type for k in {
               "missing_header", "ssl_observation", "tech_stack"}):
            return "info"

        # directory_listing, backup_file -> max severity: medium
        if any(k in finding_type for k in {
               "directory_listing", "backup_file"}):
            if severity in {"high", "critical"}:
                return "medium"
            return severity

        # Check verification evidence
        has_evidence = (
            "vuln_proven:" in detail_lower) or (
            "confirmed" in detail_lower)

        # A finding WITHOUT VULN_PROVEN: or confirmed in detail -> cap at
        # medium
        if not has_evidence:
            if severity in {"high", "critical"}:
                return "medium"
            return severity

        # If it has evidence but is sql_injection, rce, lfi, xxe -> allow
        # critical/high
        if any(k in finding_type for k in {
               "sql_injection", "rce", "lfi", "xxe", "remote_code_execution", "sqli", "vulnerability"}):
            return severity

        if severity == "critical":
            return "high"

        return severity

    def _has_target_foothold_generic(self) -> bool:
        """Best-effort: does any finding indicate a real foothold ON the target?

        Generalizes the persistence agent's foothold gate to every agent so the
        W8.2 ops-sanity backstop can tell a real host-level claim from one that
        only describes our own scanner box.
        """
        FOOTHOLD_TYPES = {
            "valid_credential", "shell_access", "rce_confirmed",
            "initial_access", "confirmed_vulnerability"}
        RCE_MARKERS = ("rce", "remote code execution", "reverse shell",
                       "command execution", "shell obtained", "session opened")
        try:
            for f in self._findings:
                ft = (f.get("type", "") or "").lower()
                if ft in FOOTHOLD_TYPES and ft != "confirmed_vulnerability":
                    return True
                if ft == "confirmed_vulnerability":
                    det = (f.get("detail", "") or "").lower()
                    if any(m in det for m in RCE_MARKERS):
                        return True
        except Exception:
            pass
        return False

    def _ops_sanity_backstop(self, finding_type: str, detail: str,
                             severity: str) -> tuple[str, str]:
        """W8.2 — run the centralized ops-sanity check on exotic (high/critical)
        findings and downgrade self-fooling artifacts to a lead. Returns the
        (possibly adjusted) (severity, detail). Defensive: never raises."""
        if severity not in ("high", "critical"):
            return severity, detail
        # Never downgrade an EVIDENCE-BACKED finding. A confirmed_vulnerability has
        # already passed the hypothesis engine's rigorous differential validation
        # and carries an explicit Proof[...]; the ops-sanity heuristic is a backstop
        # for the AI's UNVALIDATED self-reported claims and must NOT override a
        # proven PoC (same rule as the false-positive guard — a hardcoded signature
        # never overrides real evidence). Without this, a proven LFI/RCE whose proof
        # mentions host terms (/etc/, root, shell) — and which IS the first foothold,
        # so has_target_foothold is still False — was silently demoted to a lead.
        _d = detail or ""
        if (finding_type == "confirmed_vulnerability"
                or "VULN_PROVEN" in _d or "Proof[" in _d):
            return severity, detail
        if not hasattr(self, "awareness") or not self.awareness:
            return severity, detail
        try:
            proxy_active = bool(
                getattr(self, "_ip_rotator", None) is not None
                and getattr(self._ip_rotator, "_tor_verified", False))
            ops_context = {
                "proxy_active": proxy_active,
                "has_target_foothold": self._has_target_foothold_generic(),
                # ran_on_target is unknown generically; leave unset so the
                # host-claim branch keys off foothold only.
            }
            verdict = self.awareness.ops_sanity_check(detail, ops_context)
            if not verdict.get("plausible", True):
                reasons = "; ".join(verdict.get("reasons", []))
                self.log.warning(
                    f"[OPS SANITY] Downgrading {finding_type} '{detail[:60]}' "
                    f"to lead — {reasons}")
                return "info", f"[UNVERIFIED LEAD — ops-sanity: {reasons}] {detail}"
        except Exception as _os_err:
            self.log.debug(f"ops-sanity backstop failed (non-fatal): {_os_err}")
        return severity, detail

    def add_finding(self, finding_type: str, target: str, detail: str,
                    severity: str = "info", source_tool: str = None, command: str = None):
        with self._findings_lock:
            # Enforce severity validation rules
            severity = self._validate_severity(finding_type, detail, severity)
            # W8.2 — ops-sanity backstop: catch self-fooling exotic conclusions
            # (host-level claims with no foothold, etc.) and demote to a lead.
            severity, detail = self._ops_sanity_backstop(
                finding_type, detail, severity)

            detail_prefix = detail[:200]
            # Normalise URLs by dropping only the QUERY/FRAGMENT (cache-bust
            # tokens, session ids, ?id=1 vs ?id=2 test values) — NOT the whole
            # URL. The old `re.sub(r'https?://\S+','')` stripped the ENTIRE URL,
            # so every crawler endpoint (katana/gau/hakrawler — the highest-value
            # attack-surface findings, emitted as a bare URL) collapsed to the
            # SAME empty dedup key and all but the first of ~60 URLs were silently
            # dropped. Keeping scheme+host+PATH preserves each endpoint's identity
            # while still merging pure cache-bust variants.
            dedup_detail = re.sub(
                r'(https?://[^\s?#]+)[?#]\S*', r'\1', detail_prefix).strip().lower()
            dedup_key = f"{finding_type}::{target}::{dedup_detail[:160]}"
            if dedup_key in self._findings_seen:
                self._finding_dedup_counts[dedup_key] = self._finding_dedup_counts.get(
                    dedup_key, 0) + 1
                return
            self._findings_seen.add(dedup_key)
            # Feed the self-awareness lobe in EVERY phase. register_finding was
            # recon-only and each agent owns its own awareness instance, so
            # exploitation's knowledge_state was always empty. Findings carry a
            # SEVERITY (not a 0-1 confidence), so map it; deduped above, so each
            # unique finding registers exactly once.
            try:
                if getattr(self, "awareness", None):
                    _sev2conf = {"critical": 0.9, "high": 0.85, "medium": 0.6,
                                 "low": 0.4, "info": 0.35}
                    self.awareness.register_finding({
                        "type": finding_type, "target": target, "detail": detail,
                        "confidence": _sev2conf.get(str(severity).lower(), 0.5)})
            except Exception as _aw_e:
                self.log.debug(f"awareness register_finding failed: {_aw_e}")
            self.store.add_finding(
                engagement_id=self.session.engagement_id,
                phase=self.name,
                finding_type=finding_type,
                target=target,
                detail=detail,
                severity=severity
            )

            # Populate AttackGraph
            target_node = f"target:{target}"
            finding_node = f"finding:{finding_type}:{
                hashlib.md5(
                    detail.encode()).hexdigest()[
                    :8]}"

            self.attack_graph.add_node(
                self.session.engagement_id,
                target_node,
                "TARGET",
                {"url": target}
            )

            self.attack_graph.add_node(
                self.session.engagement_id,
                finding_node,
                "FINDING",
                {
                    "type": finding_type,
                    "detail": detail,
                    "severity": severity,
                    "source": source_tool or self.name
                }
            )

            # Link target to finding
            self.attack_graph.add_edge(
                self.session.engagement_id,
                target_node,
                finding_node,
                "CONTAINS"
            )

            self._findings.append({
                "type": finding_type,
                "target": target,
                "detail": detail,
                "severity": severity,
                "source_tool": source_tool or self.name,
                "command": command or ""
            })
            # Record in strategic advisor for cross-engagement learning
            if hasattr(self, "advisor") and self.advisor:
                try:
                    confidence = 0.9 if severity in {
                        "high", "critical"} else 0.6 if severity == "medium" else 0.4
                    self.advisor.record_finding(
                        finding_type=finding_type,
                        target=target,
                        detail=detail,
                        severity=severity,
                        confidence=confidence,
                    )
                except Exception as _advisor_err:
                    self.log.debug(
                        f"Advisor finding record failed: {_advisor_err}")
        agent_msg(
            self.name, f"[{severity.upper()}] {finding_type} on {target}: {detail[:100]}")

    def check_liveness(self, urls: list[str]) -> dict[str, int]:
        """
        Check the HTTP liveness of a list of URLs/domains.
        Returns a dict mapping url/domain -> HTTP status code (or 0 if connection failed).
        """
        import concurrent.futures
        import socket
        import urllib.request
        import ssl

        def probe_one(domain: str) -> tuple[str, int]:
            domain = domain.strip().lower()
            if not domain:
                return domain, 0

            schemes = ["https://", "http://"] if "://" not in domain else [""]

            for scheme in schemes:
                url = f"{scheme}{domain}" if scheme else domain
                parsed_host = url.replace(
                    "https://",
                    "").replace(
                    "http://",
                    "").split("/")[0].split(":")[0]
                try:
                    socket.gethostbyname(parsed_host)
                except socket.gaierror:
                    continue

                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE

                try:
                    req = urllib.request.Request(
                        url,
                        headers={
                            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}
                    )
                    with urllib.request.urlopen(req, timeout=4, context=ctx) as response:
                        return domain, response.status
                except urllib.error.HTTPError as e:
                    return domain, e.code
                except Exception:
                    # Do not log the full stack trace for expected network
                    # errors (timeouts, refused connections)
                    continue

            return domain, 0

        results = {}
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            future_to_url = {
                executor.submit(
                    probe_one,
                    url): url for url in urls}
            for future in concurrent.futures.as_completed(future_to_url):
                url = future_to_url[future]
                try:
                    domain, code = future.result()
                    if domain:
                        results[domain] = code
                except Exception as e:
                    import logging as __logging_tmp
                    __logging_tmp.getLogger(__name__).debug(
                        f"Silenced exception: {e}")
                    results[url] = 0
        return results

    def flush_dedup_stats(self) -> None:
        if self._finding_dedup_counts:
            total = sum(self._finding_dedup_counts.values())
            self.log.info(
                f"Dedup summary: {total} duplicates suppressed across {
                    len(
                        self._finding_dedup_counts)} categories.")
            self._finding_dedup_counts.clear()

    def finish_phase(self, results: dict, status: ResultStatus = ResultStatus.SUCCESS,
                     message: str = "") -> PhaseResult:
        """
        Unified method to finalize a phase, set status, and return a validated PhaseResult.
        Ensures all agents comply with the strict PhaseResult data contract.
        FIX #3.6: Never return invalid PhaseResult - return error status instead.
        """
        # Ensure findings are attached to the data if not already there
        if "findings" not in results:
            with self._findings_lock:
                results["findings"] = list(self._findings)

        # Set status in state store (V5/V6 dual-mode)
        if self.store and self.session and hasattr(
                self.session, "engagement_id"):
            status_val = status.value if hasattr(
                status, "value") else str(status)
            self.store.set_phase_status(
                self.session.engagement_id, self.name, status_val, message)
            self.store.set_phase_data(
                self.session.engagement_id, self.name, results)

        # Build PhaseResult object
        phase_res = PhaseResult(
            phase=self.name,
            status=status,
            timestamp=_time_module.time(),
            data=results,
            error_message=message
        )

        # Validate strictly before returning
        is_valid, errors = phase_res.validate()
        if not is_valid:
            error_detail = '; '.join(errors)
            self.log.error(
                f"[FIX 3.6] PHASE CONTRACT VIOLATION ({
                    self.name}): {error_detail}")
            # FIX #3.6: Return error PhaseResult instead of invalid result
            return PhaseResult(
                phase=self.name,
                status=ResultStatus.VALIDATION_ERROR,
                timestamp=_time_module.time(),
                data={},  # Empty data - invalid data doesn't propagate
                error_message=f"Phase result validation failed: {error_detail}"
            )

        return phase_res

    # Words the AI (or the hypothesis-engine refinement field) sometimes prepends
    # to a command as prose — "rerun ffuf ...", "Use gobuster ...", "Try sqlmap
    # ...", "Run nikto ...". Left in, the first word is parsed as the tool name
    # ("rerun"/"use") and the COMMAND GUARDIAN blocks it. None of these are real
    # tools, so dropping leading ones is safe and universal.
    _COMMAND_PROSE_PREFIXES = {
        "run", "rerun", "re-run", "use", "using", "try", "trying", "execute",
        "exec", "please", "then", "next", "also", "now", "first", "finally",
        "lets", "let's", "command", "perform", "the", "a", "an"}

    @classmethod
    def _strip_command_prose(cls, command: str) -> str:
        """Drop leading prose/filler words so the first token is the real tool."""
        toks = (command or "").split()
        while len(toks) > 1 and toks[0].lower().strip(":,.") in cls._COMMAND_PROSE_PREFIXES:
            toks.pop(0)
        return " ".join(toks) if toks else (command or "")

    def _clean_command(self, command: str) -> str:
        if not command:
            return ""
        command = self._normalize_unicode_to_ascii(command.strip())
        command = self._strip_command_prose(command)
        if re.search(r'(?:rm\s+-rf|mkfs|dd)\s', command, re.IGNORECASE):
            raise ValueError("Dangerous command sequence detected")

        # Remove $(dig +short TARGET) wrapper since Python handles resolution
        # natively
        command = re.sub(r'\$\(\s*dig\s+\+short\s+([^\)]+)\)', r'\1', command)
        command = re.sub(r'`\s*dig\s+\+short\s+([^`]+)`', r'\1', command)

        return command

    @staticmethod
    def _normalize_unicode_to_ascii(text: str) -> str:
        """Normalize Unicode lookalikes to ASCII equivalents, then strip
        any remaining non-printable characters.

        LLMs frequently emit Unicode hyphens (\u2013, \u2014), smart quotes
        (\u201c, \u201d, \u2018, \u2019), and other lookalikes. Stripping them
        turns `--batch` into `batch` (a bare positional argument). Normalizing
        them preserves the flag intent.
        """
        import unicodedata
        # Step 1: Map common problematic codepoints to ASCII equivalents
        UNICODE_TO_ASCII = {
            '\u2013': '-',   # en-dash
            '\u2014': '-',   # em-dash
            '\u2015': '-',   # horizontal bar
            '\u2212': '-',   # minus sign
            '\uFE63': '-',   # small hyphen-minus
            '\uFF0D': '-',   # fullwidth hyphen-minus
            '\u201C': '"',   # left double quotation mark
            '\u201D': '"',   # right double quotation mark
            '\u201E': '"',   # double low-9 quotation mark
            '\u2018': "'",   # left single quotation mark
            '\u2019': "'",   # right single quotation mark
            '\u201A': "'",   # single low-9 quotation mark
            '\u2032': "'",   # prime
            '\u2033': '"',   # double prime
            '\u00AB': '"',   # left-pointing double angle quotation
            '\u00BB': '"',   # right-pointing double angle quotation
            '\u2026': '...', # horizontal ellipsis
            '\u00A0': ' ',   # non-breaking space
            '\u2003': ' ',   # em space
            '\u2002': ' ',   # en space
            '\u2009': ' ',   # thin space
            '\u200B': '',    # zero-width space
            '\uFEFF': '',    # byte order mark
        }
        for uchar, ascii_char in UNICODE_TO_ASCII.items():
            if uchar in text:
                text = text.replace(uchar, ascii_char)

        # Step 2: NFKD decomposition to catch remaining lookalikes
        text = unicodedata.normalize('NFKD', text)

        # Step 3: Strip any remaining non-printable-ASCII
        text = re.sub(r'[^\x20-\x7E\n\t]', '', text)

        return text

    def _resolve_wordlist_path(self, tool: str, requested_path: str) -> str:
        """Dynamically resolve wordlist path from config, download if needed."""
        from config_paths import get_vps_wordlist, VPS_TEMP_DIR

        # Check if path exists on VPS
        if self.tools and self.tools.remote:
            try:
                ec, _, _ = self.tools.remote.execute(
                    f"[ -f {requested_path} ] && echo YES", timeout=5)
                if ec == 0:
                    return requested_path
            except Exception as _vps_check_err:
                self.log.debug(
                    f"VPS file existence check failed for '{requested_path}': {_vps_check_err}")

        # Try to resolve from configured wordlist paths
        wordlist_type = "common" if "common" in requested_path.lower() else "directory"
        vps_wordlist = get_vps_wordlist(
            wordlist_type, self.tools.remote if self.tools else None)
        if vps_wordlist:
            return vps_wordlist

        # Fallback: return AI wordlist path (should be auto-downloaded by recon
        # phase)
        return f"{VPS_TEMP_DIR}/ai_wordlist.txt"

    def _sanitize_output_path(self, tool: str, requested_path: str) -> str:
        """Sanitize output path to always reside dynamically under WSL_RESULTS_DIR or WSL_TEMP_DIR.

        Extracts the basename from the requested path. If the requested path is a bare directory
        (e.g., /root, /tmp, /root/results, /tmp/antigravity), generates a default filename based on the tool name.

        RC-5 FIX: Any path under /root/ is rejected regardless of basename — the WSL user
        runs as non-root and will get EACCES when writing to /root/*.
        """
        import posixpath

        # Clean requested path of whitespace and quotes
        requested_path = (requested_path or "").strip().strip("'\"")
        if not requested_path:
            return posixpath.join(
                config_paths.WSL_RESULTS_DIR, f"{tool.lower()}_results.txt")

        # RC-5: Always redirect /root/* regardless of basename — non-root WSL
        # user gets EACCES.
        if requested_path.startswith("/root"):
            _basename = posixpath.basename(requested_path)
            _filename = _basename if _basename and _basename not in (
                ".", "..", "root") else f"{tool.lower()}_results.txt"
            _safe = posixpath.join(config_paths.WSL_RESULTS_DIR, _filename)
            self.log.debug(f"[RC-5] /root/ path redirected → {_safe}")
            self._ensure_wsl_dir(posixpath.dirname(_safe))
            return _safe

        # Check if requested path is a directory (ends with slash or has known directory names)
        # Or if it has no extension and is a directory path like /root or /tmp
        basename = posixpath.basename(requested_path)

        # Determine if basename is empty (e.g. /root/results/) or is a known
        # directory name
        is_dir = False
        if not basename or basename in (
                ".", "..", "results", "antigravity", "tmp", "root"):
            is_dir = True

        if is_dir:
            # Generate default file name under RESULTS_DIR
            filename = f"{tool.lower()}_results.txt"
        else:
            filename = basename

        # Place it under config_paths.WSL_RESULTS_DIR and ensure the dir exists
        safe_path = posixpath.join(config_paths.WSL_RESULTS_DIR, filename)
        self._ensure_wsl_dir(posixpath.dirname(safe_path))
        return safe_path

    def _ensure_wsl_dir(self, wsl_path: str) -> None:
        """Create the target directory in WSL if it doesn't exist, using self.tools.remote if available."""
        if not wsl_path:
            return
        if self.tools and self.tools.remote:
            try:
                self.tools.remote.execute(f"mkdir -p {wsl_path}", timeout=5)
            except Exception as e:
                self.log.warning(
                    f"Failed to create WSL directory '{wsl_path}': {e}")

    def _normalize_command_targets(self, command: str) -> str:
        if not command:
            return command

        normalized = command

        # Collapse repeated or nested schemes inside commands.
        while True:
            updated = re.sub(
                r"(?i)(https?://)(?:https?://)+",
                r"\1",
                normalized)
            if updated == normalized:
                break
            normalized = updated

        # Strip any subdomain prefix from a trailing IP address (e.g. sg5.216.198.79.1 -> 216.198.79.1)
        # BUG-10 Fix: Removing this greedy regex because it destroys legitimate hostnames like mysql.10.0.0.5
        # normalized = re.sub(r'\b[a-zA-Z0-9.-]+\.(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b', r'\1', normalized)

        return normalized

    def _is_remote_path_valid(self, path: str) -> bool:
        if not path:
            return False
        if self.tools and self.tools.remote:
            try:
                # Resolve ~ manually if needed
                test_path = path
                if path.startswith("~"):
                    if not hasattr(self, "_remote_home_dir"):
                        ec, out, _ = self.tools.remote.execute("echo $HOME", timeout=3)
                        if ec == 0:
                            self._remote_home_dir = out.strip()
                        else:
                            self._remote_home_dir = "/root"
                    test_path = path.replace("~", self._remote_home_dir, 1)
                
                # Check using remote SSH command test -e
                ec, _, _ = self.tools.remote.execute(f"test -e '{test_path}'", timeout=3)
                return ec == 0
            except Exception:
                return False
        return os.path.exists(path)

    def _canonicalize_tool_command(
            self, tool: str, command: str, target: str = None) -> str:
        """Normalize tool-specific targets and remove retry-accumulated flags."""
        if not command:
            return command

        tool_name = (tool or "").lower()
        canonical = self._normalize_command_targets(command)

        if target:
            try:
                ctx = TargetContext.from_input(target)
                url_target = ctx.base_url
                host_target = ctx.host
            except Exception as e:
                import logging as __logging_tmp
                __logging_tmp.getLogger(__name__).debug(
                    f"Silenced exception: {e}")
                url_target = target
                host_target = target

            if tool_name in {"curl", "nikto", "gobuster", "ffuf",
                             "nuclei", "whatweb", "wafw00f", "dirsearch", "dirb"}:
                preferred_target = url_target
            elif tool_name in {"nmap", "masscan", "subfinder", "theharvester", "assetfinder", "dnsenum", "whois", "ping", "traceroute", "mtr", "host", "netstat", "sslscan"}:
                preferred_target = host_target
            else:
                preferred_target = url_target if "://" in canonical else host_target

            for variant in {target, url_target, host_target}:
                if not variant or variant == preferred_target:
                    continue
                if variant not in canonical:
                    continue
                # URL-boundary-safe replacement: NEVER replace a bare hostname (e.g.
                # "novalink.lk") when it already appears as part of a full URL in the
                # command (e.g. "https://novalink.lk"). Doing a naive str.replace()
                # turns "https://novalink.lk" into "https://https://novalink.lk".
                # Instead, only replace the variant when it is NOT immediately preceded
                # by "://" (i.e. it is a standalone bare-host token, not inside
                # a URL).
                escaped = re.escape(variant)
                canonical = re.sub(
                    r"(?<!://)(?<![a-zA-Z0-9._-])" +
                    escaped + r"(?![a-zA-Z0-9._/-])",
                    preferred_target,
                    canonical,
                )

        # Strip http:// or https:// from targets inside the command for
        # bare-host tools
        BARE_HOST_TOOLS = {
            "nmap", "masscan", "sslscan", "ping", "traceroute",
            "dnsenum", "whois", "dig", "host", "nslookup"
        }
        if tool_name in BARE_HOST_TOOLS:
            # BUG-9 Fix: Only strip scheme if it precedes the intended target host
            if target and 'host_target' in locals():
                canonical = re.sub(
                    r'https?://(' + re.escape(host_target) + r')\b', r'\1', canonical)
            else:
                # If target unknown, we must guess, but be careful not to strip proxy URLs
                canonical = re.sub(
                    r'(?<!proxy )https?://([a-zA-Z0-9.-]+)', r'\1', canonical)
            
            # Strip path suffix (e.g. novalink.lk/tiki/ -> novalink.lk) but preserve CIDR ranges (e.g. 192.168.1.1/24)
            canonical = re.sub(r'\b([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/([a-zA-Z_]\S*)', r'\1', canonical)
            canonical = re.sub(r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/([a-zA-Z_]\S*)', r'\1', canonical)
            canonical = re.sub(r'\b([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/+$', r'\1', canonical)

        # Note: Tool flag construction and syntax adjustments are delegated to AI reasoning and SyntaxLearner.
        canonical = re.sub(r'\s{2,}', ' ', canonical).strip()

        # Hydra target URL formatting
        if tool_name == "hydra":
            if "http://" in canonical or "https://" in canonical:
                urls = re.findall(r'https?://[^\s\'"]+', canonical)
                for url in urls:
                    has_post_format = (
                        "post" in canonical.lower() or
                        "form" in canonical.lower() or
                        url.count(":") >= 2 or
                        "^user^" in canonical.lower()
                    )
                    if has_post_format:
                        new_url = url.replace("https://", "https-post-form://").replace("http://", "http-post-form://")
                    else:
                        new_url = url.replace("https://", "https-get://").replace("http://", "http-get://")
                    canonical = canonical.replace(url, new_url)

        # Nuclei templates path resolution
        if tool_name == "nuclei":
            # Correct hallucinated wordlist/txt file in -t flag
            canonical = re.sub(r'(?i)(?:-t|-templates)\s+["\']?[^"\']+\.txt["\']?', '', canonical)
            t_matches = re.findall(
                r'(?<!\S)(?:-t|-templates)\s+("[^"]*"|\'[^\']*\'|\S+)', canonical)
            if t_matches:
                for match in t_matches:
                    raw_path = match.strip('"\'')
                    paths = raw_path.split(",")
                    new_paths = []
                    for p in paths:
                        p_stripped = p.strip()
                        if not self._is_remote_path_valid(p_stripped) and "nuclei-templates" in p_stripped:
                            valid_base = self._nuclei_templates_path().rstrip("/")
                            parts = p_stripped.split("nuclei-templates", 1)
                            suffix = parts[1].lstrip("/")
                            new_p = f"{valid_base}/{suffix}" if suffix else valid_base
                            new_paths.append(new_p)
                        else:
                            new_paths.append(p_stripped)
                    new_path = ",".join(new_paths)
                    
                    if match.startswith('"') or match.startswith("'"):
                        quote_char = match[0]
                        replacement = f"{quote_char}{new_path}{quote_char}"
                    else:
                        replacement = new_path
                    canonical = canonical.replace(match, replacement)

        # Thread flag deduplication + BARE/INVALID `-t` repair.
        # A `-t` with no numeric value — e.g. the AI or a WAF "reduce threads"
        # transform emitting `-t` immediately followed by another flag — makes the
        # fuzzer parse the NEXT flag as -t's value ("invalid value '-ac' for flag
        # -t: parse error"), which then fails identically on every retry (and was
        # even mis-escalated as a WAF block). The old dedup only handled
        # `-t <N>`, so a bare `-t` passed straight through. Now: strip EVERY
        # thread flag (valid `-t N`, bare `-t`, or `-t <non-numeric>`) and re-add
        # exactly one valid count (last numeric seen, else a safe default).
        if re.search(r'(?<!\S)(?:-t|--threads)\b', canonical):
            threads_matches = re.findall(
                r'(?<!\S)(?:-t|--threads)\s+(\d+)\b', canonical)
            canonical = re.sub(
                r'(?<!\S)(?:-t|--threads)(?:\s+\d+)?(?=\s|$)', '', canonical)
            canonical = re.sub(r'\s{2,}', ' ', canonical).strip()
            val = threads_matches[-1] if threads_matches else "10"
            canonical = f"{canonical} -t {val}".strip()

        # User-agent flag deduplication and subcommand/wordlist checking for Gobuster
        if tool_name == "gobuster":
            # Ensure subcommand is present
            subcommands = {"dir", "dns", "s3", "gcs", "vhost", "tftp", "fuzz"}
            words = canonical.split()
            try:
                gobuster_idx = -1
                for idx, w in enumerate(words):
                    if w.lower() == "gobuster" or w.lower().endswith("/gobuster"):
                        gobuster_idx = idx
                        break
                if gobuster_idx != -1:
                    has_sub = False
                    for w in words[gobuster_idx + 1:]:
                        if w.lower() in subcommands:
                            has_sub = True
                            break
                    if not has_sub:
                        words.insert(gobuster_idx + 1, "dir")
                        canonical = " ".join(words)
            except Exception:
                pass

            # Ensure wordlist is present
            if " -w" not in canonical and " --wordlist" not in canonical:
                canonical = f"{canonical} -w {{WORDLIST}}"

            ua_matches = re.findall(
                r'(?<!\S)(?:-a|--useragent)\s+("[^"]*"|\'[^\']*\'|\S+)', canonical)
            if ua_matches:
                val = ua_matches[-1]
                canonical = re.sub(
                    r'(?<!\S)(?:-a|--useragent)\s+(?:"[^"]*"|\'[^\']*\'|\S+)', '', canonical)
                canonical = f"{canonical.strip()} -a {val}".strip()

        canonical = re.sub(r'(?<!\S)--p(?!\S)', '-p', canonical)
        canonical = re.sub(r'(?<!\S)-T(\d)(?!\S)', r'-T\1', canonical)

        if tool_name == "nmap":
            ports = re.findall(r'(?<!\S)-p\s+([^\s]+)', canonical)
            if ports:
                canonical = re.sub(r'(?<!\S)-p\s+[^\s]+', '', canonical)
                canonical = f"{canonical.strip()} -p {ports[-1]}".strip()

            timing_flags = re.findall(r'(?<!\S)-T\d(?!\S)', canonical)
            if timing_flags:
                canonical = re.sub(r'(?<!\S)-T\d(?!\S)', '', canonical)
                prefix = " ".join(timing_flags[-1:])
                remainder = canonical.split(
                    "nmap ", 1)[-1] if "nmap " in canonical else canonical
                canonical = f"nmap {prefix} {remainder}".strip()

        canonical = re.sub(r'\s{2,}', ' ', canonical).strip()
        return canonical

    def _nuclei_templates_path(self) -> str:
        # Check if the configured template path exists in the WSL remote
        # context
        configured = os.getenv("NUCLEI_TEMPLATES", "~/nuclei-templates/")
        if self.tools and self.tools.remote:
            try:
                ec, _, _ = self.tools.remote.execute(
                    f"find {configured} -maxdepth 2 -name '*.yaml' | head -n 1 | grep -q .", timeout=5)
                if ec != 0:
                    # Fallback to the standard default location if the provided
                    # path is invalid or empty
                    return "~/nuclei-templates/"
            except Exception as _e:
                import logging
                logging.getLogger(__name__).debug(
                    f'Swallowed exception in base_agent.py: {_e}')
        return configured

    def _extract_host(self, command: str) -> str | None:
        """Extract the target URL or host from a CLI command string.

        Searches for URL patterns (https://host, http://host) or bare IPs/domains
        within the command - never feeds the entire command to a host:port parser.
        """
        if not command:
            return None

        import re
        # Priority 1: Find full URLs (http://... or https://...)
        # We handle stacked schemes explicitly here since standard regex stops
        # short
        url_matches = re.findall(
            r'(?:https?://)+[a-zA-Z0-9._-]+(?::[0-9]+)?',
            command,
            flags=re.IGNORECASE)
        if url_matches:
            # Fix stacked schemes (e.g. https://https://novalink.lk)
            match = url_matches[0]
            match = re.sub(r'(?i)^(https?://)+', '', match)
            return match

        # Priority 2: Find bare IPs
        ips = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?\b', command)
        if ips:
            return ips[0]

        # Priority 3: Find domain-like strings (not tool names or flags)
        domains = re.findall(
            r'\b([a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?\.(?:[a-zA-Z]{2,}))(?::\d+)?\b',
            command)
        if domains:
            return domains[0]

        return None

    def _translate_command_for_fallback(
            self, original_tool: str, fallback_tool: str, command: str) -> str:
        """Proxy to ToolManager's translation function."""
        if hasattr(self.tools, "_translate_command_for_fallback"):
            return self.tools._translate_command_for_fallback(
                original_tool, fallback_tool, command)
        return ""

    def _is_syntax_rejection(self, tool: str, command: str, result) -> bool:
        """UNIVERSAL, no-hardcoded-vocabulary detector: did the TOOL ITSELF reject
        the command's syntax (print its own usage/help and refuse to run)?

        The only 100%-accurate authority on a tool's syntax is the tool. When a
        CLI rejects its arguments it prints its OWN usage/option list. So we use
        the tool's REAL `--help` as ground truth: if the failed output is
        substantially that help text, the tool bounced our command → it's a
        SYNTAX error to be REPAIRED (re-grounded against the help), NOT a WAF
        block, network failure, or dead end. This generalises to ANY tool the AI
        decides to use — no per-tool flag lists, no error-vocabulary list (which
        is always incomplete; e.g. ffuf's "parse error" was missing). A real WAF
        block returns an HTML/403 page that shares ~none of the tool's option
        lines, so it scores ~0 and is left alone.
        """
        try:
            out = ((getattr(result, "stdout", "") or "") + "\n" +
                   (getattr(result, "stderr", "") or "")).strip()
            if not out or len(out) > 20000:
                return False
            help_text = ""
            if hasattr(self, "tools") and hasattr(
                    self.tools, "get_tool_help_brief"):
                # Cached; returns "" for not-installed/no-help tools so we no-op.
                help_text = self.tools.get_tool_help_brief(tool, command) or ""
            if not help_text or len(help_text) < 40:
                return False

            def _opt_lines(text: str) -> set:
                # Distinctive lines a CLI prints in its usage: option lines
                # (start with '-') or a 'usage' header. Generic CLI shape, not
                # tied to any specific tool.
                lines = set()
                for ln in text.splitlines():
                    s = ln.strip().lower()
                    if len(s) >= 6 and (
                            s[0] == "-" or s.startswith("usage")):
                        lines.add(s[:80])
                return lines

            help_opts = _opt_lines(help_text)
            if len(help_opts) < 3:
                return False
            out_low = out.lower()
            hits = sum(1 for o in help_opts if o in out_low)
            # The failed output echoed back a big chunk of the tool's own option
            # list → the tool printed its usage → syntax rejection.
            return hits >= max(3, int(len(help_opts) * 0.3))
        except Exception as _e:
            self.log.debug(
                f"syntax-rejection check failed (non-fatal): {_e}")
            return False

    def _is_transport_error(self, result) -> bool:
        """UNIVERSAL detection of a TRANSPORT / CONNECTION-layer failure — a TLS
        certificate mismatch/expiry, a DNS resolution failure, or a refused/
        reset/timed-out connection — as opposed to an HTTP-layer WAF block.

        These failures happen BELOW HTTP: no response was ever served, so WAF
        evasion (rotating headers / IPs) can NEVER fix them — looping evasion on
        them is the 'stuck' symptom. They must instead go to the AI triage +
        --help-grounded repair (e.g. the AI adds `-k`/`--no-tls-validation` for a
        cert mismatch, or abandons an unresolvable host). The strings matched here
        are STANDARD language/library networking-error text (Go, curl, OpenSSL,
        getaddrinfo) emitted IDENTICALLY by any tool — not per-tool or per-target
        logic; and they only ROUTE the result to the AI, which makes the call.
        """
        try:
            txt = ((getattr(result, "stdout", "") or "") + " " +
                   (getattr(result, "stderr", "") or "")).lower()
            if not txt.strip():
                return False
            transport_sigs = (
                # TLS / certificate
                "tls: failed to verify", "x509:", "certificate is valid for",
                "certificate has expired", "ssl certificate problem",
                "self-signed certificate", "self signed certificate",
                "unable to get local issuer", "handshake failure",
                "tls handshake", "wrong version number",
                # DNS
                "could not resolve host", "name or service not known",
                "no such host", "temporary failure in name resolution",
                "could not resolve",
                # TCP / connection
                "connection refused", "connection reset", "connection timed out",
                "no route to host", "network is unreachable", "dial tcp",
                "i/o timeout", "failed to connect", "couldn't connect",
            )
            return any(s in txt for s in transport_sigs)
        except Exception:
            return False

    def _interpret_outcome(self, tool: str, command: str, result) -> dict:
        """Universal AI outcome triage — the system's GENERAL way to handle a
        result it may never have seen before, instead of pattern-matching it
        against hardcoded signature lists (which can't generalize to a new tool,
        error format, or defense).

        Given any NON-success result, the AI reasons from first principles and
        returns one action:
          • "accept"  — the output ALREADY holds useful results (the tool merely
            exits non-zero by convention, or partially succeeded) → keep it, for
            ANY tool, with no hardcoded tool whitelist.
          • "abandon" — a genuinely non-recoverable failure for THIS target → stop
            burning the repair budget, with no hardcoded "deterministic error"
            string list.
          • "repair"  — a malformed/too-heavy command a corrected retry may fix
            (falls through to the existing AI repair/--help flow).

        Bounded + fail-safe: cached per (tool, error-signature) so each novel
        error is reasoned about ONCE per engagement (repeats reuse the verdict —
        no AI call); any error or missing AI backend → {"action":"repair"} (the
        current default). No per-tool or per-error logic anywhere."""
        default = {"action": "repair", "reason": ""}
        try:
            out = ((result.stdout or "") + "\n" + (result.stderr or "")).strip()
            # Clean raw output from ANSI codes, VT100 escapes, and excessive noise before prompting
            out = clean_text(out)
            sig = tool + "|" + " ".join(out.lower().split())[:160]
            cache = getattr(self, "_outcome_interp_cache", None)
            if cache is None:
                cache = self._outcome_interp_cache = {}
            if sig in cache:
                return cache[sig]
            if not getattr(self, "ai", None):
                return default
            # Limit error snippet to high-signal 800 chars to avoid window saturation
            error_snippet = out[:800] if len(out) > 800 else (out or "(no output)")
            prompt = (
                "A security tool returned a NON-success result. Decide what to do. "
                "This may be a tool, error, or defense you have never seen — reason "
                "from first principles; do NOT rely on a fixed list of known "
                "errors.\n\n"
                f"Tool: {tool}\nCommand: {command}\n"
                f"Exit code / status: {getattr(result, 'exit_code', '?')} / "
                f"{getattr(result, 'status', '?')}\n"
                f"Output (stdout+stderr, cleaned):\n{error_snippet}\n\n"
                "Pick ONE action:\n"
                "- accept: the output ALREADY contains useful results worth keeping "
                "(many tools exit non-zero by convention, or partially succeed).\n"
                "- abandon: a real, NON-recoverable failure for THIS target "
                "(wrong/closed/unsupported — no flag change or retry can fix it).\n"
                "- repair: the command itself is malformed or too heavy; a corrected "
                "or lighter retry could work.\n"
                'Output STRICT JSON only: {"action":"accept|abandon|repair","reason":"short"}'
            )
            resp = self.ai.query(
                "You triage security-tool outcomes for an autonomous operator. Be "
                "decisive and general — handle unfamiliar tools and errors too.",
                prompt)
            verdict = default
            m = re.search(r'\{[\s\S]*\}', resp or "")
            if m:
                data = json.loads(m.group(0))
                act = str(data.get("action", "repair")).lower().strip()
                if act in ("accept", "abandon", "repair"):
                    verdict = {"action": act,
                               "reason": str(data.get("reason", ""))[:160]}
            cache[sig] = verdict
            return verdict
        except Exception as e:
            self.log.debug(f"outcome interpret failed (default=repair): {e}")
            return default

    def safe_run_tool(self, tool: str, command: str, target: str = None,
                      output_path: str | Path = None, silent: bool = False,
                      timeout: int = 120, is_repair: bool = False):
        # Nikto and Nmap require longer base timeouts
        if tool in ["nikto", "nmap", "sqlmap"]:
            from tools.tool_registry import TOOL_TIMEOUTS
            if timeout < 300 or timeout == TOOL_TIMEOUTS.get(tool, 120):
                timeout = 900

        from core.scope_enforcer import ScopeViolation

        # ── Proactive Kill-Switch Check ──────────────────────────────────────
        if self.should_abort():
            return ToolResult(tool=tool, command=command, stdout="",
                              stderr=f"Engagement aborted: {
                                  self.node_label} resource critical.",
                              exit_code=-1, duration_seconds=0, status=ResultStatus.BLOCKED)

        # ── V6 CRITICAL: Check ban list BEFORE anything else ─────────────────
        # The ban list is populated when a tool times out 3+ times. We must gate
        # here - after cross-phase load in __init__ - so bans from a prior phase
        # (e.g., nuclei banned during Recon) prevent execution in Exploitation too.
        _run_host = self._extract_host(command) or target or "unknown"
        _ban_key_specific = f"{tool}@{_run_host}"
        _ban_key_global = f"{tool}@GLOBAL"
        if _ban_key_specific in self._tool_ban_list or _ban_key_global in self._tool_ban_list:
            matched_key = _ban_key_specific if _ban_key_specific in self._tool_ban_list else _ban_key_global
            self.log.warning(
                f"[TOOL BAN GATE] '{tool}' is banned (key={matched_key}). Skipping execution.")
            return ToolResult(tool=tool, command=command, stdout="",
                              stderr=f"Tool '{tool}' is permanently banned for this engagement (3+ timeouts).",
                              exit_code=-1, duration_seconds=0, status=ResultStatus.BLOCKED)
        # ─────────────────────────────────────────────────────────────────────

        # Scope is a strict allowlist and check_target's contract is "called
        # before EVERY tool execution". The declared `target` is the SEMANTIC
        # target — correct to check, and it avoids over-blocking resolver/infra
        # hosts a command may also contact (e.g. dig @1.1.1.1). But when no
        # target is passed we must NOT silently skip the check: fall back to the
        # host the command actually hits so an out-of-scope command can't slip
        # through with target=None. (Local `--help` fetches have no host, so
        # _run_host is "unknown" and are correctly left alone.) Fail CLOSED.
        _scope_host = target or (
            _run_host if _run_host and _run_host != "unknown" else None)
        if _scope_host and hasattr(self.scope, "check_target"):
            try:
                self.scope.check_target(_scope_host)
            except ScopeViolation as e:
                self.log.warning(f"SCOPE BLOCK: {e}")
                return ToolResult(tool=tool, command=command, stdout="", stderr=str(e),
                                  exit_code=-1, duration_seconds=0, status=ResultStatus.BLOCKED)

        # ── OPSEC fail-closed: never leak the real IP when stealth was asked for
        # but Tor isn't verified working (GAP-2). Blocks leak-prone network tools
        # unless the operator opted into allow_direct_on_tor_fail.
        _leak = self._stealth_leak_guard(tool, command)
        if _leak is not None:
            self._track_failure(_leak)
            return _leak

        # ── V6 HARDENED URL normalization (no naive str.replace on bare hosts) ──
        if target and isinstance(target, str):
            ctx = TargetContext.from_input(target)

            if tool.lower() in HTTP_TOOLS:
                target = ctx.base_url   # e.g. "https://novalink.lk"
            else:
                # bare hostname/IP for nmap, masscan, etc.
                target = ctx.host

            # ── SAFE command sanitization: collapse any stacked schemes already
            # present in the command string without touching other text.
            # Example: "dirb https://http://novalink.lk/ ..." -> "dirb https://novalink.lk/ ..."
            # We do NOT use str.replace(old_bare_host, new_full_url) because that
            # turns "https://novalink.lk/" into "https://http://novalink.lk/".
            if command:
                # Pass 1: collapse stacked schemes (e.g. https://http://,
                # http://https://)
                _prev = None
                while _prev != command:
                    _prev = command
                    command = re.sub(
                        r"(?i)(https?://)(?:https?://)+",
                        r"\1",
                        command,
                    )

        if target:
            target = clean_text(target)
            # Validate using the bare host portion (never a full URL)
            from core.result_contracts import FragileParseFixer
            _host_for_validation, _ = FragileParseFixer.safe_port_extraction(
                target)

            if not _host_for_validation:
                self.log.warning(
                    f"VALIDATION BLOCK: Could not extract host from '{target}'")
                return ToolResult(tool=tool, command=command, stdout="",
                                  stderr=f"Invalid target format: {target}", exit_code=-1,
                                  duration_seconds=0, status=ResultStatus.FAILURE)

            if not is_valid_target(_host_for_validation):
                self.log.warning(
                    f"VALIDATION BLOCK: '{_host_for_validation}' is not a valid domain or IP.")
                return ToolResult(tool=tool, command=command, stdout="",
                                  stderr=f"Target '{_host_for_validation}' failed validation", exit_code=-1,
                                  duration_seconds=0, status=ResultStatus.FAILURE)

        cmd_host = self._extract_host(command)
        tls_blocked = (
            (tool == "curl" or tool in VIRTUAL_TOOLS)
            and cmd_host
            and cmd_host in self._tls_blocked_hosts
            and ("https://" in command or "http://" in command)
        )
        if tls_blocked:
            breaker_info = self._tls_blocked_hosts[cmd_host]
            elapsed = _time_module.time() - breaker_info["blocked_at"]
            if elapsed < TLS_BREAKER_BACKOFF_SECS:
                self.log.warning(
                    f"[TLS CIRCUIT BREAKER] Skipping curl -> {cmd_host} "
                    f"(TLS dead, retry in {
                        TLS_BREAKER_BACKOFF_SECS - elapsed:.0f}s)"
                )
                res = ToolResult(tool=tool, command=command, stdout="",
                                 stderr="TLS blocked by circuit breaker",
                                 exit_code=35, duration_seconds=0, status=ResultStatus.BLOCKED)
                self._track_failure(res)
                return res
            elif breaker_info["retries"] >= TLS_BREAKER_MAX_RETRIES:
                self.log.warning(
                    f"[TLS CIRCUIT BREAKER] Permanently blocked: {cmd_host} "
                    f"({breaker_info['retries']}/{TLS_BREAKER_MAX_RETRIES} retries exhausted)"
                )
                res = ToolResult(tool=tool, command=command, stdout="",
                                 stderr="TLS blocked permanently after max retries",
                                 exit_code=35, duration_seconds=0, status=ResultStatus.BLOCKED)
                self._track_failure(res)
                return res
            else:
                self.log.info(
                    f"[TLS CIRCUIT BREAKER] Backoff expired for {cmd_host}. "
                    f"Clearing block for clean retry (attempt {
                        breaker_info['retries'] + 1}/{TLS_BREAKER_MAX_RETRIES})..."
                )
                self._tls_blocked_hosts[cmd_host]["retries"] += 1
                self._tls_blocked_hosts[cmd_host]["blocked_at"] = 0

        # ── V6: COMMAND DEDUPLICATION & PROACTIVE LEARNING ──
        # We'll use the tool+target as a key for failure tracking
        clean_host = self._extract_host(command) or target or "unknown"
        fail_key = f"{tool}@{clean_host}"
        fail_count = self._tool_failure_counts.get(fail_key, 0)

        # ── Historical Memory: Check cross-engagement failures ──
        # FIX: Only match historical timeouts for the SAME host, not just
        # the same tool. One timeout on target A should not proactively
        # lighten commands for target B.
        historical_timeout = False
        # Honor the same-host rule STRICTLY. The old `or "unknown" in pattern`
        # matched ANY timeout record merely containing the substring "unknown" —
        # a host that couldn't be extracted, or error text like "unknown option"
        # / "unknown host". So a single stray timeout proactively lightened this
        # tool on EVERY host for the rest of the run, silently under-scoping
        # scans (smaller wordlist / fewer ports) and missing findings. Require a
        # real, specific same-host match; if the current host is itself unknown,
        # don't proactively lighten at all (the reactive timeout path still will).
        if clean_host and clean_host != "unknown":
            for pattern in self._recent_failures:
                if (f"tool={tool}" in pattern and "TIMEOUT" in pattern.upper()
                        and clean_host in pattern):
                    historical_timeout = True
                    break

        # FIX: Require 2+ failures (not >= 1) — a single failure could be
        # transient (network blip, one-off timeout). This prevents the
        # proactive lighter from firing an extra AI round-trip on every
        # command after a single fluke.
        effective_fail_count = fail_count
        if historical_timeout or effective_fail_count >= 2:
            reason = "historical memory" if historical_timeout else f"recent failures ({effective_fail_count})"
            self.log.info(
                f"[PROACTIVE LEARNING] Tool {tool} previously timed out on {clean_host} ({reason}). Lightening command.")
            command = self._make_command_lighter(
                tool, command, effective_fail_count + (1 if historical_timeout else 0))

        # ── V6: Automated WAF Evasion integration ──
        if self._waf_ghost and tool.lower() in HTTP_TOOLS:
            # Check if WAF is present in current context
            ctx_data = self.store.get_phase_data(
                self.session.engagement_id, "recon") or {}
            if ctx_data.get("waf_present"):
                self.log.info(
                    f"[WAF EVASION] WAF detected on target. Applying Ghost Engine mutations to {tool}.")
                command = self._waf_ghost.transform(command, tool, level=2)

        # ── V6: PRE-EMPTIVE RETARGETING (Mandatory Bypass Adoption) ──
        _authorized_retarget = None  # set to the origin URL when a WAF bypass is adopted (guardian authz)
        if tool.lower() in HTTP_TOOLS:
            try:
                recon_data = self.store.get_phase_data(
                    self.session.engagement_id, "recon") or {}
                bypass_url = recon_data.get("waf_bypass_url")
                if bypass_url:
                    bypass_url = bypass_url.strip()
                    if not re.match(
                            r'^https?://[a-zA-Z0-9.:\-\[\]/]+$', bypass_url):
                        self.log.warning(
                            f"[WAF SANITIZE] Rejected unsafe/malformed bypass URL: {bypass_url}")
                        bypass_url = None
                if bypass_url:
                    bypass_url = bypass_url.rstrip('/')
                    original_host = self._extract_host(command)
                    if original_host and original_host.rstrip(
                            '/') != bypass_url:
                        self.log.info(
                            f"[RETARGETING] Adopting discovered bypass for {tool}: {original_host} -> {bypass_url}")
                        # Use word boundaries so we don't accidentally replace substrings in random text.
                        # We use \b on both sides. If the host contains characters that break \b (like a trailing /),
                        # the previous regex lookarounds might have been brittle. Let's use robust string replacement
                        # instead of regex if it's a simple URL match, or just
                        # \b if we use regex.
                        escaped_host = re.escape(original_host)
                        command = re.sub(
                            r'\b' + escaped_host + r'\b',
                            bypass_url,
                            command,
                        )
                        # Authorize the origin target for the downstream guardian.
                        # Without this, the guardian's "replace a foreign public IP
                        # with the domain's resolved (CDN edge) IP" rule (utils/
                        # guardian.py) rewrites the origin IP back to the edge and
                        # SILENTLY UNDOES this WAF-origin bypass. The raw target arg
                        # is always in the guardian's check_targets, so passing the
                        # origin URL makes the retargeted command validate as in-scope.
                        _authorized_retarget = bypass_url

                        # ── V6: HOST HEADER INJECTION (Critical for Direct IP Access) ──
                        # If retargeting to an IP, ensure we have a Host header
                        # for HTTP compliance
                        is_ip = re.search(r'\d+\.\d+\.\d+\.\d+', bypass_url)
                        if is_ip and "Host:" not in command:
                            clean_domain = original_host.replace(
                                "http://", "").replace("https://", "").split('/')[0]
                            if tool.lower() in ("curl", "gobuster", "ffuf", "dirsearch"):
                                # Ensure we don't duplicate -H
                                if tool.lower() == "curl":
                                    command = command.replace(
                                        "curl ", f'curl -H "Host: {clean_domain}" ')
                                elif tool.lower() == "gobuster":
                                    if "gobuster dir " in command:
                                        command = command.replace(
                                            "gobuster dir ", f'gobuster dir -H "Host: {clean_domain}" ')
                                    elif "gobuster vhost " in command:
                                        command = command.replace(
                                            "gobuster vhost ", f'gobuster vhost -H "Host: {clean_domain}" ')
                                    elif "gobuster dns " in command:
                                        command = command.replace(
                                            "gobuster dns ", f'gobuster dns -H "Host: {clean_domain}" ')
                                    elif "gobuster fuzz " in command:
                                        command = command.replace(
                                            "gobuster fuzz ", f'gobuster fuzz -H "Host: {clean_domain}" ')
                                    else:
                                        command = command.replace(
                                            "gobuster ", f'gobuster dir -H "Host: {clean_domain}" ')
                                else:
                                    command += f' -H "Host: {clean_domain}"'
                                self.log.debug(
                                    f"[RETARGETING] Injected Host header: {clean_domain}")
            except Exception as _retarget_err:
                self.log.debug(
                    f"Pre-emptive retargeting error: {_retarget_err}")

        # ── V6: PREFLIGHT ADJUSTMENT ──
        # Detect wildcards or environmental issues before first run
        command_tool = (self._extract_primary_tool(
            command) or tool or "").lower()

        current_command = self._normalize_command_targets(
            self._clean_command(clean_text(command)))
        # Preflight adjust happens once
        current_command = self._preflight_adjust_for_wildcard(
            command_tool, current_command, target or cmd_host)

        validated_command, validation_reason = block_or_repair(
            current_command,
            _authorized_retarget or target or cmd_host or (
                self.session.target if self.session and hasattr(
                    self.session, "target") else ""),
            target_context=self.session.target_context if self.session and hasattr(
                self.session, "target_context") else None
        )
        if not validated_command:
            if validation_reason.startswith("REQUIRES_APPROVAL:"):
                # Human-in-the-loop Destructive Action Gateway
                self.log.warning(
                    f"\n[!!! DESTRUCTIVE ACTION DETECTED !!!]\n{validation_reason}\nCommand: {current_command}")
                print(
                    "\n\033[91m[WARNING] The AI wants to execute a potentially DESTRUCTIVE command:\033[0m")
                print(f"  Command: \033[93m{current_command}\033[0m")
                print(f"  Reason:  {validation_reason}")

                try:
                    # In some environments, input() might throw EOFError if not interactive.
                    # We default to rejecting if we can't prompt.
                    approval = input(
                        "Do you want to allow this command? (y/N): ").strip().lower()
                except Exception as e:
                    import logging as __logging_tmp
                    __logging_tmp.getLogger(__name__).debug(
                        f"Silenced exception: {e}")
                    approval = "n"

                if approval in ["y", "yes"]:
                    self.log.info(
                        "[HUMAN OVERRIDE] Destructive command approved by operator.")
                    # Force the command through by bypassing block_or_repair
                    validated_command = current_command
                else:
                    self.log.warning(
                        "[HUMAN OVERRIDE] Destructive command REJECTED by operator.")
                    res = ToolResult(
                        tool=tool,
                        command=current_command,
                        stdout="",
                        stderr="Human operator REJECTED the destructive command.",
                        exit_code=-1,
                        duration_seconds=0,
                        status=ResultStatus.BLOCKED,
                    )
                    self._track_failure(res)
                    return res
            else:
                self.log.warning(f"[COMMAND GUARDIAN] {validation_reason}")
                res = ToolResult(
                    tool=tool,
                    command=current_command,
                    stdout="",
                    stderr=validation_reason,
                    exit_code=-1,
                    duration_seconds=0,
                    status=ResultStatus.BLOCKED,
                )
                self._track_failure(res)
                return res

        current_command = validated_command
        # Harden the command using agent's shell hardening rules
        hardened = self._harden_shell_cmd(current_command)
        if not hardened:
            self.log.warning(
                f"[SHELL HARDEN] Command rejected by hardening rules: {current_command[:100]}")
            res = ToolResult(
                tool=tool,
                command=current_command,
                stdout="",
                stderr="Command rejected by base agent shell hardening rules.",
                exit_code=-1,
                duration_seconds=0,
                status=ResultStatus.BLOCKED,
            )
            self._track_failure(res)
            return res
        current_command = hardened

        cmd_hash = hashlib.sha256(current_command.encode()).hexdigest()[:16]
        now = _time_module.time()

        # ── V6: COMMAND DEDUPLICATION ──
        # We only care about tracking failures to prevent infinite loops.
        # If a command succeeds, we shouldn't block it from running again
        # (e.g. nuclei might run multiple times with different tags).
        # The AI is responsible for not suggesting the exact same thing twice.
        if cmd_hash in self._command_history:
            prior = self._command_history[cmd_hash]
            elapsed = now - prior["ts"]
            prior_status = prior.get("status", "unknown")

            # If the command failed recently (not a timeout which gets a retry,
            # and not success)
            if elapsed < 300 and prior_status not in (
                    ResultStatus.TIMEOUT.value, ResultStatus.SUCCESS.value, "running"):
                self.log.warning(
                    f"[COMMAND DEDUP] Exact command already failed {
                        elapsed:.0f}s ago. Rejecting.")
                res = ToolResult(tool=tool, command=current_command, stdout="",
                                 stderr="Command rejected: identical command already failed within 5 minutes",
                                 exit_code=-1, duration_seconds=0, status=ResultStatus.BLOCKED)
                self._track_failure(res)
                return res

        # ── FIX #8: CYCLE DETECTION ──────────────────────────────────────
        # Track attempts per tool+target. If 3+ attempts all failed with same error,
        # force a strategy change (different tool or technique).
        clean_host = self._extract_host(current_command) or target or "unknown"
        tool_target_key = f"{tool}@{clean_host}"

        # Get cycle count from repair history
        cycle_count = 0
        if cmd_hash in self._repair_attempts_history:
            cycle_count = len(self._repair_attempts_history[cmd_hash])

        if cycle_count >= 3:
            # We've tried this command+tool+target 3+ times. Force a different
            # approach.
            self.log.warning(
                f"[CYCLE DETECTION] Tool '{tool}' tried {cycle_count} times on {clean_host} with persistent errors. "
                f"Forcing strategy change..."
            )

            # Multi-level tool fallback chains for systematic recovery
            # FIX #3.2: Expanded tool fallback chains with missing tools
            TOOL_FALLBACK_CHAINS = {
                # Recon tools
                "nmap": ["masscan", "zmap", "shodan-cli"],
                "masscan": ["nmap", "zmap"],
                "zmap": ["nmap", "masscan"],
                "shodan-cli": ["nmap", "masscan"],

                # Vulnerability scanning
                "nuclei": ["nikto", "wapiti", "curl"],
                "nikto": ["nuclei", "wapiti", "w3af"],
                "wapiti": ["nuclei", "nikto", "w3af"],
                "w3af": ["nuclei", "nikto", "wapiti"],

                # Directory enumeration
                "gobuster": ["ffuf", "dirsearch", "dirb", "wfuzz"],
                "ffuf": ["gobuster", "dirsearch", "dirb", "wfuzz"],
                "dirsearch": ["gobuster", "ffuf", "dirb", "wfuzz"],
                "dirb": ["gobuster", "ffuf", "dirsearch", "wfuzz"],
                "wfuzz": ["gobuster", "ffuf", "dirsearch", "dirb"],

                # SQL injection
                "sqlmap": ["curl", "burp"],
                "burp": ["sqlmap", "curl"],

                # Subdomain enumeration
                "subfinder": ["assetfinder", "amass", "crtsh"],
                "assetfinder": ["subfinder", "amass", "crtsh"],
                "amass": ["subfinder", "assetfinder", "crtsh"],
                "crtsh": ["subfinder", "assetfinder", "amass"],

                # Web technology detection
                "whatweb": ["curl", "wget"],
                "curl": ["wget", "python"],
                "wget": ["curl", "python"],

                # SSL/TLS testing
                "sslyze": ["openssl", "testssl"],
                "openssl": ["sslyze", "testssl"],
                "testssl": ["sslyze", "openssl"],

                # DNS tools (FIX #3.2: Added missing DNS fallbacks)
                "dig": ["nslookup", "host"],
                "nslookup": ["dig", "host"],
                "host": ["dig", "nslookup"],

                # Python/scripting tools (FIX #3.2: Added missing script
                # execution fallbacks)
                "python3": ["python", "bash"],
                "python": ["python3", "bash"],
                "python_payload": ["python3", "python", "bash"],
                "bash": ["sh", "python3"],
                "sh": ["bash", "python3"],

                # Metasploit (FIX #3.2: Added missing Metasploit fallback)
                "metasploit": ["python_payload", "bash", "curl"],
                "msfconsole": ["python_payload", "bash", "curl"],

                # Web proxy tools (FIX #3.2: Added missing proxy tools)
                "zap": ["burp", "sqlmap", "curl"],
            }

            # Get the full fallback chain for this tool
            fallback_chain = TOOL_FALLBACK_CHAINS.get((tool or "").lower(), [])

            # Find which tools in chain are available
            available_fallbacks = []
            for candidate in fallback_chain:
                if candidate.lower() != tool.lower():  # Don't cycle back to same tool
                    available_fallbacks.append(candidate)

            if available_fallbacks:
                # Try each fallback in sequence
                # Start with first available
                next_tool = available_fallbacks[0]
                self.log.info(
                    f"[CYCLE RECOVERY] Tool chain for '{tool}': {fallback_chain}")
                self.log.info(
                    f"[CYCLE RECOVERY] Switching from '{tool}' to '{next_tool}' (attempt 1/{
                        len(available_fallbacks)})")

                # Ask AI to translate the command
                translated_cmd = self._translate_command_for_fallback(
                    tool, next_tool, current_command)
                if translated_cmd:
                    current_command = translated_cmd
                    cmd_hash = hashlib.sha256(
                        current_command.encode()).hexdigest()[:16]
                    self.log.info(
                        f"[CYCLE RECOVERY] Translated command: {current_command} (New hash: {cmd_hash})")

                tool = next_tool
            else:
                self.log.warning(
                    f"[CYCLE RECOVERY] No fallback defined for {tool}. Abandoning this approach.")
                return ToolResult(tool=tool, command=current_command, stdout="",
                                  stderr=f"Cycle detection: {tool} failed {cycle_count} times. Cannot recover.",
                                  exit_code=-1, duration_seconds=0, status=ResultStatus.BLOCKED)
        # ──────────────────────────────────────────────────────────────────

        # Record this command attempt (will be updated with final status after
        # run)
        self._command_history[cmd_hash] = {"ts": now, "status": "running"}

        repair_count = 0
        max_repairs = 3
        last_result = None
        # Enforce minimum timeout for heavy scanners to prevent premature AI
        # kill-switches
        heavy_tools = {
            "nmap",
            "gobuster",
            "ffuf",
            "nuclei",
            "sqlmap",
            "masscan",
            "feroxbuster",
            "wfuzz"}
        if tool.lower() in heavy_tools:
            from tools.tool_registry import TOOL_TIMEOUTS
            min_timeout = TOOL_TIMEOUTS.get(tool.lower(), 600)
            if timeout < min_timeout:
                self.log.info(
                    f"Escalating dangerously low AI timeout ({timeout}s) to {min_timeout}s for heavy tool: {tool}")
                timeout = min_timeout

        current_timeout = timeout
        # Tor/proxychains scales wall-clock HARD: every request hops ~3 relays
        # (commonly 3-5x slower) and the WAF-evasion throttle (--delay / fewer
        # threads) compounds it. All the timeout/budget math below is calibrated
        # for DIRECT speed, so under Tor a command is killed before it can finish
        # — the dominant cause of "everything timed out". Give Tor'd commands
        # proportionally more wall-clock: better to run FEWER commands that
        # actually COMPLETE than MANY that all time out and produce nothing.
        _tor_on = bool(getattr(getattr(self, "_ip_rotator", None), "_tor_verified", False))
        if _tor_on:
            current_timeout = int(current_timeout * 3)
        if hasattr(self, "_phase_deadline") and self._phase_deadline:
            time_left = self._phase_deadline - _time_module.monotonic() - 30
            # A phase is meant to run MANY tools, so no single command may consume
            # the whole remaining budget. Cap any one command to ~half of what's
            # left (with a sane floor so a real scan still fits). This is what
            # stops a single "full TCP port scan" from starving recon for an hour.
            if time_left > 0:
                # At most ~40% of the remaining budget for any single command
                # (floor 180s so a real scan still fits) — stops one heavy tool
                # (e.g. nuclei loading 6221 templates) from eating the whole
                # phase and starving every tool after it. Under Tor each command
                # legitimately needs longer, so allow a bigger single slice.
                per_cmd_ceiling = max(180, int(time_left * (0.6 if _tor_on else 0.4)))
                if current_timeout > per_cmd_ceiling:
                    self.log.info(
                        f"Capping tool timeout from {current_timeout}s to {per_cmd_ceiling}s "
                        f"so one command can't consume the whole phase budget ({int(time_left)}s left).")
                    current_timeout = per_cmd_ceiling
            if time_left < current_timeout:
                self.log.info(
                    f"Capping tool timeout from {current_timeout}s to {int(max(1, time_left))}s to respect phase deadline.")
                current_timeout = int(max(1, time_left))

            # UNIVERSAL: never run a tool with a timeout too small to possibly
            # succeed. A heavy tool given 1-9s (nuclei needs ~10s just to LOAD
            # its templates) is guaranteed to fail, then burns the repair loop
            # reruning the same doomed command. Once the phase budget is this
            # thin the phase is effectively over — skip cleanly instead.
            _min_viable = 45 if tool.lower() in heavy_tools else 8
            if current_timeout < _min_viable:
                self.log.warning(
                    f"[BUDGET] Only {current_timeout}s of phase budget left for '{tool}' "
                    f"(needs ~{_min_viable}s to be viable) — skipping rather than running it doomed.")
                return ToolResult(
                    tool=tool, command=current_command, stdout="",
                    stderr=f"Skipped: insufficient phase budget ({current_timeout}s < {_min_viable}s viable).",
                    exit_code=0, duration_seconds=0, status=ResultStatus.SKIPPED)

        timeout_cap = max(timeout * 4, timeout + 900)
        # UNIVERSAL anti-monopoly cap: no SINGLE command's run+repair+evasion loop
        # may consume more than a fraction of the WHOLE phase budget. Without this
        # the cap above (e.g. 3h for a heavy tool) is far larger than the phase, so
        # one command stuck in a slow loop (WAF evasion w/ 5s DNS timeouts, etc.)
        # ran until the phase deadline and STARVED every later loop — recon aborted
        # at loop 4 of 8 after one gobuster ate 67 min. Cap to 40% of the phase so
        # the phase always has budget left for other work; never below one viable
        # run so a legitimate heavy scan still gets its chance.
        _phase_total = getattr(self, "_phase_budget_total", 0) or 0
        if _phase_total > 0:
            # At most 40% of the WHOLE phase for this command's entire loop, but
            # never below ONE full run (current_timeout, already phase-capped) so a
            # legitimate heavy scan is never cut mid-run. The +60 covers overhead.
            timeout_cap = max(
                current_timeout + 60,
                min(timeout_cap, _phase_total * 0.4))
        start_time = _time_module.monotonic()

        while True:
            if _time_module.monotonic() - start_time > timeout_cap:
                self.log.error(
                    f"[TIMEOUT] Hard timeout cap ({timeout_cap}s) exceeded during safe_run_tool loop for {tool}")
                result = ToolResult(
                    tool=tool, command=current_command, stdout="",
                    stderr=f"Hard repair loop timeout cap exceeded ({timeout_cap}s).", exit_code=-1,
                    duration_seconds=0, status=ResultStatus.TIMEOUT
                )
                self._track_failure(result)
                return result

            if hasattr(self, "_phase_deadline") and self._phase_deadline and _time_module.monotonic(
            ) > self._phase_deadline:
                self.log.error(
                    f"[TIMEOUT] Phase deadline exceeded during safe_run_tool loop for {tool}")
                result = ToolResult(
                    tool=tool, command=current_command, stdout="",
                    stderr="Phase deadline exceeded during execution/repair", exit_code=-1,
                    duration_seconds=0, status=ResultStatus.TIMEOUT
                )
                self._track_failure(result)
                return result

            if self.should_abort():
                self.log.error(
                    f"[ABORT] Execution aborted during safe_run_tool loop for {tool}")
                result = ToolResult(
                    tool=tool, command=current_command, stdout="",
                    stderr=f"Engagement aborted: {self.node_label} resource critical.", exit_code=-1,
                    duration_seconds=0, status=ResultStatus.BLOCKED
                )
                self._track_failure(result)
                return result
            if repair_count > 0:
                self.log.info(
                    f"Repair attempt #{repair_count} for tool '{tool}'")

            # ── V6: CANONICALIZATION & TARGET VALIDATION (Inside Loop) ──
            # Apply canonicalization to AI-repaired commands before they are
            # executed.
            command_tool = (self._extract_primary_tool(
                current_command) or tool or "").lower()
            current_command = self._canonicalize_tool_command(
                command_tool, current_command, target=target or cmd_host)
            current_command = re.sub(
                r"(?i)(https?://)(?:https?://)+", r"\1", current_command)

            final_host = self._extract_host(current_command)
            is_exempt = bool(re.search(r'(?<!\S)(?:-h|--help|-version|--version|-iL|-l|-dL|-list|--list|--input-file)\b', current_command))
            if not final_host and not is_exempt and (target or getattr(
                    self.session, "target", None)):
                self.log.warning(
                    f"[TARGET VALIDATION] Missing target in command: {current_command}")
                result = ToolResult(
                    tool=tool,
                    command=current_command,
                    stdout="",
                    stderr="SYNTAX ERROR: The command is missing a valid target (IP, hostname, or URL). You MUST include the target in your command.",
                    exit_code=1,
                    duration_seconds=0,
                    status=ResultStatus.FAILURE
                )
            elif tool in VIRTUAL_TOOLS:
                command_to_run = self._apply_stealth_routing(tool, current_command)
                result = self.tools.run(
                    "ssh_cmd", command_to_run, self.name,
                    timeout=current_timeout, save_raw=True,
                    output_path=output_path, silent=silent
                )
            else:
                # UNIVERSAL stealth: route tool traffic through Tor when active.
                run_command = self._apply_stealth_routing(tool, current_command)
                result = self.tools.run(
                    tool, run_command, self.name,
                    timeout=current_timeout, save_raw=True,
                    output_path=output_path, silent=silent
                )

            if result is None:
                self.log.error(
                    f"Tool '{tool}' returned None - this should never happen.")
                result = ToolResult(
                    tool=tool, command=current_command, stdout="",
                    stderr="Tool manager returned None", exit_code=-2,
                    duration_seconds=0, status=ResultStatus.FAILURE
                )
                self._track_failure(result)
                return result

            # Override false-positive successes ONLY when the tool produced no
            # real output — i.e. the command was rejected and printed just a
            # usage/error banner. A tool that exits 0 WITH substantial output
            # (e.g. sslscan dumping a full certificate, whatweb its fingerprint)
            # is trusted even if the text happens to contain a marker substring.
            # ToolManager (_produced_real_output) already makes this call before
            # returning; WITHOUT the substantial-output guard here we were
            # RE-flipping results ToolManager had correctly accepted — marking
            # real successes as FAILURE and burning the repair/token budget
            # chasing phantom failures (the sslscan exit-0→FAILURE loop). A
            # hardcoded signature must never override real evidence; it may only
            # confirm an otherwise-empty result.
            if result.success:
                out_text = ((result.stdout or "") +
                            (result.stderr or "")).lower()
                real_output_len = len((result.stdout or "").strip())
                failure_sigs = [
                    "usage:", "unrecognized argument", "invalid option", "no such option",
                    "unknown flag", "illegal option", "invalid choice",
                    "flag provided but not defined", "could not find template",
                    "no such file or directory"
                ]
                if real_output_len < 200 and any(
                        sig in out_text for sig in failure_sigs):
                    self.log.warning(
                        f"[FALSE POSITIVE] Overriding exit code 0 to FAILURE for tool '{tool}' "
                        "(usage/error banner with no real output).")
                    result.success = False
                    result.status = ResultStatus.FAILURE
                    result.exit_code = 1

            # ── UNIVERSAL "NOT-A-BLOCK" GUARD (any tool, no per-tool vocab) ──
            # WAF evasion (rotating headers/IPs) can ONLY help an actual HTTP-layer
            # WAF block. Two common failures get MISLABELLED as blocks and then
            # loop forever in pointless evasion (the 'stuck' symptom):
            #   • SYNTAX rejection — the tool printed its OWN usage/help (proven by
            #     matching its real --help). Fix = re-ground against that help.
            #   • TRANSPORT error — a TLS cert mismatch, DNS failure, or refused/
            #     timed-out connection (below HTTP, no response served). Fix = AI
            #     repair (e.g. add `-k`) or abandon an unresolvable host.
            # A mis-applied block status EXCLUDES the result from the AI triage
            # below AND sends it to WAF evasion. Strip the block status so it flows
            # into triage + the --help-grounded repair loop instead. The triage
            # (AI) makes the actual accept/abandon/repair call; this only stops
            # evasion from stealing a result it can never fix.
            if (not result.success
                    and result.status in (
                        ResultStatus.WAF_BLOCKED, "waf_blocked",
                        ResultStatus.BLOCKED, "blocked")
                    and (self._is_syntax_rejection(tool, current_command, result)
                         or self._is_transport_error(result))):
                _why = ("printed its own usage/help (command-syntax error)"
                        if self._is_syntax_rejection(tool, current_command, result)
                        else "hit a transport/TLS/DNS/connection error")
                self.log.info(
                    f"[NOT-A-BLOCK GUARD] '{tool}' {_why} — WAF evasion can't fix this. "
                    f"Routing to AI triage + --help-grounded repair instead.")
                result.status = ResultStatus.FAILURE
                result.exit_code = result.exit_code or 1

            # ── DETERMINISTIC UN-REPAIRABLE EXIT GUARD (no AI call) ──────────
            # A structurally hopeless exit code (127 not-found, 126 not-exec,
            # 6 DNS, 7 refused, 137/143 killed, -1 no-code) can NEVER be fixed by
            # rewriting the command. Classify it HERE — before the AI triage and
            # the repair loop — so the operator does not (a) burn an AI triage
            # call on a foregone conclusion and (b) then guess new flags at a
            # missing binary (the #1 hallucination-compounding path). Purely
            # exit-code driven via core.safe_executor.classify_unrepairable — no
            # per-tool or per-error-string logic, so new tools inherit it for
            # free. should_retry() (later, line ~3111) shares the same exit set
            # as a backstop; this just stops the wasted work up front.
            if (not result.success
                    and not getattr(result, "was_timeout", False)
                    and result.status not in (
                        ResultStatus.BLOCKED, ResultStatus.SCOPE_BLOCKED,
                        ResultStatus.WAF_BLOCKED, ResultStatus.NOT_INSTALLED,
                        ResultStatus.SKIPPED)):
                _unrep = classify_unrepairable(result)
                if _unrep == "not_installed":
                    self.log.info(
                        f"[EXIT-GUARD] '{tool}' exit {getattr(result, 'exit_code', '?')}: "
                        f"binary missing / not executable — marking NOT_INSTALLED "
                        f"(no repair, no AI call).")
                    result.status = ResultStatus.NOT_INSTALLED
                    self._command_history[cmd_hash] = {
                        "ts": time.time(), "status": ResultStatus.NOT_INSTALLED.value}
                    self._track_failure(result)
                    return result
                if _unrep == "abandon":
                    self.log.info(
                        f"[EXIT-GUARD] '{tool}' exit {getattr(result, 'exit_code', '?')}: "
                        f"structurally un-repairable (DNS/refused/killed/no-code) — "
                        f"abandoning (no repair, no AI call).")
                    self._command_history[cmd_hash] = {
                        "ts": time.time(), "status": ResultStatus.FAILURE.value}
                    self._track_failure(result)
                    return result

            # ── UNIVERSAL AI OUTCOME TRIAGE ──────────────────────────────────
            # For a NON-success result, reason about what actually happened
            # instead of relying on hardcoded signature lists (which cannot
            # generalize to a tool/error/defense never seen before). Two
            # generalizing shortcuts are taken here; everything else falls
            # through to the existing repair/timeout logic UNCHANGED:
            #   • accept  — salvage useful output for ANY tool (no tool whitelist)
            #   • abandon — stop budget-burning on a non-recoverable failure (no
            #               hardcoded deterministic-error list)
            if (not result.success
                    and not getattr(result, "was_timeout", False)
                    and result.status not in (
                        ResultStatus.BLOCKED, ResultStatus.SCOPE_BLOCKED,
                        ResultStatus.WAF_BLOCKED, ResultStatus.NOT_INSTALLED,
                        ResultStatus.SKIPPED)):
                _verdict = self._interpret_outcome(tool, current_command, result)
                _act = (_verdict or {}).get("action")
                if _act == "accept":
                    self.log.info(
                        f"[AI TRIAGE] '{tool}': salvaging useful output despite a "
                        f"non-success exit — {(_verdict.get('reason') or '')[:120]}")
                    result.status = ResultStatus.FALLBACK_SUCCESS
                elif _act == "abandon":
                    self.log.info(
                        f"[AI TRIAGE] '{tool}': abandoning (non-recoverable for this "
                        f"target) — {(_verdict.get('reason') or '')[:140]}")
                    self._command_history[cmd_hash] = {
                        "ts": time.time(), "status": ResultStatus.FAILURE.value}
                    self._track_failure(result)
                    return result

            if result.success:
                # ── NEW: Persistent Syntax Learning ──
                if tool and hasattr(self, "syntax_learner"):
                    try:
                        err_ctx = str(result.stderr or result.stdout)[
                            :200] if repair_count > 0 else "Success on first try"
                        self.syntax_learner.learn_syntax(
                            tool, current_command, err_ctx,
                            context=self._syntax_context())
                    except Exception as _e:
                        self.log.debug(
                            f"Failed to persist syntax learning: {_e}")

                # Update dedup record: mark as succeeded so future identical
                # commands are allowed
                self._command_history[cmd_hash] = {
                    "ts": now, "status": ResultStatus.SUCCESS.value}
                if hasattr(self, "awareness"):
                    self.awareness.register_tool_outcome(
                        current_command, "tool_execution", success=True)
                # Feed the effectiveness tracker on SUCCESS too (not just on
                # failure) so success rates and durations are real.
                self._record_tool_metric(result, success=True)
                # Record in advisor for strategic learning
                if hasattr(self, "advisor") and self.advisor:
                    try:
                        self.advisor.record_tool_outcome(
                            tool=tool,
                            target=target or cmd_host or "unknown",
                            success=True,
                            duration=getattr(
                                result, "duration_seconds", 0.0) or 0.0,
                            phase=self.name,
                        )
                    except Exception as _advisor_err:
                        self.log.debug(
                            f"Advisor success record failed: {_advisor_err}")

                if tool.lower() in HTTP_TOOLS:
                    try:
                        recon_bundle = self.store.get_phase_data(
                            self.session.engagement_id, "recon"
                        ) if hasattr(self, 'store') and hasattr(self.session, 'engagement_id') else {}
                        waf_fingerprint = (
                            recon_bundle or {}).get("waf_fingerprint") or {}
                        waf_present = (
                            recon_bundle or {}).get(
                            "waf_present", False)
                        if waf_present or waf_fingerprint:
                            host_for_learning = cmd_host or self._extract_host(
                                current_command) or target or "default"
                            if self._waf_ghost:
                                self._waf_ghost.feedback(
                                    host_for_learning, tool, blocked=False)
                            if self._waf_learner:
                                waf_id = "generic"
                                if isinstance(waf_fingerprint, dict):
                                    waf_id = waf_fingerprint.get(
                                        "waf_type") or waf_fingerprint.get("id") or "generic"
                                self._waf_learner.update_tactic_effectiveness(
                                    "header_mutation", True, waf_id=str(waf_id))
                    except Exception as _waf_learn_err:
                        self.log.debug(
                            f"WAF learning success feedback error (non-fatal): {_waf_learn_err}")
                return result

            last_result = result
            if repair_count >= max_repairs:
                self._command_history[cmd_hash] = {
                    "ts": time.time(), "status": getattr(
                        ResultStatus, "FAILURE", "failed")}
                self._track_failure(last_result)
                if hasattr(self, "awareness"):
                    self.awareness.register_tool_outcome(
                        current_command, "tool_execution", success=False)
                # Record in advisor for strategic learning
                if hasattr(self, "advisor") and self.advisor:
                    try:
                        self.advisor.record_tool_outcome(
                            tool=tool,
                            target=target or cmd_host or "unknown",
                            success=False,
                            duration=getattr(
                                last_result, "duration_seconds", 0.0) or 0.0,
                            phase=self.name,
                        )
                    except Exception as _advisor_err:
                        self.log.debug(
                            f"Advisor failure record failed: {_advisor_err}")
                return last_result

            if result.exit_code in NETWORK_UNFIXABLE_EXITS:
                self.log.warning(
                    f"Unfixable network error for {tool} ({
                        result.status}). Skipping repair.")
                self._command_history[cmd_hash] = {
                    "ts": time.time(), "status": getattr(
                        ResultStatus, "FAILURE", "failed")}
                self._track_failure(last_result)
                return last_result

            # UNIVERSAL transport-failure abandon: if the tool could not even
            # reach the target PORT (closed/filtered/timeout/refused), no AI
            # flag-repair can fix that — a closed port stays closed no matter how
            # we tweak -t/-w. Abandon instead of burning N repair attempts (the
            # hydra-SSH-vs-Vercel-IP-with-no-:22 case ran 12 times over ~6min).
            # Keys off the tool's OWN error output, so it works for any tool.
            _transport_blob = (result.stdout + result.stderr).lower()
            _TRANSPORT_DEAD = (
                "could not connect", "timeout connecting", "connection timed out",
                "connection refused", "no route to host", "network is unreachable",
                "host is down", "could not resolve", "failed to resolve",
            )
            if any(m in _transport_blob for m in _TRANSPORT_DEAD):
                _w = next(m for m in _TRANSPORT_DEAD if m in _transport_blob)
                self.log.warning(
                    f"[ABANDON] {tool}: transport-level failure ('{_w}') — the target "
                    f"port is unreachable; no flag change can open a closed port. "
                    f"Not repairing. (Likely a phantom service from a noisy port scan.)")
                self._command_history[cmd_hash] = {
                    "ts": time.time(), "status": getattr(
                        ResultStatus, "FAILURE", "failed")}
                # Surface a clear lead so the AI's next move steers away from this
                # dead port rather than re-prescribing it.
                try:
                    _dead_host = self._extract_host(current_command) or cmd_host or target or "target"
                    self._recent_failures.append(
                        f"[UNREACHABLE] {tool} could not connect to {_dead_host} "
                        f"('{_w}') — that port/service is closed or filtered; do NOT re-attempt it.")
                except Exception:
                    pass
                self._track_failure(last_result)
                return last_result

            if self._should_rate_limit(result, cmd_host):
                # Re-running the SAME scan after a rate-limit just re-triggers it
                # — it sends the same flood of requests. A heavy scanner
                # (ffuf/gobuster/nuclei...) costs 10-20 min PER attempt, so
                # looping wait→re-run burned ~90 min on one ffuf and proved
                # nothing. A WAF rate-limit is not a command bug: ABANDON heavy
                # tools on the first rate-limit (move to a different technique),
                # and give light tools one transient-backoff retry before
                # abandoning. Bounded, universal — no per-tool attack logic.
                _rl_key = f"{tool}@{cmd_host or target}"
                if not hasattr(self, "_rate_limit_counts"):
                    self._rate_limit_counts = {}
                self._rate_limit_counts[_rl_key] = self._rate_limit_counts.get(
                    _rl_key, 0) + 1
                _abandon_at = 1 if tool.lower() in heavy_tools else 2
                if self._rate_limit_counts[_rl_key] >= _abandon_at:
                    self.log.warning(
                        f"[RATE-LIMIT ABANDON] '{tool}' rate-limited "
                        f"{self._rate_limit_counts[_rl_key]}x on {cmd_host or target} "
                        f"— re-running the same scan can't beat a throughput limit; "
                        f"abandoning to save the phase budget for other techniques.")
                    self._command_history[cmd_hash] = {
                        "ts": time.time(), "status": ResultStatus.BLOCKED.value}
                    self._track_failure(result)
                    return result
                self._wait_rate_limit(result, cmd_host)
                repair_count += 1
                continue

            if result.status not in (ResultStatus.FAILURE, "failed", ResultStatus.TIMEOUT, "timeout",
                                     ResultStatus.BLOCKED, "blocked", ResultStatus.ERROR, "error") or not should_retry(result):
                self._command_history[cmd_hash] = {
                    "ts": time.time(), "status": getattr(
                        ResultStatus, "FAILURE", "failed")}
                self._track_failure(last_result)
                return last_result

            # ── EVASION CIRCUIT-BREAKER (universal, zero extra AI cost) ──────
            # WAF evasion is only worth doing if it CHANGES the outcome. If two
            # successive attempts on the SAME command yield the SAME failure
            # signature (exit code + error fingerprint), evasion is futile here —
            # it isn't really an evadable WAF block, or this defense can't be
            # beaten from here — and looping just burns the phase (the gobuster
            # that ate 67 min). Bail to the AI triage + --help repair instead.
            # The signal is purely "did evasion move the needle?": no hardcoded
            # cause list, no per-block AI call — so it catches ANY future unknown
            # stuck-cause, not just the ones we have vocab for.
            if result.status in (ResultStatus.BLOCKED, "blocked",
                                 ResultStatus.WAF_BLOCKED, "waf_blocked"):
                try:
                    _ev_sig = f"{getattr(result, 'exit_code', '')}:" + hashlib.md5(
                        ((result.stderr or "")[-400:] +
                         (result.stdout or "")[-400:]).strip().lower().encode(
                            "utf-8", "ignore")).hexdigest()[:12]
                    if not hasattr(self, "_waf_evasion_state"):
                        self._waf_evasion_state = {}
                    _ev = self._waf_evasion_state.setdefault(
                        cmd_hash, {"sig": None, "stuck": 0})
                    if _ev["sig"] == _ev_sig:
                        _ev["stuck"] += 1
                    else:
                        _ev["sig"], _ev["stuck"] = _ev_sig, 0
                    if _ev["stuck"] >= 1:
                        # 2nd identical block in a row → evasion changed nothing.
                        self.log.warning(
                            f"[EVASION CIRCUIT-BREAKER] WAF evasion changed nothing for "
                            f"'{tool}' (same failure twice) — abandoning evasion, routing "
                            f"to AI triage + --help repair instead of looping the phase away.")
                        result.status = ResultStatus.FAILURE
                        result.exit_code = result.exit_code or 1
                        self._waf_evasion_state.pop(cmd_hash, None)
                except Exception as _cb_e:
                    self.log.debug(
                        f"evasion circuit-breaker check failed (non-fatal): {_cb_e}")

            if result.status in (ResultStatus.BLOCKED, "blocked",
                                 ResultStatus.WAF_BLOCKED, "waf_blocked"):
                # ── WAF EVASION ENGINE: activate learned evasion tactics on any block ──
                # WafEvasionEngine picks the best tactic based on recon fingerprint data.
                # Actual command mutation is handled by WafGhostEngine (the
                # transformer).
                try:
                    recon_bundle = self.store.get_phase_data(
                        self.session.engagement_id, "recon"
                    ) if hasattr(self, 'store') and hasattr(self.session, 'engagement_id') else {}
                    waf_fingerprint = (
                        recon_bundle or {}).get("waf_fingerprint") or {}
                    waf_present = (
                        recon_bundle or {}).get(
                        "waf_present",
                        False)
                    if waf_present or waf_fingerprint:
                        evasion_strategy = self._waf_evasion.build_evasion_strategy(
                            waf_fingerprint or {
                                "waf_type": "generic", "block_frequency": 0.8}
                        )
                        tactic = (evasion_strategy.get("evasion_tactics") or [
                                  {"name": "header_mutation"}])[0]
                        tactic_name = tactic.get("name") if isinstance(
                            tactic, dict) else str(tactic)
                        self._waf_evasion.rotate_tactic()
                        self.log.info(
                            f"[WAF EVASION] Block detected. Applying tactic '{tactic_name}'. WAF: {
                                waf_fingerprint.get(
                                    'waf_type', 'generic')}")

                        # Apply the tactic to get evasion parameters
                        evasion_data = self._waf_evasion.apply_tactic(
                            tactic_name, {"command": current_command})
                        if "_evasion_delay" in evasion_data:
                            delay = evasion_data["_evasion_delay"]
                            self.log.info(
                                f"[WAF EVASION] Tactic {tactic_name}: Sleeping {delay}s")
                            time.sleep(delay)
                        if "_proxy_request" in evasion_data:
                            self.log.info(
                                f"[WAF EVASION] Tactic {tactic_name}: Rotating IP")
                            current_command = f"proxychains4 -q {current_command}"

                        try:
                            host_for_learning = cmd_host or self._extract_host(
                                current_command) or target or "default"
                            if self._waf_ghost:
                                self._waf_ghost.feedback(
                                    host_for_learning, tool, blocked=True)
                            if self._waf_learner:
                                waf_id = "generic"
                                if isinstance(waf_fingerprint, dict):
                                    waf_id = waf_fingerprint.get(
                                        "waf_type") or waf_fingerprint.get("id") or "generic"
                                self._waf_learner.update_tactic_effectiveness(
                                    str(tactic), False, waf_id=str(waf_id))
                        except Exception as _waf_block_learn_err:
                            self.log.debug(
                                f"WAF learning block feedback error (non-fatal): {_waf_block_learn_err}")
                except Exception as _waf_evasion_err:
                    self.log.debug(
                        f"WAF evasion engine error (non-fatal): {_waf_evasion_err}")

                # ── V6: WAF ORCHESTRATOR ESCALATION (Proactive Bypass) ──
                if hasattr(
                        self, "_waf_orchestrator") and self._waf_orchestrator:
                    try:
                        self.log.info(
                            f"[WAF ORCHESTRATOR] Block detected for {tool}. Escalating...")
                        # Only run if we haven't maxed out repairs for this
                        # specific command run
                        if repair_count < 2:
                            # V6.1: Import Authorization Exception
                            from intelligence.waf_bypass_orchestrator import WafAttackAuthorizationRequired

                            try:
                                bypass_res = self._waf_orchestrator.execute_bypass(
                                    self.session.engagement_id, target
                                )
                            except WafAttackAuthorizationRequired as e:
                                self.log.warning(f"[HITL GATE] {e}")
                                # Request HITL authorization
                                # In a real agentic flow, we pause and wait for user input.
                                # For this CLI implementation, we will log it and skip to next strategy unless auto-approved by a flag.
                                # If we had an interactive bus, we would block
                                # here. Since this is non-interactive batch
                                # mode mostly:
                                self.log.error(
                                    f"HITL Attack '{
                                        e.attack_name}' requires manual approval. Skipping bypass strategy.")
                                bypass_res = {
                                    "success": False,
                                    "strategy": e.attack_name,
                                    "error": "HITL Authorization Denied"}

                            if bypass_res.get("success"):
                                bypass_url = bypass_res.get("bypass_url")
                                self.log.info(
                                    f"[WAF ORCHESTRATOR] Bypass SUCCEEDED via {
                                        bypass_res.get('strategy')}")

                                # ── V6: PERSIST BYPASS TO STATE STORE ──
                                # This is critical: ensures subsequent tools
                                # adoption
                                try:
                                    recon_data = self.store.get_phase_data(
                                        self.session.engagement_id, "recon") or {}
                                    recon_data["waf_bypass_url"] = bypass_url
                                    recon_data["waf_bypass_strategy"] = bypass_res.get(
                                        "strategy")
                                    self.store.set_phase_data(
                                        self.session.engagement_id, "recon", recon_data)
                                    self.log.info(
                                        f"[WAF PERSISTENCE] Persisted bypass URL {bypass_url} to StateStore.")
                                except Exception as _persist_err:
                                    self.log.debug(
                                        f"Failed to persist bypass: {_persist_err}")

                                if bypass_url:
                                    host_match = self._extract_host(
                                        current_command)
                                    if host_match and host_match.rstrip(
                                            '/') != bypass_url.rstrip('/'):
                                        self.log.info(
                                            f"[WAF ORCHESTRATOR] Re-targeting retry: {host_match} -> {bypass_url}")
                                        escaped_host = re.escape(host_match)
                                        current_command = re.sub(
                                            r'(?<![a-zA-Z0-9/._:-])' +
                                            escaped_host +
                                            r'(?![a-zA-Z0-9._/-])',
                                            bypass_url.rstrip('/'),
                                            current_command,
                                        )

                                repair_count += 1
                                continue
                            else:
                                self.log.warning(
                                    f"[WAF ORCHESTRATOR] Strategy '{
                                        bypass_res.get('strategy')}' failed. Escalating tier.")
                                self._waf_orchestrator.increment_evasion_tier(
                                    target)
                    except Exception as _orc_err:
                        self.log.debug(
                            f"WAF orchestrator escalation error (non-fatal): {_orc_err}")

                if self._waf_ghost:
                    self.log.info(
                        "Command blocked. Escalating WafGhost mutation...")
                    # force=True: this branch is reached only after a confirmed
                    # block, so evasion is warranted regardless of block-rate.
                    current_command = self._waf_ghost.transform(
                        current_command, tool, force=True)
                    repair_count += 1
                    continue

                # ── V6: AI-DRIVEN REPAIR (Final Failsafe) ──
                if self.ai and repair_count >= max_repairs - 1:
                    self.log.info(
                        f"[AI REPAIR] Standard repairs failed for {tool}. Asking AI for creative mutation...")
                    try:
                        prompt = f"""
                        The following security tool command was BLOCKED by a WAF:
                        Command: {current_command}
                        Tool: {tool}

                        The standard header mutations and origin discovery did not work.
                        Suggest a modified version of this command that might bypass the WAF.
                        You can:
                        - Change encoding (e.g. use double URL encoding if tool supports it)
                        - Add obscure headers
                        - Change the user-agent to something specific
                        - Use a different protocol version if applicable

                        Return ONLY the modified command string.
                        """
                        ai_mutation = self.ai.query(
                            system_prompt="You are an expert in WAF bypass and command-line tool optimization.",
                            user_message=prompt,
                            model_id=self._light_model())
                        if ai_mutation and ai_mutation.strip() and ai_mutation.strip() != current_command:
                            self.log.info(
                                f"[AI REPAIR] AI suggested mutation: {
                                    ai_mutation.strip()}")
                            current_command = ai_mutation.strip()
                            repair_count += 1
                            continue
                    except Exception as _ai_err:
                        self.log.debug(f"AI repair failed: {_ai_err}")

            if self._stealth.get("rotate_ip") and self._ip_rotator and result.status in (
                    ResultStatus.BLOCKED, "blocked"):
                self._ip_rotator.rotate()
                self.log.info("IP rotated due to block.")
                repair_count += 1
                continue

            # ── V6: TIMEOUT ESCALATION (if command timed out, automatically make it lighter) ──
            if result.status in (ResultStatus.TIMEOUT, "timeout"):
                tool_target_key = f"{tool}@{cmd_host or target or 'unknown'}"

                self._tool_failure_counts[tool_target_key] = self._tool_failure_counts.get(
                    tool_target_key, 0) + 1

                fail_count = self._tool_failure_counts[tool_target_key]

                # Ban tool after 3 consecutive failures
                if fail_count >= 3:
                    self._tool_ban_list.add(tool_target_key)
                    self.log.warning(
                        f"[TOOL BAN] {tool} banned for {
                            cmd_host or target} after 3 timeouts.")
                    # ── V6 CROSS-PHASE PERSISTENCE: write ban to StateStore ──
                    if self.store and self.session and hasattr(
                            self.session, "engagement_id"):
                        try:
                            existing_bans: list = self.store.get(
                                f"{self.session.engagement_id}:tool_bans") or []
                            if isinstance(existing_bans, str):
                                import json as _json
                                existing_bans = _json.loads(existing_bans)
                            if tool_target_key not in existing_bans:
                                existing_bans.append(tool_target_key)
                            import json as _json
                            self.store.set(
                                f"{self.session.engagement_id}:tool_bans", _json.dumps(existing_bans))
                        except Exception as _ban_err:
                            self.log.debug(
                                f"[TOOL BAN] Could not persist ban to store: {_ban_err}")
                    # ────────────────────────────────────────────────────────────────────
                    dur = getattr(
                        result, "duration_seconds", getattr(
                            result, "duration", 0.0))
                    return ToolResult(tool=tool, command=current_command, stdout="",
                                      stderr=f"Tool {tool} auto-banned: 3+ consecutive timeouts on this target",
                                      exit_code=-1, duration_seconds=dur, status=ResultStatus.BLOCKED)

                # Apply timeout escalation: make command lighter and increase
                # timeout
                self.log.info(
                    f"[TIMEOUT ESCALATION] Attempt #{fail_count} for {tool}. Making command lighter...")
                lighter_cmd = self._make_command_lighter(
                    tool, current_command, fail_count)

                if lighter_cmd != current_command:
                    current_command = lighter_cmd
                    current_command = self._canonicalize_tool_command(
                        tool, current_command, target=target or cmd_host)
                    cmd_hash = hashlib.sha256(
                        current_command.encode()).hexdigest()[:16]
                    self.log.info(
                        f"[TIMEOUT ESCALATION] Reduced scope/flags: {current_command[:120]}... (New hash: {cmd_hash})")
                    # A lighter command finishes faster, so trim the timeout to
                    # fail CHEAPLY instead of burning N full timeouts (the nmap
                    # --script case burned 900s×3 = 45min of dead air). BUT under
                    # Tor a timeout usually means "Tor is slow", not "too much
                    # work" — halving to a 90s floor then RE-times-out, and 3 such
                    # timeouts BAN the tool for the whole engagement (why every
                    # heavy tool died on the WAF'd Tor target). So under Tor trim
                    # GENTLY with a much higher floor; only fail-fast hard when
                    # running direct.
                    if _tor_on:
                        current_timeout = max(240, int(current_timeout * 0.8))
                    else:
                        current_timeout = max(90, int(current_timeout * 0.5))
                    self.log.info(
                        f"[TIMEOUT ESCALATION] Retry timeout set to {current_timeout}s "
                        f"({'Tor-gentle' if _tor_on else 'fail-fast'}).")
                else:
                    self.log.warning(
                        "[TIMEOUT ESCALATION] No lighter version available. Increasing timeout...")
                    current_timeout = min(timeout_cap, max(
                        current_timeout + 120, int(current_timeout * 2)))

                # Update dedup record with TIMEOUT status so a lighter-version
                # retry is allowed
                self._command_history[cmd_hash] = {
                    "ts": now, "status": ResultStatus.TIMEOUT.value}
                # Track in history for AI awareness
                self._recent_failures.append(
                    f"[TIMEOUT] {tool} on {
                        cmd_host or target} (attempt {fail_count})")
                repair_count += 1
                continue

            # Ghost Protocol AI repair
            if is_repair:
                self.log.warning(f"Repair attempt for '{tool}' failed. Breaking loop to prevent infinite recursion.")
                break

            suggestion = self._ai_repair_tool(tool, current_command, result)
            if suggestion and suggestion != current_command:
                # RC-4 FIX: Hash the raw AI suggestion BEFORE flag correction.
                # The corrector used to produce a different hash than the suggestion,
                # bypassing the dedup guard and allowing the same broken repair
                # to loop.
                suggestion_hash = hashlib.sha256(
                    suggestion.encode()).hexdigest()[:16]
                if suggestion_hash in self._command_history:
                    existing = self._command_history[suggestion_hash]
                    if existing.get("status") not in (
                            ResultStatus.TIMEOUT.value, "timeout"):
                        self.log.warning(
                            "[AI REPAIR SKIPPED] Same repair output already tried this engagement. "
                            "Abandoning to prevent identical-repair loop."
                        )
                        self._command_history[cmd_hash] = {
                            "ts": time.time(), "status": getattr(
                                ResultStatus, "FAILURE", "failed")}
                        self._track_failure(last_result)
                        return last_result
                self._command_history[suggestion_hash] = {
                    "ts": now, "status": "ai_repair_pending"}
                current_command = self._clean_command(suggestion)
                current_command = self._canonicalize_tool_command(
                    tool, current_command, target=target or cmd_host)
                cmd_hash = hashlib.sha256(
                    current_command.encode()).hexdigest()[:16]
                self.log.info(
                    f"AI suggested command repair. (New hash: {cmd_hash})")
                repair_count += 1
                continue
            else:
                self._command_history[cmd_hash] = {
                    "ts": time.time(), "status": getattr(
                        ResultStatus, "FAILURE", "failed")}
                self._track_failure(last_result)
                return last_result

    def _harden_shell_cmd(self, cmd: str) -> str:
        """
        Sanitize and harden an AI-generated shell command before execution.
        Strips dangerous operators, validates structure, and ensures the command
        is safe to execute on the remote VPS.

        Called by ReconAgent (and any other agent) before running AI-suggested commands.
        Returns the hardened command string, or empty string if command is rejected.
        """
        if not cmd or not cmd.strip():
            return ""

        try:
            # Normalize Unicode lookalikes to ASCII (e.g. em-dash -> hyphen)
            # then strip remaining non-printable characters
            cleaned = self._normalize_unicode_to_ascii(cmd.strip())

            # Reject commands with outright destructive sequences
            DANGEROUS_PATTERNS = [
                r';\s*rm\s+-rf',
                r'&&\s*rm\s+-rf',
                r'\|\s*rm\s+-rf',
                r'mkfs\.',
                r'dd\s+if=',
                r':\s*\(\s*\)\s*\{',   # fork bomb
                r'>/dev/sd[a-z]',
                r'chmod\s+777\s+/',
                r'nmap\s+.*-sU',       # UDP scans are too slow/unreliable and cause timeouts
            ]
            for pattern in DANGEROUS_PATTERNS:
                if re.search(pattern, cleaned, re.IGNORECASE):
                    self.log.warning(
                        f"[HARDEN] Rejected dangerous command pattern '{pattern}': {cleaned[:80]}")
                    return ""

            # Reject commands that try to exfiltrate to unknown external hosts
            # (allow our known VPS tools but block ad-hoc curl/wget to random IPs)
            EXFIL_PATTERN = r'(?:curl|wget)\s+.*?(?:\d{1,3}\.){3}\d{1,3}(?!.*(?:target|scope))'
            if re.search(EXFIL_PATTERN, cleaned, re.IGNORECASE):
                # Check if it's targeting our scope - if not, warn but allow
                # (tools may use IPs)
                self.log.debug(
                    f"[HARDEN] Potential external IP in command (non-fatal): {cleaned[:80]}")

            # Enforce max command length
            if len(cleaned) > 4096:
                self.log.warning(
                    f"[HARDEN] Command too long ({
                        len(cleaned)} chars), truncating.")
                cleaned = cleaned[:4096]

            return cleaned
        except Exception as e:
            self.log.error(f"[HARDEN] Command hardening failed: {e}")
            return ""

    def _should_rate_limit(self, result: ToolResult, host: str) -> bool:
        # ONLY a genuine throughput rate-limit (429 / "rate limit" / RATE_LIMITED).
        # A WAF BLOCK is deliberately NOT treated as a rate-limit: it must fall
        # through to the WAF EVASION path (mutate the request and retry), which
        # was DEAD because this method used to catch BLOCKED here and back off /
        # abandon — so the engine's whole WafGhost/evasion machinery never ran on
        # a real block. (A block that ALSO carries a 429 is still a rate-limit.)
        if not host:
            return False
        if result.status == ResultStatus.RATE_LIMITED:
            return True
        if "429" in (result.stdout or "") or "429" in (result.stderr or ""):
            return True
        if "rate limit" in (result.stderr or "").lower():
            return True
        return False

    def _http_probe(self, url: str, timeout: int = 8) -> tuple[int, int, dict]:
        """Lightweight HTTP probe returning (status_code, content_length, headers).
        Non-fatal: returns (0,0,{}) on error.
        """
        try:
            headers = STEALTH_HEADERS.copy() if isinstance(STEALTH_HEADERS, dict) else {}
            r = requests.get(
                url,
                headers=headers,
                timeout=timeout,
                allow_redirects=True)
            length = len(r.content) if r.content is not None else 0
            return r.status_code, length, dict(r.headers or {})
        except Exception as e:
            self.log.debug(
                f"HTTP probe failed for {url}: {
                    type(e).__name__} - {e}")
            return 0, 0, {}

    def _preflight_adjust_for_wildcard(
            self, tool: str, command: str, target: str) -> str:
        """Detect wildcard/always-200 responses and adapt dir-bruteforce commands.

        - For `gobuster` commands that are likely to hit wildcard responses, switch
          to a lighter `ffuf` invocation with reduced threads and a micro-wordlist.
        - For `ffuf` commands, reduce threads and use micro-wordlist when wildcard
          behavior is detected.

        This function is intentionally heuristic and uses runtime probes rather
        than hardcoded rules for specific targets.
        """
        primary = self._extract_primary_tool(command) or tool
        lower = (primary or tool).lower()

        from core.config_loader import get_config_manager
        tuning_config = get_config_manager().get("tools.wildcard_tuning", {})

        if lower not in tuning_config:
            return command

        # Prepare probe URLs
        try:
            ctx = TargetContext.from_input(target)
            base = ctx.base_url
        except Exception as e:
            import logging as __logging_tmp
            __logging_tmp.getLogger(__name__).debug(f"Silenced exception: {e}")
            base = target

        # Probe the base URL and a random non-existent path
        import uuid
        rand_path = str(uuid.uuid4())
        probe_base = base if base.endswith("/") else base + "/"
        probe_url_existing = probe_base
        probe_url_random = probe_base + rand_path

        st_base, len_base, _hbase = self._http_probe(
            probe_url_existing, timeout=6)
        st_rand, len_rand, _hrand = self._http_probe(
            probe_url_random, timeout=6)

        # Heuristic: if random path returns same status and similar length,
        # it's wildcard
        wildcard = False
        if st_rand != 0 and st_base != 0:
            if st_rand == st_base:
                # length difference small (within 5%) considered wildcard
                if len_base == 0:
                    wildcard = True
                else:
                    diff = abs(len_base - len_rand)
                    if diff <= max(10, int(len_base * 0.05)):
                        wildcard = True

        if not wildcard:
            # No adjustment needed
            return command

        # Wildcard detected: adapt command conservatively
        self.log.info(
            f"[PREFLIGHT] Wildcard-like responses detected for {base} (st={st_base}, rand={st_rand}); adapting {lower} command.")

        # AI engine now explicitly injects `{WORDLIST}` templates which get translated to actual paths
        # in the agent loop. There is no need for `_harden_shell_cmd` to force
        # wordlist overrides anymore.

        tool_config = tuning_config[lower]

        if tool_config.get("status_code_flag"):
            status_flag = tool_config["status_code_flag"]
            if st_rand in [403, 500, 503, 400]:
                if f"{status_flag} " in command:
                    # Dynamically append to existing blocklist
                    command = re.sub(
                        rf'{status_flag}\s+([\d,]+)', lambda m: f'{status_flag} {
                            m.group(1).rstrip(",")},{st_rand}' if str(st_rand) not in m.group(1).split(",") else f'{status_flag} {
                            m.group(1)}', command)
                else:
                    base = tool_config.get("status_code_base", "404")
                    command += f" {status_flag} {base},{st_rand}"

        if tool_config.get("length_flag") and len_rand > 0:
            length_flag = tool_config["length_flag"]
            if length_flag not in command:
                if tool_config.get("length_format") == "exact":
                    command += f" {length_flag} {len_rand}"
                else:
                    offset = tool_config.get("length_range_offset", 30)
                    min_len = max(1, len_rand - offset)
                    max_len = len_rand + offset
                    command += f" {length_flag} {min_len}-{max_len}"

        if tool_config.get("extra_flags"):
            for flag in tool_config["extra_flags"].split():
                if flag not in command:
                    command += f" {flag}"

        return command

    def _wait_rate_limit(self, result: ToolResult, host: str) -> None:
        retry = None
        combined = f"{result.stdout or ''}\n{result.stderr or ''}"
        m = re.search(r"retry-after\s*[:=]\s*(\d+)", combined, re.IGNORECASE)
        if m:
            retry = m.group(1)

        if retry is not None:
            wait = int(retry)
        else:
            self._host_rate_limits[host] = self._host_rate_limits.get(
                host, RATE_LIMIT_INITIAL_BACKOFF) * 2
            wait = min(self._host_rate_limits[host], RATE_LIMIT_MAX_BACKOFF)
        self.log.info(f"Rate limit detected on {host}. Waiting {wait}s...")
        _time_module.sleep(wait)

    def _post_scan_cooldown(self, scan_type: str) -> None:
        """
        Post-scan cooldown: wait after a heavy scan (e.g. Nuclei) to evade WAF/IPS.
        """
        if POST_HEAVY_SCAN_COOLDOWN > 0:
            agent_msg(
                self.name,
                f"WAF-Awareness: Heavy scan '{scan_type}' completed. Cooling down for {POST_HEAVY_SCAN_COOLDOWN}s to evade detection...")
            self.log.info(
                f"Post-scan cooldown for {scan_type}: {POST_HEAVY_SCAN_COOLDOWN}s")
            _time_module.sleep(POST_HEAVY_SCAN_COOLDOWN)

    def reset_context(self):
        """
        Implement Contextual Isolation.
        Clears short-term conversation context between discrete tasks
        to prevent LLM hallucination and context window overflow.
        """
        self.log.info(
            f"[{self.name}] Contextual isolation: resetting short-term memory.")
        self.session.clear_transient_context()

    def _extract_primary_tool(self, command: str) -> str | None:
        cmd = self._strip_command_prose((command or "").strip())
        if not cmd:
            return None

        # Trim wrapper prefixes like "export ... && tool ..." or "VAR=1 && tool
        # ..."
        parts = [p.strip() for p in re.split(r"\s*&&\s*", cmd) if p.strip()]
        while parts:
            head = parts[0]
            if head.startswith("export ") or re.match(
                    r"^[A-Za-z_][A-Za-z0-9_]*=.*$", head):
                parts.pop(0)
                continue
            cmd = head
            break

        m = re.search(
            r'^(?:proxychains4?\s+(?:-q\s+)?|timeout\s+\d+\s+|sudo\s+)*([\w.-]+)',
            cmd,
            re.IGNORECASE)
        if not m:
            return None
        return m.group(1).lower()

    def _make_command_lighter(
            self, tool: str, command: str, attempt: int) -> str:
        """
        Progressive reduction of scanning scope instead of just slowing down.
        Delegates to the AI to intelligently make the command lighter based on the learned syntax.
        """
        effective_tool = tool
        if tool in {"ai_dynamic_recon", "ssh_cmd",
                    "remote_exec", "react_payload", "python", "python3"}:
            effective_tool = self._extract_primary_tool(command) or tool

        tier = min(3, attempt if attempt > 0 else 1)
        
        # Give the AI context of the tool's syntax hints so it generates correct flags
        syntax_hints = ""
        if hasattr(self, "syntax_learner"):
            syntax_hints = self.syntax_learner.get_syntax_hints(
                [effective_tool], context=self._syntax_context())
            
        system_prompt = (
            "You are an expert offensive security AI. A tool command timed out or "
            "kept failing — it is doing TOO MUCH WORK for the time budget.\n"
            f"Make it significantly lighter (Tier {tier} reduction).\n"
            "KEY INSIGHT: the #1 cause of a timeout is SCAN BREADTH — full port "
            "ranges (e.g. nmap -p-), large wordlists, many targets — NOT thread "
            "count. Cutting breadth helps far more than slowing threads, and you "
            "must NEVER raise parallelism/threads (e.g. --min-parallelism) to 'go "
            "faster' — that makes it heavier.\n"
            "Tier 1: cut breadth modestly (e.g. top ~1000 ports instead of -p-, a "
            "smaller wordlist).\n"
            "Tier 2: cut breadth HARD (a handful of common ports, a tiny wordlist) "
            "AND lower concurrency.\n"
            "Tier 3: absolute minimum scope (a single port/file/thread, no retries).\n"
            "Keep the SAME tool and target — only shrink the workload.\n"
            "Output ONLY the new raw command string, nothing else. Do not use markdown backticks."
        )
        if syntax_hints:
            system_prompt += f"\n{syntax_hints}"
            
        user_prompt = f"Original command:\n{command}\n\nLighter command:"
        
        try:
            self.log.info(f"Asking AI to make command lighter (Tier {tier})...")
            res = self.ai.query(system_prompt, user_prompt)
            if res and res.strip():
                lighter = res.strip()
                # strip potential markdown
                lighter = re.sub(r'^```[a-z]*\n', '', lighter)
                lighter = re.sub(r'\n```$', '', lighter)
                return self._canonicalize_tool_command(effective_tool, lighter)
        except Exception as e:
            self.log.error(f"Failed to make command lighter via AI: {e}")

        return self._canonicalize_tool_command(effective_tool, command)

    def _syntax_context(self) -> dict:
        """Current engagement identity used to abstract/re-hydrate learned
        syntax (target host + WSL workspace dir). Cached per agent."""
        if self._syntax_ctx_cache is None:
            try:
                import config_paths
                self._syntax_ctx_cache = {
                    "target": getattr(self.session, "target", "") or "",
                    "workdir": config_paths.WSL_TEMP_DIR,
                }
            except Exception:
                self._syntax_ctx_cache = {"target": "", "workdir": ""}
        return self._syntax_ctx_cache

    def _ground_prescriptions(self, prescriptions: list, phase: str = "recon") -> list:
        """PROACTIVE grounding (pass 2 of two-pass generation).

        Pass 1 (the caller's normal think()) gives us DRAFT prescriptions —
        the AI's choice of tools + intent, written from memory. Here we fetch
        each named tool's REAL `--help` (ground truth, cached) and ask the AI
        to rewrite each command so its syntax matches that help. This stops the
        engine from firing blind, wrong commands and then burning the whole
        retry/repair/token budget fixing them after the fact.

        Defensive: if anything goes wrong, or no tool help can be obtained, we
        return the original drafts unchanged — grounding can only help, never
        make things worse than today.
        """
        try:
            drafts = [p for p in (prescriptions or [])
                      if isinstance(p, dict) and p.get("command")]
            if not drafts:
                return prescriptions
            # Items without a command (non-command directives) are not part of
            # grounding. Keep them so a SUCCESSFUL rewrite (which returns only the
            # grounded command items) doesn't silently drop them from the list.
            non_commands = [p for p in (prescriptions or [])
                            if not (isinstance(p, dict) and p.get("command"))]
            if not hasattr(self, "tools") or not hasattr(
                    self.tools, "get_tool_help_brief"):
                return prescriptions

            # Gather real help for each unique tool referenced in the drafts.
            help_blocks = []
            seen_tools = set()
            for p in drafts:
                cmd = p.get("command", "")
                tool = (self._extract_primary_tool(cmd) or "").lower()
                if not tool or tool in seen_tools:
                    continue
                seen_tools.add(tool)
                brief = ""
                try:
                    brief = self.tools.get_tool_help_brief(tool, cmd)
                except Exception as _he:
                    self.log.debug(f"help-brief failed for {tool}: {_he}")
                # Supplement (advisory only) with any learned-good syntax, but
                # the AI is told the --help is authoritative — a "learned"
                # command may itself have been subtly wrong.
                learned = ""
                if hasattr(self, "syntax_learner"):
                    try:
                        learned = self.syntax_learner.get_syntax_hints(
                            [tool], context=self._syntax_context()) or ""
                    except Exception:
                        learned = ""
                if brief or learned:
                    block = f"### TOOL: {tool}\n"
                    if brief:
                        block += f"-- REAL --help (authoritative ground truth) --\n{brief}\n"
                    if learned:
                        block += f"-- previously-observed syntax (advisory only, may be imperfect) --\n{learned}\n"
                    help_blocks.append(block)

            if not help_blocks:
                # No ground truth available (e.g. tools not installed yet) —
                # don't spend a second AI call; let the normal repair loop cope.
                return prescriptions

            draft_json = json.dumps(
                [{"command": p.get("command"), "reason": p.get("reason", ""),
                  "timeout": p.get("timeout", 120)} for p in drafts],
                default=str)[:4000]

            system = (
                "You are a precise offensive-security CLI synthesizer. You are given "
                "DRAFT commands, a (possibly TRUNCATED) slice of each tool's REAL --help, "
                "and the live EXECUTION ENVIRONMENT. Rewrite EACH command so it is valid: "
                "(1) CORRECT only flags that are CLEARLY wrong (a real syntax error, a "
                "misspelled flag, wrong argument order). The --help excerpt may be cut off, "
                "so DO NOT drop a flag merely because it is absent from the excerpt — only "
                "drop a flag you are confident is invalid for this tool. When unsure, KEEP "
                "the draft's flag. (1b) VALUE-COMPLETENESS: every flag that TAKES A VALUE "
                "(per the --help: it shows an argument/default, e.g. '-t Number of threads') "
                "MUST be followed by that value. A value-expecting flag immediately followed "
                "by ANOTHER flag or the end of the command (e.g. a bare trailing `-t`, or "
                "`-t -ac`) is MALFORMED — the tool will parse the next flag as the value and "
                "abort. Supply a sensible value from the help's default/description, or drop "
                "the flag. (2) Respect the environment — never require privileges "
                "the environment lacks, and never reference an input file not listed as "
                "existing. Keep the same target and intent. Do not add shell pipes, &&, or "
                ";. Output ONLY a JSON array of "
                "[{\"command\": \"...\", \"reason\": \"...\", \"timeout\": <int>}]."
            )
            # Environment reality the rewrite must honour (universal, not per-tool).
            env_constraints = ""
            try:
                cap = self._probe_capabilities()
                if cap and not cap.get("raw_socket"):
                    env_constraints += (
                        "- NOT root and NO raw-socket capability: any privileged/raw "
                        "operation fails. Use the unprivileged equivalent for the chosen "
                        "tool; drop --privileged and privileged-only scan modes.\n")
                env_constraints += self._workspace_state_note()
            except Exception:
                pass
            user = (
                f"PHASE: {phase}\n\n"
                f"### TOOL REFERENCE (real --help)\n" + "\n".join(help_blocks) +
                (f"\n### EXECUTION ENVIRONMENT (must honour)\n{env_constraints}\n"
                 if env_constraints else "") +
                f"\n### DRAFT COMMANDS TO CORRECT\n{draft_json}\n\n"
                "Return the corrected JSON array now."
            )
            from core.robust_parser import extract_json_list
            # Grounding is mechanical syntax correction against real --help — a
            # per-loop call that doesn't need the scarce 70B. Route it to the
            # small fast model to conserve the daily budget. (Command GENERATION
            # stays on the 70B; this only rewrites flags against the help text.)
            resp = self.ai.query(
                system, user, model_id=self._light_model())
            grounded = extract_json_list(resp)
            corrected = [g for g in (grounded or [])
                         if isinstance(g, dict) and g.get("command")]
            if not corrected:
                return prescriptions
            # Preserve any draft keys (e.g. evasion_level) the grounding pass
            # may have dropped, matching by position when counts align.
            if len(corrected) == len(drafts):
                for orig, new in zip(drafts, corrected):
                    for k, v in orig.items():
                        new.setdefault(k, v)
            self.log.info(
                f"[GROUNDING] Rewrote {len(corrected)} command(s) against real "
                f"--help for {len(seen_tools)} tool(s) before execution.")
            return corrected + non_commands
        except Exception as e:
            self.log.debug(f"[GROUNDING] skipped (non-fatal): {e}")
            return prescriptions

    def _build_evidence_context(self) -> str:
        """
        FIX #2.5: Build evidence-driven context with TYPE SAFETY
        Safely extracts findings from StateStore with null/type checking.
        Handles None, [], and "" uniformly.
        """
        if not self.store or not self.session or not hasattr(
                self.session, "engagement_id"):
            return ""

        try:
            evidence = []

            # ── Extract Recon Findings (with type safety) ──
            recon_data = self.store.get_phase_data(
                self.session.engagement_id, "recon")
            if recon_data and isinstance(recon_data, dict):
                # Type-safe port extraction
                ports = recon_data.get("open_ports")
                if ports and isinstance(ports, list):
                    port_strs = [str(p) for p in ports[:10]
                                 if isinstance(p, (int, str))]
                    if port_strs:
                        evidence.append(
                            f"[RECON] Open ports: {
                                ', '.join(port_strs)}")

                # Type-safe tech stack
                tech_stack = recon_data.get("tech_stack")
                if tech_stack and isinstance(tech_stack, list):
                    tech_strs = [str(t) for t in tech_stack[:5]
                                 if isinstance(t, (str, dict))]
                    if tech_strs:
                        evidence.append(
                            f"[RECON] Tech stack: {
                                ', '.join(tech_strs)}")

                # Type-safe WAF detection
                waf_present = recon_data.get("waf_present")
                if waf_present is True:  # Explicit True check
                    waf_fp = recon_data.get("waf_fingerprint")
                    if isinstance(waf_fp, dict):
                        waf_type = waf_fp.get("waf_type", "unknown")
                        evidence.append(f"[RECON] WAF detected: {waf_type}")

                # Type-safe services
                services = recon_data.get("services")
                if services and isinstance(services, list):
                    service_names = []
                    for s in services[:5]:
                        if isinstance(s, dict) and s.get("name"):
                            service_names.append(str(s.get("name")))
                    if service_names:
                        evidence.append(
                            f"[RECON] Services: {
                                ', '.join(service_names)}")

                # Type-safe CVEs
                cves = recon_data.get("identified_cves")
                if cves and isinstance(cves, list) and len(cves) > 0:
                    evidence.append(
                        f"[RECON] CVEs identified: {
                            len(cves)} total")

            # ── Extract Weaponization Findings (with type safety) ──
            weapon_data = self.store.get_phase_data(
                self.session.engagement_id, "weaponization")
            if weapon_data and isinstance(weapon_data, dict):
                exploits = weapon_data.get("exploits_ready")
                if exploits and isinstance(
                        exploits, list) and len(exploits) > 0:
                    evidence.append(
                        f"[WEAPONIZATION] {
                            len(exploits)} exploits prepared")

                payloads = weapon_data.get("payloads")
                if payloads and isinstance(
                        payloads, list) and len(payloads) > 0:
                    evidence.append(
                        f"[WEAPONIZATION] {
                            len(payloads)} payloads available")

            # ── Extract Exploitation Findings (with type safety) ──
            exploit_data = self.store.get_phase_data(
                self.session.engagement_id, "exploitation")
            if exploit_data and isinstance(exploit_data, dict):
                successful = exploit_data.get("successful_exploits")
                if successful and isinstance(
                        successful, list) and len(successful) > 0:
                    evidence.append(
                        f"[EXPLOITATION] Successful exploits: {
                            len(successful)}")
                    for exp in successful[:2]:
                        if isinstance(exp, dict):
                            cve_name = exp.get("cve") or exp.get(
                                "name", "unknown")
                            evidence.append(f"  - {cve_name}")

                shell_access = exploit_data.get("shell_access")
                if shell_access and isinstance(
                        shell_access, dict) and shell_access.get("achieved") is True:
                    shell_type = shell_access.get("shell_type", "unknown")
                    evidence.append(
                        f"[EXPLOITATION] Shell access: {shell_type}")

            # ── FIX 3.4: Sliding Window for Recent Findings ──
            # Cap findings to the last 100 to avoid O(n) performance degradation.
            # Format the last 20 for prompt size optimization.
            all_findings = self.store.get_all_findings(
                self.session.engagement_id) or []
            if all_findings:
                sliding_window = all_findings[-100:]
                unique_recent = []
                seen_recent = set()
                for f in reversed(sliding_window):
                    detail_snippet = f.get("detail", "")[:80]
                    key = (f.get("type"), f.get("target"), detail_snippet)
                    if key not in seen_recent:
                        seen_recent.add(key)
                        unique_recent.append(f)
                    if len(unique_recent) >= 20:
                        break
                unique_recent.reverse()

                if unique_recent:
                    evidence.append(
                        f"[RECENT FINDINGS] (sliding window: last {
                            len(unique_recent)} findings)")
                    for f in unique_recent:
                        evidence.append(
                            f"  - [{f.get('severity',
                                          'info').upper()}] {f.get('type')}: "
                            f"{f.get('target')} -> {f.get('detail')[:100]}"
                        )

            # ── Extract Previous Phase Failures (with type safety) ──
            if hasattr(self, '_recent_failures') and isinstance(
                    self._recent_failures, list):
                recent_fails = self._recent_failures[-5:]
                if recent_fails:
                    fail_strs = [str(f)[:80] for f in recent_fails[:3]]
                    evidence.append(
                        f"[FAILURES] Recent: {
                            '; '.join(fail_strs)}")

            return "\n".join(evidence) if evidence else ""
        except Exception as e:
            self.log.debug(f"Failed to build evidence context: {e}")
            return ""

    def _ai_repair_tool(self, tool: str, command: str,
                        result: ToolResult) -> tuple[bool, str] | None:
        # V6: Enhanced prompt engineering with evidence context (FIX #9)
        err = (result.stderr or result.stdout or "Unknown error")[:300]

        is_timeout = result.status in (ResultStatus.TIMEOUT, "timeout")
        repair_tool = (self._extract_primary_tool(
            command) or tool or "").lower()

        # Build context-aware prompt with environment snapshot + evidence
        env_snapshot = self._get_environment_snapshot()
        env_context = f"--- RUNTIME ENVIRONMENT ---\n{env_snapshot}\n\n" if env_snapshot else ""

        # ── FIX #9: Inject Evidence Context ──
        evidence_context = self._build_evidence_context()
        evidence_section = f"--- PHASE EVIDENCE ---\n{evidence_context}\n\n" if evidence_context else ""

        # ── NEW: Inject Syntax Hints ──
        syntax_hints = ""
        if hasattr(self, "syntax_learner"):
            syntax_hints = self.syntax_learner.get_syntax_hints(
                [repair_tool], context=self._syntax_context())
            if syntax_hints:
                syntax_hints += "\n"

        # ── Check repair history (FIX #5): Learn from repeated failures ──
        cmd_hash = hashlib.sha256(command.encode()).hexdigest()[:16]
        repair_history = self._repair_attempts_history.get(cmd_hash, [])
        history_summary = ""
        if len(repair_history) >= 2:
            # Extract error patterns
            unique_errors = list(set([e[:80] for e in repair_history]))
            history_summary = f"\nThis command has failed {
                len(repair_history)} times with errors:\n"
            history_summary += "\n".join(
                [f"  - {e}" for e in unique_errors[:3]])
            history_summary += "\nTry a fundamentally different approach (different tool, different scope, etc.)"

        help_context = ""
        self.log.info(
            f"[AI REPAIR] Fetching valid flags/help context for '{repair_tool}'...")
        if hasattr(self.tools, "get_tool_valid_flags"):
            valid_flags = self.tools.get_tool_valid_flags(repair_tool, command)
            if valid_flags:
                help_context = f"\n--- VALID FLAGS FOR {
                    repair_tool.upper()} ---\n{
                    ', '.join(
                        sorted(valid_flags))}\n\n"

        if not help_context:
            help_res = self.safe_run_tool(
                repair_tool,
                f"{repair_tool} --help",
                timeout=15,
                silent=True,
                is_repair=True)
            if not help_res or (not getattr(
                    help_res, "stdout", "") and not getattr(help_res, "stderr", "")):
                help_res = self.safe_run_tool(
                    repair_tool, f"{repair_tool} -h", timeout=15, silent=True, is_repair=True)

            help_text = (
                getattr(
                    help_res,
                    "stdout",
                    "") or getattr(
                    help_res,
                    "stderr",
                    "") or "")[
                :2500]
            if help_text:
                help_context = f"\n--- TOOL HELP MENU ---\n{help_text}\n"

        if is_timeout:
            prompt = (
                f"{env_context}{evidence_section}CRITICAL: The previous command TIMED OUT after {
                    result.duration:.0f}s.\n"
                f"Tool: {repair_tool}\nFailed command: {command}\n{history_summary}\n"
                f"{syntax_hints}"
                f"REPAIR RULES:\n"
                f"- Do not return the same command or same breadth of scan.\n"
                f"- Prefer a lighter variant of the same tool first; if that is still risky, pick a different approved tool that can answer the same question.\n"
                f"- If the command is URL-like but the tool expects a host or host:port, normalize it accordingly.\n"
                f"- Preserve scope and target, but reduce concurrency, breadth, or template count.\n"
                f"- Use discovered evidence from previous phases to scope the scan (e.g., only scan open ports, only scan known tech).\n"
                f"- Use available runtime paths and wordlists from the environment snapshot instead of inventing paths.\n\n"
                f"IMPORTANT: Return the single best repaired command string only.\n"
                f"- Drastically reduce the scope (e.g. fewer ports, omit heavy scripts, lower thread counts).\n"
                f"- If using an interactive tool, ensure batch/non-interactive flags are set.\n"
                f"Recent failures: {self._recent_failures[-3:]}\n"
                "Suggest a corrected command string ONLY. No explanation."
            )
        else:
            parser_note = ""
            if hasattr(result, "parser_error") and result.parser_error:
                parser_note = f"\nPARSER REJECTION: {
                    result.parser_error}\nThe tool's output could not be parsed. You MUST change the output format flags (e.g. use JSON instead of plain text).\n"

            prompt = (
                f"{env_context}{evidence_section}Tool: {repair_tool}\nCommand: {command}\nError Output: {err}\n{parser_note}\n{history_summary}\n"
                f"{help_context}"
                f"{syntax_hints}"
                f"REPAIR RULES:\n"
                f"- The tool failed with a non-zero exit code. Read the 'Error Output' closely. It likely contains the tool's help menu or specific syntax errors (e.g., missing mandatory flags, unsupported flags).\n"
                f"- Fix the syntax error directly based on the tool's expected usage.\n"
                f"- Preserve the target, but normalize it to what the tool actually expects.\n"
                f"- Avoid repeating the same exact flags or command shape that just failed.\n"
                f"- Prefer a smaller or more specific variant over a broader one.\n"
                f"- Use discovered evidence from RECON and WEAPONIZATION phases to inform the command.\n"
                f"- Use configured paths and discovered runtime context; do not invent fixed paths.\n"
                f"Recent failures: {self._recent_failures[-3:]}\n"
                "Suggest a corrected command string ONLY. No explanation."
            )

        # Check command dedup: if this exact command already failed recently, skip AI repair
        # EXCEPT if it's a syntax error, in which case we MUST repair it to
        # learn the tool's usage.
        err_lower = err.lower()
        syntax_keywords = [
            "usage:",
            "unrecognized argument",
            "invalid option",
            "no such option",
            "unknown flag",
            "illegal option",
            "invalid choice",
            "flag provided but not defined",
            "unknown command-line parameter",
            "no templates provided"]
        any(k in err_lower for k in syntax_keywords)

        # ── Flawed check removed ──
        # We previously checked if cmd_hash was in _command_history here, but safe_run_tool
        # populates _command_history immediately before running the tool, so this always triggered.
        # Deduping of identical repairs is handled by _repaired_cmds below.
        try:
            suggestion = self.ai.query(
                "You are a pentest CLI repair assistant.", prompt,
                model_id=self._light_model())
            if suggestion and suggestion != command:
                import re
                cleaned = suggestion.strip()
                cleaned = re.sub(r"^```(?:bash|sh|cmd)?\s*", "", cleaned)
                cleaned = re.sub(r"\s*```$", "", cleaned.strip())
                # If the model just echoed the SAME command back wrapped in markdown
                # fences, the raw `suggestion != command` guard above passed but the
                # cleaned repair is identical — re-running it just burns another
                # execution on the same failure (a full tool timeout under Tor).
                if cleaned == command:
                    self.log.debug(
                        "[AI REPAIR REJECTED] Suggestion equals the original command "
                        "after cleaning; abandoning to avoid re-running the same failure.")
                    self._repair_attempts_history[cmd_hash] = repair_history + [err]
                    return None
                # ── Shell-validity guard ──
                # Reject repairs that aren't even parseable as a shell command
                # (e.g. unbalanced quotes). These previously fired anyway and
                # raised shlex "No closing quotation" downstream, burning a
                # whole repair attempt on a command that can never run.
                import shlex as _shlex
                try:
                    _shlex.split(cleaned)
                except ValueError as _ve:
                    self.log.debug(
                        f"[AI REPAIR REJECTED] Suggestion is not shell-parseable "
                        f"({_ve}); discarding instead of executing a broken command.")
                    self._repair_attempts_history[cmd_hash] = repair_history + [err]
                    return None
                # ── Repair-output dedup: skip if this exact repair was already tried ──
                # This closes the loop where two different original failures produce
                # the same AI suggestion. Without this, the repaired cmd fires again
                # because each original has a different input hash.
                repaired_hash = hashlib.sha256(
                    cleaned.encode()).hexdigest()[:16]
                if repaired_hash in self._repaired_cmds:
                    self.log.warning(
                        "[AI REPAIR SKIPPED] Same repair output already tried this engagement. "
                        "Abandoning to prevent identical-repair loop."
                    )
                    # ── FIX #5: Track that this repair strategy failed ──
                    self._repair_attempts_history[cmd_hash] = repair_history + [err]
                    return None
                self._repaired_cmds.add(repaired_hash)
                # ── FIX #5: Mark this as a successful repair strategy ──
                self._successful_repair_strategies[err[:50]] = cleaned[:100]
                return cleaned
        except Exception as _repair_err:
            self.log.debug(
                f"Repair strategy failed for cmd hash {cmd_hash}: {_repair_err}")

        # ── FIX #5: Track all repair attempts for learning ──
        self._repair_attempts_history[cmd_hash] = repair_history + [err]
        return None

    # ═══════════════════════════════════════════════════════════════════
    # TOOL SYNTAX GUIDE
    # ═══════════════════════════════════════════════════════════════════

    def get_tool_syntax_guide(self, phase: str = "recon") -> str:
        """Returns structural rules for autonomous tool execution without hardcoding commands."""
        guide = [
            "### AUTONOMOUS TOOL EXECUTION RULES",
            "You are fully autonomous. Construct tool commands dynamically based on your internal knowledge and the recon findings.",
            "Target Format Rules:",
        ]

        if phase == "recon":
            guide.extend([
                "- HTTP tools (ffuf, gobuster, nuclei, nikto, curl): MUST use FULL URL (e.g. {target} or https://target.com/)",
                "- Raw Socket tools (nmap, masscan, sslscan, dig, subfinder): MUST use BARE IP or HOSTNAME (e.g. {host} or target.com) WITHOUT http://"
            ])
        else:
            guide.extend([
                "- HTTP exploit tools (sqlmap, hydra, curl, wpscan, commix): MUST use FULL URL (e.g. {target} or https://target.com/)",
                "- Raw Socket exploit tools (crackmapexec, msfconsole): MUST use BARE IP or HOSTNAME (e.g. {host} or target.com) WITHOUT http://"
            ])

        guide.extend([
            "",
            "Execution Constraints:",
            "- CRITICAL: DO NOT use bash pipes (`|`), `&&`, or `;` to chain commands. Execute ONE tool per command. The execution engine does not support piped shell commands.",
            "- CRITICAL: Use the `{WORDLIST}` literal string whenever a fuzzing/bruteforce wordlist is required. DO NOT invent paths.",
            "- If you encounter an unrecognized target environment, keep your commands simple.",
            "- If a command fails due to bad syntax, the system will automatically fetch the tool's `--help` manual and loop you back in to repair it."
        ])

        return "\n".join(guide)

    # ═══════════════════════════════════════════════════════════════════
    # V6 REACT LOOP  (new agents can override run() to call super().run())
    # ═══════════════════════════════════════════════════════════════════

    def _build_initial_prompt(self) -> tuple[str, str]:
        """Return (system_prompt, user_prompt). Override in subclass."""
        return ("", "")

    def _parse_ai_response(self, response: str) -> ReActAction | dict | None:
        return None

    def _query_ai(self, system: str, user: str) -> str:
        MAX_PROMPT = 120000
        if len(system) + len(user) > MAX_PROMPT:
            self.log.warning(
                "Prompt oversized; truncating user message safely from middle.")
            allowed_len = MAX_PROMPT - len(system) - 50
            keep = allowed_len // 2
            user = user[:keep] + "\n...[truncated]...\n" + user[-keep:]
        try:
            return self.ai.query(system, user)
        except Exception as e:
            self.log.error(f"AI query failed: {e}")
            raise

    def _compact_ai_context(
            self, text: str, max_chars: int, label: str) -> str:
        """Compress long AI context blocks while preserving high-signal lines."""
        if not text or len(text) <= max_chars:
            return text

        lines = [line.rstrip() for line in text.splitlines()]
        markers = (
            "error", "fail", "timeout", "blocked", "success", "warning",
            "finding", "port", "service", "waf", "cloudflare", "tech_stack",
            "confidence", "probability", "summary", "target", "scope",
            "command", "result", "response", "observation", "recommendation"
        )
        important = [line for line in lines if line and any(
            marker in line.lower() for marker in markers)]
        keep_each_side = max(15, min(50, len(lines) // 10 or 15))
        head = lines[:keep_each_side]
        tail = lines[-keep_each_side:] if len(lines) > keep_each_side else []

        chunks = [
            f"[{label} COMPRESSED: {len(text)} chars -> {max_chars} chars budget]"]
        if important:
            chunks.append("--- IMPORTANT EXCERPTS ---")
            chunks.extend(important[:60])
        if head:
            chunks.append("--- LEADING CONTEXT ---")
            chunks.extend(head)
        if tail:
            chunks.append("--- TRAILING CONTEXT ---")
            chunks.extend(tail)

        compacted = "\n".join(chunks)
        if len(compacted) > max_chars:
            compacted = compacted[: max_chars - 20] + "\n...[truncated]"
        return compacted

    def _build_observation_prompt(self, observation: str) -> str:
        ctx = self._get_target_context_json()
        history = self._format_history()
        syntax_guide = self.get_tool_syntax_guide(phase=self.name)
        return (
            f"### ENGAGEMENT CONTEXT\n{ctx}\n\n"
            f"### PREVIOUS ACTIONS\n{history}\n\n"
            f"{syntax_guide}\n\n"
            f"### LATEST OBSERVATION\n{observation}\n\n"
            f"Based on the observation above, what should you do next?\n"
            f"Return either:\n"
            f"1. A JSON action: {{'capability': '...', 'target_url': '...', 'params': {{'raw_command': '<exact_bash_command>', 'wordlist_type': '...'}}, 'reason': '...'}}\n"
            f"   CRITICAL: If you know the exact flags for a tool, provide them in 'params.raw_command'. If you DO NOT know the exact flags, you MUST omit the 'raw_command' parameter. The system will then run the tool's --help command in the background and return the manual to you so you can construct it perfectly on the next step.\n"
            f"2. A completion marker: {{'status': 'complete', 'summary': '...'}}\n"
        )

    def _execute_v6_action(self, action: ReActAction) -> str:
        cap_name = action.capability
        target_url = action.target_url
        params = action.params or {}

        if cap_name == "return_result_to_manager":
            action.result = ToolResult(
                tool="return_result_to_manager",
                command="return_result_to_manager",
                stdout="SUCCESS: Results returned to manager. Objective accomplished.",
                stderr="",
                exit_code=0,
                duration_seconds=0,
                status=ResultStatus.SUCCESS
            )
            return "SUCCESS: Results returned to manager. Objective accomplished."

        risk_needed = RiskLevel(params.get("risk", "low"))
        destructive_ok = self.session.destructive_mode if hasattr(
            self.session, "destructive_mode") else False
        tool = self.cap_reg.resolve(
            cap_name,
            risk_cap=risk_needed,
            destructive_allowed=destructive_ok)

        if not tool:
            ai_fallback = self.cap_reg.discover_custom_tool(cap_name)
            if ai_fallback:
                tool = ai_fallback
            else:
                return f"ERROR: No tool available for capability '{cap_name}'. Tried AI discovery - also failed."

        cmd = self._build_command_from_capability(tool, target_url, params)

        if cmd == "FETCH_HELP":
            self.log.info(
                f"[HELP REQUEST] AI requested help menu for '{
                    tool.name}'.")
            help_res = self.safe_run_tool(
                tool.name, f"{
                    tool.name} --help", target_url, timeout=30, silent=True)
            help_text = (help_res.stdout or "") + \
                "\n" + (help_res.stderr or "")
            if len(help_text) > 2500:
                help_text = help_text[:2500] + "\n...[truncated]"
            return (
                f"SYSTEM INTERCEPT: You requested the help menu for '{
                    tool.name}'.\n\nHelp Output:\n{help_text}\n\n"
                f"Please review this and issue the exact bash command using the 'params.raw_command' field."
            )

        if not cmd:
            return f"ERROR: Could not build command for {tool.name} on {target_url}"

        # W1.3 — proactive grounding on the v6 ReAct path (parity with recon/
        # exploitation). Rewrite the freshly-built command against the tool's
        # REAL --help before firing, so we don't burn the repair loop fixing a
        # blind-generated flag. Defensive: returns cmd unchanged if no help.
        if not params.get("raw_command"):
            # Only ground AI-built commands; a user/AI-supplied raw_command is
            # taken as-is (the operator already chose the exact invocation).
            try:
                _grounded = self._ground_prescriptions(
                    [{"command": cmd, "reason": cap_name, "timeout": params.get("timeout", 120)}],
                    phase=getattr(self, "name", "exploitation"))
                if _grounded and isinstance(_grounded[0], dict) and _grounded[0].get("command"):
                    _new_cmd = _grounded[0]["command"]
                    if _new_cmd != cmd:
                        self.log.info(
                            f"[GROUNDING v6] Rewrote {tool.name} command against real --help.")
                        cmd = _new_cmd
            except Exception as _g_err:
                self.log.debug(f"v6 grounding failed (non-fatal): {_g_err}")

        if self._waf_ghost:
            cmd = self._waf_ghost.transform(
                cmd, tool.name, level=params.get(
                    "evasion_level", 1))

        if not is_valid_target(target_url):
            return f"ERROR: Invalid target URL '{target_url}' generated by AI."

        try:
            if hasattr(self.scope, "check_target"):
                self.scope.check_target(target_url)
        except Exception as e:
            return f"SCOPE BLOCKED: {e}"

        # Use safe_run_tool for robust repair and WAF handling
        result = self.safe_run_tool(
            tool.name, cmd, target_url,
            timeout=params.get("timeout", tool.timeout_default),
            output_path=params.get("output_path"),
            silent=params.get("silent", False)
        )
        action.result = result

        if not result.success:
            self._track_failure(result)
            return (
                f"FAILED: tool={
                    tool.name} exit={
                    result.exit_code} status={
                    result.status}\n"
                f"STDERR: {result.stderr[:500]}\n"
                f"STDOUT: {result.stdout[:500]}"
            )

        dur = getattr(
            result,
            "duration_seconds",
            getattr(
                result,
                "duration",
                0.0))
        obs = f"SUCCESS: tool={tool.name} duration={dur:.1f}s\n"
        if tool.name not in self._tools_validated:
            self._tools_validated.add(tool.name)
        if result.stdout:
            obs += f"OUTPUT:\n{result.stdout[:2000]}\n"
        if result.stderr:
            obs += f"ERRORS:\n{result.stderr[:500]}\n"
        self._auto_ingest(tool.name, target_url, result.stdout)
        return obs

    def _build_command_from_capability(
            self, tool, target_url: str, params: dict) -> str | None:
        t = tool.name
        p = params

        # ── AI Decision takes precedence ──
        if "raw_command" in p and p["raw_command"].strip():
            cmd = p["raw_command"].strip()
            if "{WORDLIST}" in cmd:
                from config_paths import get_vps_wordlist, VPS_TEMP_DIR
                wl_type = p.get("wordlist_type", "directory")
                vps_wl = get_vps_wordlist(wl_type, wsl_executor=self._ssh)
                wl_path = vps_wl or f"{VPS_TEMP_DIR}/ai_wordlist.txt"
                cmd = cmd.replace("{WORDLIST}", wl_path)
            return cmd

        # If no raw_command provided, AI is requesting help
        self.log.info(
            f"No raw_command provided by AI for tool '{t}'. Fetching help...")
        return "FETCH_HELP"

    def _auto_ingest(self, tool_name: str, target_url: str,
                     stdout: str) -> None:
        ctx = self.session.target_context if hasattr(
            self.session, "target_context") else None
        if not ctx:
            return
        text = stdout.lower()
        for match in re.findall(
                r'([a-z0-9][-a-z0-9]*\.[a-z0-9][-a-z0-9]*\.[a-z]{2,})', stdout):
            if match != ctx.host and ctx.host in match:
                ctx.add_subdomain(match)
                self.add_finding(
                    "subdomain",
                    match,
                    f"Discovered via {tool_name}",
                    "info")
        for path_match in re.findall(
                r'(\/[-a-zA-Z0-9_./]+\.(php|asp|aspx|jsp|json|xml|yaml|env))', stdout):
            ctx.add_endpoint(path_match[0])
        for auth_path in re.findall(
                r'(/(?:login|signin|auth|admin|wp-login|api/auth)[^\s\"\'<>]*)', stdout, re.IGNORECASE):
            ctx.add_auth_endpoint(auth_path.rstrip("/"))
            self.add_finding(
                "auth_endpoint", f"{
                    ctx.base_url}{
                    auth_path.rstrip('/')}", f"Detected via {tool_name}", "medium")
        tech_map = {
            "php": "PHP", "wordpress": "WordPress", "drupal": "Drupal", "joomla": "Joomla",
            "laravel": "Laravel", "django": "Django", "flask": "Flask", "rails": "Ruby on Rails",
            "express": "Express.js", "next.js": "Next.js", "react": "React", "vue": "Vue.js", "angular": "Angular",
            "nginx": "Nginx", "apache": "Apache", "iis": "IIS",
            "cloudflare": "Cloudflare CDN", "fastly": "Fastly CDN", "akamai": "Akamai CDN",
        }
        for keyword, tech_name in tech_map.items():
            if keyword in text:
                ctx.add_tech(tech_name)
                if keyword in ("cloudflare", "fastly", "akamai"):
                    ctx.is_cdn = True
                    ctx.cdn_provider = tech_name
        if any(k in text for k in ("cloudflare", "akamai",
               "incapsula", "sucuri", "fortinet", "barracuda")):
            ctx.waf_detected = True
            for waf in ("cloudflare", "akamai", "incapsula",
                        "sucuri", "fortinet", "barracuda"):
                if waf in text:
                    ctx.waf_type = waf.title()
                    break
        for port_match in re.findall(r'(\d+)/(tcp|udp)\s+open', stdout):
            ctx.add_endpoint(f":{int(port_match[0])}")

    def _get_target_context_json(self) -> str:
        ctx = self.session.target_context if hasattr(
            self.session, "target_context") else None
        if ctx:
            return ctx.to_json(indent=0)
        return "{}"

    def _format_history(self) -> str:
        lines = []
        for h in self._react_history[-5:]:
            if "action" in h:
                a = h["action"]
                lines.append(
                    f"- Action: {a.get('capability')} on {a.get('target_url')} -> {a.get('result_summary', '?')}")
            elif "observation" in h:
                obs = str(h.get("observation", ""))[:200]
                lines.append(f"  Observation: {obs}...")
        return "\n".join(lines) if lines else "No prior actions."

    def _compile_phase_result(self) -> dict:
        res = {
            "phase": self.name,
            "findings_count": len(self._findings),
            "iterations": len(self._react_history),
            "findings": self._findings,
            "target_context": self.session.target_context.to_dict() if hasattr(self.session, "target_context") else {},
        }
        if hasattr(self, "result_returned"):
            res["returned_result"] = self.result_returned
        return res

    def run_react(self) -> dict:
        """V6 ReAct loop. Subclasses should call this if they want AI-driven exploration."""
        self.store.set_phase_status(
            self.session.engagement_id, self.name, "running")
        iteration = 0
        consecutive_failures = 0
        system_prompt, user_prompt = self._build_initial_prompt()

        # ── SOFT DEADLINE INIT ──
        import time
        import json
        from pathlib import Path
        start_time = time.monotonic()
        try:
            rules_path = Path(__file__).parent.parent / \
                "rules" / "orchestration.json"
            with open(rules_path, "r") as f:
                rules = json.load(f)["phase_orchestration"]
            mode = getattr(self.session, "mode", "pentest")
            mode_rules = rules.get(
                f"{mode}_mode", rules.get(
                    "pentest_mode", {}))
            phase_timeout = mode_rules.get(
                "phase_timeouts", {}).get(
                self.name, 1800)
        except Exception as e:
            import logging as __logging_tmp
            __logging_tmp.getLogger(__name__).debug(f"Silenced exception: {e}")
            phase_timeout = 1800
        soft_deadline = start_time + phase_timeout - 120  # 120s buffer for graceful exit

        while iteration < self._max_react_iterations:
            if time.monotonic() > soft_deadline:
                self.log.warning(
                    f"[{self.name}] Soft deadline reached (Timeout: {phase_timeout}s). Forcing graceful completion.")
                self._react_history.append({"iteration": iteration, "type": "completion", "data": {
                                           "status": "complete", "reason": "soft_timeout"}})
                break

            iteration += 1
            self.log.info(
                f"[{self.name}] ReAct iteration {iteration}/{self._max_react_iterations}")
            ai_response = self._query_ai(system_prompt, user_prompt)
            if not ai_response:
                break
            parsed = self._parse_ai_response(ai_response)
            if isinstance(parsed, dict) and parsed.get(
                    "status") in ("complete", "done", "finished"):
                self._react_history.append(
                    {"iteration": iteration, "type": "completion", "data": parsed})
                break
            if isinstance(parsed, ReActAction):
                if not self._is_action_allowed(parsed):
                    obs = f"BLOCKED: Capability '{
                        parsed.capability}' not permitted."
                    self._react_history.append(
                        {"iteration": iteration, "action": parsed.to_dict(), "observation": obs})
                    user_prompt = self._build_observation_prompt(obs)
                    continue

                self._react_history.append(
                    {"iteration": iteration, "action": parsed.to_dict()})

                # Check for return_result_to_manager
                if parsed.capability == "return_result_to_manager":
                    self.log.info(
                        f"[{self.name}] Specialist returned results to manager: {parsed.params}")
                    self.result_returned = parsed.params.get(
                        "result", parsed.params)
                    break

                observation = self._execute_v6_action(parsed)
                # Only count as a consecutive failure if the tool result itself
                # explicitly failed
                if hasattr(
                        parsed, "result") and parsed.result and not parsed.result.success:
                    consecutive_failures += 1
                    # Invoking the StrategicMentor if failure chain threshold
                    # is breached (consecutive_failures >= 3)
                    if consecutive_failures >= 3:
                        self.log.warning(
                            f"[{self.name}] Failure Chain breached ({consecutive_failures} consecutive failures). Invoking Strategic Mentor...")
                        transcript_str = json.dumps(
                            self._react_history[-5:], indent=2, default=str)
                        objective = getattr(
                            self, "subtask_context", self.session.target)
                        guardian_logs = "\n".join(self._recent_failures[-5:])

                        try:
                            from agents.mentor_agent import StrategicMentor
                            mentor = StrategicMentor(
                                name="strategic_mentor",
                                session=self.session,
                                state_store=self.store,
                                tool_manager=self.tools,
                                ai_backend=self.ai,
                                message_bus=self.bus,
                                scope_enforcer=self.scope,
                                validation=self.validation,
                                capability_registry=self.cap_reg,
                                orchestrator=self.orchestrator
                            )

                            mentor_response = mentor.advise(
                                transcript=transcript_str,
                                objective=objective,
                                guardian_logs=guardian_logs
                            )

                            self.log.info(
                                f"[{self.name}] Strategic Mentor Pivot Advice:\n{mentor_response}")

                            observation = (
                                f"[STRATEGIC MENTOR INTERVENTION]\n"
                                f"Assessment: {
                                    mentor_response.get(
                                        'assessment', 'N/A')}\n"
                                f"Flaws: {
                                    mentor_response.get(
                                        'flaws', 'N/A')}\n"
                                f"Pivot Recommendation: {
                                    mentor_response.get(
                                        'pivot_recommendation',
                                        'Try another vector.')}\n\n"
                                f"Instruction: You MUST pivot your strategy now. Abandon your current failed approach and follow the pivot recommendation."
                            )
                            consecutive_failures = 0
                        except Exception as mentor_err:
                            self.log.error(
                                f"Failed to invoke Strategic Mentor: {mentor_err}")
                            if consecutive_failures >= self._max_repeat_failures:
                                self.log.warning(
                                    f"[{self.name}] Repeated failures detected ({consecutive_failures}). Invoking Smart Error Recovery...")
                                decision_prompt = (
                                    f"You have failed {consecutive_failures} times consecutively.\n"
                                    f"Last observation: {observation}\n\n"
                                    "Choose your next action by replying EXACTLY with one of the following tags:\n"
                                    "- [SKIP] : Abandon this specific vector and move to a completely different tool or target.\n"
                                    "- [ABORT] : The entire engagement or phase is broken, stop execution immediately.\n"
                                    "- [REPAIR] : I know exactly how to fix the syntax and want one last try."
                                )
                                decision = self.ai.query(
                                    "You are a red team error recovery engine.", decision_prompt).strip()
                                self.log.info(
                                    f"[{self.name}] Smart Error Recovery decision: {decision}")

                                if "[ABORT]" in decision:
                                    self.log.error(
                                        f"[{self.name}] AI decided to ABORT phase due to unrecoverable errors.")
                                    break
                                elif "[SKIP]" in decision:
                                    observation = "[SYSTEM OVERRIDE] Previous strategy abandoned. Pick a completely new tool or target."
                                    consecutive_failures = 0
                                else:
                                    observation += "\n\n[SYSTEM HINT] This is your final attempt to repair. If it fails, move on."
                else:
                    consecutive_failures = 0
                self._react_history[-1]["observation"] = observation
                user_prompt = self._build_observation_prompt(observation)
                continue
            break

        result = self._compile_phase_result()
        self.store.set_phase_status(
            self.session.engagement_id,
            self.name,
            "complete",
            json.dumps(
                result,
                default=str)[
                :500])
        self.flush_dedup_stats()
        return result

    def _is_action_allowed(self, action: ReActAction) -> bool:
        # Check if specialist constraint is active
        if hasattr(self, "specialist_role") and self.specialist_role:
            role = self.specialist_role
            if role == "recon":
                # Only allowed to run recon, scanning, or utility tools
                if action.capability in (
                        "sql_injection_test", "credential_brute", "react_payload", "python_payload"):
                    return False
                tool = self.cap_reg.resolve(
                    action.capability, destructive_allowed=False)
                if tool and tool.risk in (
                        RiskLevel.HIGH, RiskLevel.DESTRUCTIVE):
                    return False
            elif role == "exploit":
                # Allowed to run exploit, post-exploit, scanning, web
                pass
            elif role == "research":
                # Only allow http_probe, web_search, read_file/cat
                if action.capability not in (
                        "http_probe", "http_download", "header_extract", "return_result_to_manager"):
                    raw_cmd = (
                        action.params or {}).get(
                        "raw_command",
                        "").strip()
                    if raw_cmd:
                        first_word = raw_cmd.split(
                        )[0] if raw_cmd.split() else ""
                        if first_word not in (
                                "cat", "grep", "head", "tail", "ls", "find", "file", "echo"):
                            return False
                    else:
                        return False

        roe = self.session.rules_of_engagement if hasattr(
            self.session, "rules_of_engagement") else {}
        if action.capability in (
                "sql_injection_test", "credential_brute") and not roe.get("allow_exploitation"):
            return False
        tool = self.cap_reg.resolve(
            action.capability, destructive_allowed=True)
        if tool and tool.risk == RiskLevel.DESTRUCTIVE:
            roe = self.session.rules_of_engagement if hasattr(
                self.session, "rules_of_engagement") else {}
            if not (hasattr(self.session, "destructive_mode")
                    and self.session.destructive_mode) and not roe.get("allow_destructive"):
                return False
        return True

    # ═══════════════════════════════════════════════════════════════════
    # REQUIRED BY ORCHESTRATOR - backward-compat default
    # ═══════════════════════════════════════════════════════════════════
    def _probe_capabilities(self) -> dict:
        """Live-probe the execution environment's privilege level and raw-socket
        capability ONCE (cached). Universal facts the AI reasons over so it never
        generates a command that needs privileges the environment lacks."""
        cached = getattr(self, "_capabilities_cache", None)
        if cached is not None:
            return cached
        caps = {}
        if self._ssh:
            try:
                # uid + GROUND-TRUTH raw-socket test: actually try to open a
                # SOCK_RAW (capsh/getcap lie under WSL — they can report
                # cap_net_raw present while the kernel still refuses the open).
                # Fall back to "root ⇒ available" only if python3 is missing.
                ec, out, _ = self._ssh.execute(
                    "id -u; "
                    "if command -v python3 >/dev/null 2>&1; then "
                    "python3 -c 'import socket; "
                    "socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP); "
                    "print(\"RAW:yes\")' 2>/dev/null || echo RAW:no; "
                    "elif [ \"$(id -u)\" = 0 ]; then echo RAW:yes; else echo RAW:no; fi",
                    timeout=TOOL_VERIFY_TIMEOUT)
                rows = [r.strip() for r in (out or "").splitlines() if r.strip()]
                if rows:
                    try:
                        uid = int(rows[0])
                    except ValueError:
                        uid = None
                    caps["uid"] = uid
                    caps["root"] = (uid == 0)
                    caps["raw_socket"] = any("RAW:yes" in r for r in rows)
            except Exception as e:
                self.log.debug(f"capability probe failed: {e}")
        self._capabilities_cache = caps
        return caps

    def _workspace_state_note(self) -> str:
        """List the files that ACTUALLY exist in the workspace right now, so the
        AI only ever references real input files (universal cure for the
        hallucinated `-l <made-up-file>` failure). Probed live every call."""
        if not self._ssh:
            return ""
        try:
            import config_paths
            dirs = [config_paths.WSL_TEMP_DIR,
                    f"{config_paths.WSL_TEMP_DIR}/results"]
            # A quoted leading '~' does not expand in the shell; runtime values
            # are normally already absolute, but stay robust if they are not.
            def _q(d):
                return d if d.startswith("~") else f'"{d}"'
            cmd = "; ".join(
                f'find {_q(d)} -maxdepth 1 -type f -printf "%p (%s bytes)\\n" 2>/dev/null'
                for d in dirs)
            ec, out, _ = self._ssh.execute(cmd, timeout=TOOL_VERIFY_TIMEOUT)
            files = [r.strip() for r in (out or "").splitlines() if r.strip()]
            note = "\n=== WORKSPACE FILES (exist right now) ===\n"
            if files:
                note += "\n".join(f"  {f}" for f in files[:25])
            else:
                note += "  (none yet)"
            note += (
                "\nRULE: A tool's output is captured to findings, NOT auto-saved "
                "to a file. Only pass an input file that appears in the list above, "
                "and only for its correct purpose: the listed host/URL files (e.g. "
                "recon_hosts.txt) are HOST LISTS — valid for -l/-iL/-u/--input-file, "
                "but NOT for a fuzzing -w wordlist. For -w output the literal token "
                "{WORDLIST} instead (the engine supplies a real dictionary). To "
                "chain results, write the file yourself with the tool's own output "
                "flag (-o/-oN) first. Never invent a filename.\n")
            return note
        except Exception as e:
            self.log.debug(f"workspace-state note failed: {e}")
            return ""

    def _get_environment_snapshot(
            self, force_refresh: bool = False, phase: str = None) -> str:
        """
        VPS-AWARE environment snapshot.

        FIX A — Cached snapshot:
        The snapshot content (paths, tool list, banned tools, failures) is
        static between loops. Rebuilding it from scratch on every self.think()
        call burns ~500 tokens for nothing. We cache it and only invalidate
        when the ban list or recent-failures list actually changes.
        """
        if not phase and hasattr(self, "name"):
            phase = self.name.lower()

        # ── FIX A: dirty-flag cache ───────────────────────────────────────
        current_ban_count = len(getattr(self, '_tool_ban_list', set()))
        current_failure_count = len(getattr(self, '_recent_failures', []))
        cache = getattr(self, '_env_snapshot_cache', None)

        if (not force_refresh
                and cache is not None
                and cache.get('ban_count') == current_ban_count
                and cache.get('failure_count') == current_failure_count
                and cache.get('phase') == phase):
            # Workspace file state changes between loops, so it is appended
            # live (outside the cache) rather than baked into the snapshot.
            return cache['snapshot'] + self._workspace_state_note()

        try:
            lines = []

            # ── 1. Execution Architecture ─────────────────────────────────
            lines.append("=== EXECUTION ARCHITECTURE ===")
            lines.append("LOCAL  (Python/orchestrator): Windows")
            lines.append(
                "WSL    (Tool execution)     : Linux Subsystem (Ubuntu) - ALL tool commands run inside WSL.")
            lines.append(
                "RULE: Every command you generate is executed in the local WSL (Linux) environment, not native Windows.")

            # ── 1a. Effective privileges & capabilities (live-probed) ─────
            # Stated as a GENERAL constraint, not a per-tool rule: the AI maps
            # "no raw sockets / not root" to the right unprivileged technique
            # for whatever tool it picks (e.g. a TCP-connect scan instead of a
            # SYN scan), so we never hardcode tool flags.
            cap = self._probe_capabilities()
            if cap:
                lines.append("\n=== EXECUTION PRIVILEGES & CAPABILITIES (live) ===")
                lines.append(
                    f"  Effective user : {'root' if cap.get('root') else 'NON-root (uid=' + str(cap.get('uid', '?')) + ')'}")
                lines.append(
                    f"  Raw packet sockets (CAP_NET_RAW): {'available' if cap.get('raw_socket') else 'UNAVAILABLE'}")
                if not cap.get("raw_socket"):
                    lines.append(
                        "  CONSTRAINT: Operations needing raw packets or root WILL fail "
                        "('Operation not permitted' / 'requires root'). Choose an "
                        "UNPRIVILEGED equivalent for whatever tool you pick (connect-based "
                        "scans, userland modes). Do NOT request privileged/raw scan types "
                        "or --privileged.")

            # ── 1b. Dynamic Performance / Stealth Mandate ─────────────────
            stealth_enabled = False
            if hasattr(self, "session") and hasattr(self.session, "stealth_config"):
                stealth_enabled = any(self.session.stealth_config.values())
            
            if stealth_enabled:
                lines.append("\n=== STEALTH MANDATE ===")
                lines.append(
                    "CRITICAL: You are an autonomous offensive AI operating under a strict INHERENT STEALTH mandate.")
                lines.append(
                    "- Assume targets are heavily monitored (WAF, IPS, Tripwires).")
                lines.append(
                    "- NEVER run noisy scans (e.g., nmap -T4, aggressive ffuf) without explicit permission.")
                lines.append(
                    "- Prioritize rate-limiting, jitter, and evasion profiles automatically.")
                lines.append(
                    "- Minimize fingerprinting by spoofing User-Agents and rotating IPs if configured.")
            else:
                lines.append("\n=== PERFORMANCE MANDATE ===")
                lines.append(
                    "CRITICAL: You are operating in UNRESTRICTED PERFORMANCE mode. Stealth is disabled.")
                lines.append(
                    "- Maximize scan speeds and thread counts (e.g., nmap -T4, high concurrency ffuf/nuclei).")
                lines.append(
                    "- Do NOT use rate-limiting, delays, or slow timing flags.")
                lines.append(
                    "- Complete tasks as quickly as possible.")

            # ── 1c. Execution Watchdog (how commands are bounded) ─────────
            # Generic grounding, not per-tool: tell the AI how the executor
            # decides a command is hung, so it stops fearing long quiet scans
            # (the watchdog now spares working ones) yet still scopes work for
            # speed. The AI maps "emit progress / scope" to whatever tool it
            # picks — we never hardcode flags here.
            lines.append("\n=== EXECUTION WATCHDOG (how your commands are run) ===")
            lines.append(
                "- A command is killed early ONLY if it emits NO output AND the "
                "box shows no CPU/network activity for a long window; otherwise it "
                "runs to its hard timeout. A scan that keeps the network busy is "
                "NOT killed for being quiet — you may run legitimate long scans.")
            lines.append(
                "- Targets behind a CDN/WAF (Cloudflare, Vercel, etc.) usually "
                "FILTER most ports and tarpit requests, so an unscoped full-range "
                "scan or fuzz can burn many minutes for nothing. Prefer SCOPED, "
                "progress-emitting commands: probe the ports/paths most likely to "
                "matter first and enable the tool's own progress/verbose output so "
                "long runs keep streaming.")

            # ── 2. Target Context ─────────────────────────────────────────
            if hasattr(self, "session") and getattr(
                    self.session, "target", None):
                try:
                    tc = TargetContext.from_input(self.session.target)
                    lines.append("\n=== TARGET ===")
                    lines.append(f"Base URL  : {tc.base_url}")
                    lines.append(f"Host/IP   : {tc.netloc}")
                    lines.append(f"Full URL  : {tc.full_url}")
                    lines.append(
                        f"Tech Stack: {
                            ', '.join(
                                tc.tech_stack) or 'unknown'}")
                    if tc.waf_detected:
                        lines.append(
                            f"WAF       : {
                                tc.waf_type or 'detected'} - use evasion flags")
                except Exception as _tc_err:
                    self.log.debug(f"TargetContext error: {_tc_err}")

            # ── 3. WSL paths (what matters for command generation) ─
            lines.append(
                "\n=== WSL ENVIRONMENT PATHS (use these in all commands) ===")
            lines.append(f"  Tool base      : {config_paths.WSL_TOOL_PATH}")
            lines.append(f"  Temp/work dir  : {config_paths.WSL_TEMP_DIR}/")
            lines.append(
                f"  Buffer logs    : {
                    config_paths.WSL_TEMP_DIR}/buffers/")
            lines.append(f"  Results output : {config_paths.WSL_RESULTS_DIR}/")

            # ── 4. Verified WSL Wordlists (live-checked) ──────────────────
            lines.append("\n=== WSL WORDLISTS (verified in WSL) ===")
            wl_found = False
            for wl_type in ("directory", "common", "passwords", "subdomains"):
                vps_wl = config_paths.get_vps_wordlist(
                    wl_type, wsl_executor=self._ssh)
                if vps_wl:
                    lines.append(f"  {wl_type:<12}: {vps_wl}")
                    wl_found = True
            if not wl_found:
                lines.append("  No standard wordlist is installed in this WSL.")
            # Always state the wordlist contract (applies whether or not a
            # standard list exists), because the #1 fuzzing failure was the AI
            # pointing -w at recon_hosts.txt — a list of discovered HOSTS — which
            # only yields garbage 404s.
            lines.append(
                "  WORDLIST RULE: For ANY fuzzing -w flag, output the literal "
                "token {WORDLIST} as the wordlist path. The engine resolves it to "
                "a real, tech-stack-specific micro-wordlist (provisioning one if "
                "none is installed). NEVER use a discovered-hosts or results file "
                "(e.g. recon_hosts.txt) as a -w wordlist — those are inputs for "
                "-l/-iL/-u, not fuzzing dictionaries.")

            # ── 5. Tool Availability (live WSL check for critical tools) ──
            lines.append("\n=== TOOL AVAILABILITY (local WSL) ===")

            from tools.tool_registry import TOOL_REGISTRY
            phase_allowed_tools = []
            for t_name, t_info in TOOL_REGISTRY.items():
                cat = t_info.get("category", "")
                if not phase:
                    phase_allowed_tools.append(t_name)
                elif phase == "recon":
                    if cat in ["recon", "scanning", "web"]:
                        phase_allowed_tools.append(t_name)
                elif phase == "exploitation":
                    if cat in ["exploitation", "vulnerability",
                               "web", "post_exploitation"]:
                        phase_allowed_tools.append(t_name)
                elif phase == "weaponization":
                    if cat in ["weaponization", "vulnerability"]:
                        phase_allowed_tools.append(t_name)
                else:
                    phase_allowed_tools.append(t_name)

            critical_tools = [
                "nmap", "gobuster", "ffuf", "nuclei", "subfinder",
                "nikto", "sqlmap", "hydra", "wfuzz", "amass",
                "whatweb", "wafw00f", "dirsearch", "httpx", "feroxbuster",
            ]
            critical_tools = [
                t for t in critical_tools if t in phase_allowed_tools]
            if self._ssh:
                available_tools = []
                missing_tools = []
                try:
                    check_cmds = " && ".join(
                        f"(which {t} > /dev/null 2>&1 && echo 'FOUND:{t}' || echo 'MISSING:{t}')"
                        for t in critical_tools
                    )
                    ec, out, _ = self._ssh.execute(
                        check_cmds, timeout=TOOL_VERIFY_TIMEOUT)
                    for line in out.splitlines():
                        if line.startswith("FOUND:"):
                            available_tools.append(line[6:].strip())
                        elif line.startswith("MISSING:"):
                            missing_tools.append(line[8:].strip())
                except Exception as e:
                    import logging as __logging_tmp
                    __logging_tmp.getLogger(__name__).debug(
                        f"Silenced exception: {e}")
                    available_tools = []
                    missing_tools = critical_tools

                if available_tools:
                    lines.append(f"  Available : {', '.join(available_tools)}")
                if missing_tools:
                    lines.append(f"  MISSING   : {', '.join(missing_tools)}")
                    lines.append(
                        "  RULE: Do NOT use missing tools - pick an available alternative.")
            else:
                lines.append(
                    "  (WSL not connected - cannot verify tool availability)")

            # ── 6. Tool Effectiveness (from tracker) ──────────────────────
            if hasattr(self, "tool_tracker"):
                try:
                    summary = self.tool_tracker.summarize_effectiveness()
                    if summary:
                        lines.append(
                            "\n=== TOOL EFFECTIVENESS (this session) ===")
                        # summary is {tool: {target_type: {success_count,
                        # total_runs, ...}}} — aggregate to one rate per tool.
                        for tool, per_target in list(summary.items())[:8]:
                            if not isinstance(per_target, dict):
                                continue
                            succ = sum(s.get("success_count", 0)
                                       for s in per_target.values()
                                       if isinstance(s, dict))
                            runs = sum(s.get("total_runs", 0)
                                       for s in per_target.values()
                                       if isinstance(s, dict))
                            if runs <= 0:
                                continue
                            score = succ / runs
                            bar = "[+]" if score >= 0.5 else "[x]"
                            lines.append(f"  {bar} {tool:<16}: {score:.0%}")
                except Exception as _eff_err:
                    self.log.debug(
                        f"Tool effectiveness summary unavailable: {_eff_err}")

            # ── 7. Known Failure Patterns (inject from history) ───────────
            if self._recent_failures:
                lines.append(
                    "\n=== KNOWN FAILURE PATTERNS (do NOT repeat these) ===")
                for snippet in self._recent_failures[-8:]:
                    lines.append(f"  [!] {snippet}")

            # ── 8. Banned tools for this session ─────────────────────────
            if self._tool_ban_list:
                banned_str = ", ".join(sorted(self._tool_ban_list)[:10])
                lines.append("\n=== SESSION-BANNED TOOLS ===")
                lines.append(f"  DO NOT USE: {banned_str}")

            snapshot = "\n".join(lines)

            # ── FIX A: Store in cache with dirty-flag keys ─────────────────
            self._env_snapshot_cache = {
                'snapshot': snapshot,
                'ban_count': current_ban_count,
                'failure_count': current_failure_count,
                'phase': phase,
            }
            return snapshot + self._workspace_state_note()

        except Exception as e:
            self.log.debug(f"Environment snapshot error: {e}")
            return (
                "=== EXECUTION ARCHITECTURE ===\n"
                "LOCAL: Windows (Python). REMOTE: Linux VPS (all tool commands).\n"
                "RULE: Generate commands for the Linux VPS only - never use Windows paths."
            )

    def _situation_summary(self):
        """(tech_stack, discovered) used to ground strategic advice. Cheap/local —
        no AI call.

        Reads the PERSISTENT store first (authoritative, cross-phase): the
        per-instance ``self._findings`` only holds the findings THIS agent added,
        so during exploitation it would miss everything recon discovered (e.g.
        the tech stack) and the strategic brain would reason with a blank target
        model. The store carries all phases' findings."""
        tech = set()
        discovered = {}
        findings = []
        try:
            store = getattr(self, "store", None)
            eid = getattr(getattr(self, "session", None), "engagement_id", None)
            if store and eid:
                findings = store.get_all_findings(eid) or []
        except Exception as _e:
            self.log.debug(f"situation summary store read failed: {_e}")
        if not findings:
            findings = getattr(self, "_findings", []) or []
        try:
            by_type = {}
            for f in findings:
                if not isinstance(f, dict):
                    continue
                ft = (f.get("type") or "").lower()
                if ft:
                    by_type[ft] = by_type.get(ft, 0) + 1
                if ft == "tech_stack" and f.get("detail"):
                    # Findings are stored like "CMS: WordPress" — take the part
                    # AFTER any "label:" prefix so we get the tech name, not the
                    # label (".split()[0]" wrongly yielded "cms:").
                    _d = str(f.get("detail")).split(":")[-1].strip()
                    if _d:
                        tech.add(_d.split()[0].lower())
            discovered = {k: v for k, v in by_type.items() if v}
        except Exception as _e:
            self.log.debug(f"situation summary findings failed: {_e}")
        if not tech:
            try:
                tc = TargetContext.from_input(self.session.target)
                for t in (getattr(tc, "tech_stack", None) or []):
                    tech.add(str(t).lower())
            except Exception as _e:
                self.log.debug(f"situation summary target-context failed: {_e}")
        return sorted(tech), discovered

    def _strategic_advice_note(self, phase: str) -> str:
        """ACTIVE strategic advice injected as EVIDENCE into the AI's decision
        context — the previously-dormant brain, now wired in.

        It never decides FOR the AI; it hands the main reasoning loop the
        StrategicAdvisor's AI-generated, history-grounded tool recommendations,
        stop-signs and pivot suggestions (so the agent abandons futile
        approaches the way a human operator would), plus the SelfAwarenessModule's
        'what to collect next'. The main loop's AI remains the decider — this is
        the user's "give the AI better evidence, don't branch in code" principle.

        The advisor's AI call is cached per (phase, tech-stack); it only fires
        again when the situation materially changes, so this adds at most one
        extra AI round-trip per situational shift, not one per loop."""
        advisor = getattr(self, "advisor", None)
        awareness = getattr(self, "awareness", None)
        if not advisor and not awareness:
            return ""
        try:
            tech_stack, discovered = self._situation_summary()
            target = str(getattr(getattr(self, "session", None), "target", "") or "")
            cache_key = (phase, tuple(tech_stack))
            cache = getattr(self, "_advice_note_cache", None)
            if not cache or cache.get("key") != cache_key:
                lines = []
                if advisor:
                    try:
                        advice = advisor.advise_tool_selection(
                            phase, target, tech_stack, discovered, full=True) or {}
                        recs = [r for r in (advice.get("tool_recommendations") or [])
                                if isinstance(r, dict)][:5]
                        if recs:
                            lines.append(
                                "RECOMMENDED next (history-grounded; you still decide):")
                            for r in recs:
                                av = r.get("avoid_because")
                                tag = f" — AVOID: {av}" if av else ""
                                try:
                                    pct = int(float(r.get("expected_success_rate", 0)) * 100)
                                except (TypeError, ValueError):
                                    pct = 0
                                lines.append(
                                    f"  - {r.get('tool', '?')} (p{r.get('priority', '?')}, "
                                    f"~{pct}%): {r.get('reasoning', '')}{tag}")
                        for w in (advice.get("warning_signs") or [])[:4]:
                            lines.append(f"  STOP-SIGN: {w}")
                        for p in (advice.get("strategic_pivot_suggestions") or [])[:3]:
                            if isinstance(p, dict):
                                lines.append(
                                    f"  PIVOT: {p.get('from', '?')} -> {p.get('to', '?')} "
                                    f"({p.get('why', '')})")
                        gap = advice.get("knowledge_gap")
                        if gap:
                            lines.append(f"  KNOWLEDGE-GAP: {gap}")
                    except Exception as _e:
                        self.log.debug(f"advise_tool_selection failed: {_e}")
                    # Recon only: surface the operator's "found X → skip to Y"
                    # early-exit conditions so the agent stops over-enumerating.
                    if phase == "recon":
                        try:
                            order = advisor.advise_discovery_order(
                                target, tech_stack, phase, full=True) or {}
                            for ec in (order.get("early_exit_conditions") or [])[:3]:
                                lines.append(f"  EARLY-EXIT: {ec}")
                        except Exception as _e:
                            self.log.debug(f"advise_discovery_order failed: {_e}")
                self._advice_note_cache = {"key": cache_key, "note": "\n".join(lines)}
                cache = self._advice_note_cache
            note = cache.get("note", "")
            # Cheap/local awareness signal — refresh every call (no AI).
            if awareness:
                try:
                    for s in (awareness.suggest_data_collection() or [])[:3]:
                        if isinstance(s, dict):
                            note += (f"\n  COLLECT-NEXT: {s.get('description', '')} "
                                     f"({s.get('why', '')})")
                except Exception as _e:
                    self.log.debug(f"suggest_data_collection failed: {_e}")
            # Cheap/local prediction-calibration signal (no AI) — how well past
            # confidence matched reality, so the AI corrects its own over/under-
            # confidence. Closes the ReasoningEngine calibration loop (the writer
            # is in exploitation's hypothesis verdicts). Empty until enough data.
            reasoning = getattr(self, "reasoning", None)
            if reasoning and hasattr(reasoning, "calibration_summary_for_prompt"):
                try:
                    cal = reasoning.calibration_summary_for_prompt()
                    if cal:
                        note += "\n" + cal
                except Exception as _ce:
                    self.log.debug(f"calibration summary failed: {_ce}")
            if not note.strip():
                return ""
            return ("\n--- STRATEGIC BRAIN (advice & stop-signs; the AI still decides) ---\n"
                    + note + "\n")
        except Exception as e:
            self.log.debug(f"strategic advice note failed: {e}")
            return ""

    def _validate_assumptions(self):
        """Close the assumption loop. The agent REGISTERS tactical assumptions
        ('host is honeypot-protected', 'Try SQLi on /login') but never checked
        whether they held — so the self-awareness confidence model never reflected
        reality and the agent never learned from a wrong assumption (a write-only
        gap). Here the AI judges each still-open assumption against the evidence
        gathered so far (SUPPORT / REFUTE / UNKNOWN) and records the verdict; a
        REFUTED one is surfaced into the failure memory so the AI stops acting on
        it. AI-judged (handles ANY assumption, no hardcoding), bounded (open
        assumptions only, one AI call), fail-safe."""
        aware = getattr(self, "awareness", None)
        if not aware or not getattr(self, "ai", None):
            return
        try:
            open_assumptions = [
                a for a in getattr(aware, "active_assumptions", [])
                if isinstance(a, dict) and not a.get("validated")][:12]
            if not open_assumptions:
                return
            findings = []
            store = getattr(self, "store", None)
            eid = getattr(getattr(self, "session", None), "engagement_id", None)
            if store and eid:
                findings = store.get_all_findings(eid) or []
            ev = [f"{f.get('type')}: {f.get('detail')}"
                  for f in findings if isinstance(f, dict)][:40]
            items = [{"id": a.get("id"), "assumption": a.get("assumption")}
                     for a in open_assumptions]
            prompt = (
                "You earlier made these tactical ASSUMPTIONS. Given the evidence "
                "gathered since, judge each one: does the evidence SUPPORT it, "
                "REFUTE it, or is it still UNKNOWN? Be strict — only SUPPORT or "
                "REFUTE when the evidence is clear; otherwise UNKNOWN.\n\n"
                f"Assumptions: {json.dumps(items)}\n\n"
                f"Evidence (findings so far): {json.dumps(ev) or '[]'}\n\n"
                'Output STRICT JSON only: {"verdicts":[{"id":"ASSUME_0",'
                '"verdict":"support|refute|unknown","why":"short"}]}')
            resp = self.ai.query(
                "You audit your own assumptions honestly against evidence.", prompt)
            m = re.search(r'\{[\s\S]*\}', resp or "")
            if not m:
                return
            for v in (json.loads(m.group(0)).get("verdicts") or []):
                if not isinstance(v, dict):
                    continue
                vid = v.get("id")
                verdict = str(v.get("verdict", "unknown")).lower()
                why = str(v.get("why", ""))[:140]
                if verdict == "support":
                    aware.validate_assumption(vid, True, why)
                elif verdict == "refute":
                    aware.validate_assumption(vid, False, why)
                    # Surface the corrected belief so the AI stops acting on it.
                    self._recent_failures.append(
                        f"[ASSUMPTION REVISED] earlier assumption was WRONG: {why}")
        except Exception as e:
            self.log.debug(f"assumption validation failed: {e}")

    def think(self, prompt: str,
              system: str = "You are an expert offensive security AI assistant. Be concise and actionable. When assigning severity, use CVSS criteria: CRITICAL=RCE/SQLi/auth bypass, HIGH=LFI/SSRF/IDOR, MEDIUM=XSS/CORS/open redirect, LOW=info disclosure, INFO=missing headers.",
              mode: str = "full") -> str:
        """
        Convenience wrapper for AI query used by all agents.

        FIX B — Tiered call modes to slash token usage:
          "full" (default) — env snapshot + awareness + advisor + prompt
                             Use on loop 1 of every phase, after failures
          "slim"           — mini env (ban/failure notice only) + prompt
                             Use on mid-loop tactical calls (loops 2-N)
          "nano"           — prompt only, no injections at all
                             Use for summaries, wordlist gen, JSON formatting

        FIX D — Awareness suppression:
          Awareness + advisor are only injected when _awareness_needed is True.
          Agents set self._awareness_needed = True on loop 1 and every 5th loop,
          then set it False for all intermediate loops.
        """
        try:
            if mode == "nano":
                # ── NANO: pure prompt, zero overhead tokens ──────────────
                return self.ai.query(
                    system, prompt, model_id=self._model_for_think_mode("nano"))

            if mode == "slim":
                # ── SLIM: only inject bans/failures if they exist ────────
                slim_lines = []
                if getattr(self, '_tool_ban_list', None):
                    slim_lines.append(
                        f"BANNED TOOLS: {
                            ', '.join(
                                sorted(
                                    self._tool_ban_list)[
                                    :10])}")
                if getattr(self, '_recent_failures', None):
                    slim_lines.append("RECENT FAILURES (avoid repeating):")
                    for s in self._recent_failures[-3:]:
                        slim_lines.append(f"  [!] {s}")
                if slim_lines:
                    slim_ctx = "\n".join(slim_lines)
                    prompt = f"--- CONSTRAINTS ---\n{slim_ctx}\n\n--- TASK ---\n{prompt}"
                return self.ai.query(
                    system, prompt, model_id=self._model_for_think_mode("slim"))

            # ── FULL: current behaviour (env + awareness + advisor) ──────
            # FIX A: Use cached env snapshot — only rebuilds when dirty
            env_snapshot = self._get_environment_snapshot()
            if env_snapshot:
                env_snapshot = self._compact_ai_context(
                    env_snapshot, 2000, "ENVIRONMENT")
                prompt = f"--- RUNTIME ENVIRONMENT ---\n{env_snapshot}\n\n--- TASK ---\n{prompt}"

            # FIX D: Only inject awareness + advisor when the caller signals it's needed
            # (loop 1 of every phase, or every 5th loop). Mid-loop = suppress.
            _inject_awareness = (
                # default True for non-loop callers
                getattr(self, '_awareness_needed', True)
                and not (hasattr(self, '_skip_awareness_injection') and self._skip_awareness_injection)
            )

            if _inject_awareness:
                if hasattr(self, "awareness"):
                    report = self.awareness.get_confidence_report()
                    # Only inject when the lobe actually has something to say —
                    # an empty report would otherwise become a misleading
                    # "you know nothing" header (see get_confidence_report).
                    if report and report.strip():
                        report = self._compact_ai_context(
                            report, 1500, "SELF-AWARENESS")
                        prompt = f"--- SYSTEM SELF-AWARENESS ---\n{report}\n\n{prompt}"

                if hasattr(self, "advisor"):
                    kb_report = self.advisor.get_confidence_report()
                    if kb_report and kb_report.strip():
                        kb_report = self._compact_ai_context(
                            kb_report, 1500, "STRATEGIC KB")
                        prompt = f"--- STRATEGIC KNOWLEDGE BASE ---\n{kb_report}\n\n{prompt}"

                # ACTIVE strategic advice (the dormant brain, now wired in):
                # the advisor's recommendations / stop-signs / pivots + the
                # awareness module's 'collect-next', injected as EVIDENCE. The
                # AI still decides; this just stops it re-deriving blind each
                # loop and gives it an operator's "this is futile, pivot" sense.
                advice_note = self._strategic_advice_note(
                    getattr(self, "name", "").lower())
                if advice_note:
                    advice_note = self._compact_ai_context(
                        advice_note, 1500, "STRATEGIC BRAIN")
                    prompt = f"{advice_note}\n{prompt}"

            prompt = self._compact_ai_context(prompt, 16000, "TASK")
            return self.ai.query(
                system, prompt, model_id=self._model_for_think_mode("full"))

        except RuntimeError as e:
            if "exhausted" in str(e).lower() or "429" in str(e):
                self.log.warning(
                    f"AI think() backends temporarily exhausted: {e}")
                raise  # Let the caller handle it to wait for recovery
            self.log.error(f"AI think() failed: {e}")
            raise
        except Exception as e:
            self.log.error(f"AI think() failed: {e}")
            raise

    def _light_model(self) -> str | None:
        """The small, high-throughput Groq model (llama-3.1-8b-instant) for
        MECHANICAL / utility calls only — grounding (syntax-fix against --help),
        command repair, WAF mutation. NEVER command generation. Returns None if no
        distinct fallback model is configured (then callers use the primary)."""
        try:
            from config_backends import GROQ_MODEL as _p, GROQ_FALLBACK_MODEL as _l
        except Exception:
            return None
        return _l if (_l and _l != _p) else None

    def _model_for_think_mode(self, mode: str) -> str | None:
        """Optionally downgrade a think() TIER to the small model for daily-budget
        (TPD) relief.

        IMPORTANT: default is EMPTY. Command GENERATION uses think() in 'slim'
        (recon loops) and 'nano' (exploitation loops) — routing those to the weak
        8B produced MALFORMED commands (e.g. a bare `-t` that made ffuf parse the
        next flag as its value). So by default ALL think() reasoning, including
        mid-loop command generation, stays on the strong 70B; only MECHANICAL
        calls use _light_model(). Opt in to trade command quality for budget via
        THINK_LIGHT_MODES (e.g. "nano,slim"). Returns None -> primary model.
        """
        light = self._light_model()
        if not light:
            return None
        import os as _os
        light_modes = {
            m.strip() for m in _os.getenv(
                "THINK_LIGHT_MODES", "").split(",") if m.strip()}
        return light if mode in light_modes else None

    def _preflight(self) -> tuple[bool, str]:
        """Default preflight: subclasses may override. Returns (can_proceed, reason)."""
        return True, ""
