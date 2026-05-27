"""
base_agent.py - Ghostwire V6 Autonomous ReAct Agent (merged with V5 compat)
"""
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Optional, Dict, List, Any, Tuple
from utils.logger import get_logger
from utils.display import agent_msg
from core.result_contracts import ToolResult, ResultStatus, PhaseResult, ResultValidator
from tools.tool_registry import TOOL_REGISTRY, VIRTUAL_TOOLS, HTTP_TOOLS
import re
import json
import os
import time as _time_module
import threading
from utils.sanitizer import clean_text
from utils.validator import is_valid_target
from utils.guardian import block_or_repair
import requests
from core.safe_executor import should_retry
from core.ip_rotator import IpRotator
from core.waf_ghost_engine import WafGhostEngine
from core.waf_policy import assess_waf_command
from intelligence.waf_evasion_engine import WafEvasionEngine
from intelligence.tool_success_tracker import ToolSuccessTracker
from core.config_manager import get_config
import config_paths
import shlex
import random
import hashlib
from intelligence.waf_bypass_orchestrator import WafBypassOrchestrator
from intelligence.waf_learner import WafLearner
from intelligence.self_awareness_module import SelfAwarenessModule
from intelligence.structured_analyzer import StructuredAnalyzer
from intelligence.reasoning_engine import ReasoningEngine
from intelligence.strategic_advisor import StrategicAdvisor
from core.result_contracts import FragileParseFixer
from core.attack_graph import AttackGraph

# ── V6 imports ──
from core.target_context import TargetContext
from core.capability_registry import CapabilityRegistry, RiskLevel

# Load config once at module level
config = get_config()
USE_REMOTE_VPS = config.vps.use_remote_vps
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
    def __init__(self, capability: str, target_url: str, params: dict, reason: str = ""):
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
        validation: Optional["ResultValidator"] = None,
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
        self._command_history: dict[str, dict] = {}    # cmd_hash -> {ts: float, status: str}
        self._tool_failure_counts: dict[str, int] = {} # "tool@target" -> consecutive fails
        self._tool_ban_list: set[str] = set()           # "tool@target" banned permanently
        
        # ── FIX #6: Persistent Repair History ──
        self._repair_attempts_history: dict[str, list] = {}  # cmd_hash -> [error1, error2, ...]
        self._successful_repair_strategies: dict[str, str] = {}  # error_pattern -> successful_strategy
        self._timeout_escalation: dict[str, int] = {}   # "tool@target" -> current timeout multiplier
        self._repaired_cmds: set[str] = set()           # hashes of AI-suggested repairs already tried
        self._nuclei_timeout_count = 0                  # V6: Cross-phase nuclei stealth counter
        #   Purpose: prevents the identical-repair loop where two different original
        #   failures produce the same AI suggestion. Without this, the loop fires the
        #   same broken repair repeatedly because each original has a different hash.

        # ── V6 additions ──
        # Capability registry (auto-construct if orchestrator hasn't passed one)
        if capability_registry is None:
            ssh = getattr(tool_manager, "remote", None)
            capability_registry = CapabilityRegistry(ssh_executor=ssh, ai_backend=ai_backend)
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
                        f"[HISTORY] tool={rec.get('tool','?')} "
                        f"error={rec.get('error_type','?')} "
                        f"avoid={rec.get('avoid_next','?')[:80]}"
                    )
                    self._recent_failures.append(snippet)
            
            # Also load from local persistent storage (V6 addition)
            history_file = config_paths.FAILURE_HISTORY_FILE
            if history_file.exists():
                try:
                    local_hist = json.loads(history_file.read_text())
                    if isinstance(local_hist, dict):
                        # ONLY load escalation config, DO NOT load recent_failures or tool_failure_counts
                        # Banning tools globally across engagements breaks fresh targets!
                        self._timeout_escalation = local_hist.get("timeout_escalation", {})
                        self._nuclei_timeout_count = local_hist.get("nuclei_timeout_count", 0)
                except Exception as e:
                    self.log.error(f"CRITICAL: Failed to parse local failure history: {e}", exc_info=True)
                    raise

        except Exception as e:
            self.log.debug(f"Failed to load cross-engagement failures: {e}")

        # ── V6 CROSS-PHASE DATA LOADING: Restore state from StateStore ───────────────
        try:
            if state_store and session and hasattr(session, "engagement_id"):
                # Load nuclei timeout count
                ntc = state_store.get(f"{session.engagement_id}:nuclei_timeout_count")
                if ntc is not None:
                    try:
                        self._nuclei_timeout_count = int(ntc)
                        self.log.info(f"[STEALTH] Restored nuclei timeout count: {self._nuclei_timeout_count}")
                    except (ValueError, TypeError) as _ntc_err:
                        self.log.warning(f"[STEALTH] Invalid nuclei timeout count value '{ntc}': {_ntc_err}")

                # Load bans
                raw_bans = state_store.get(f"{session.engagement_id}:tool_bans")
                if raw_bans:
                    if isinstance(raw_bans, str):
                        loaded_bans = json.loads(raw_bans)
                    else:
                        loaded_bans = list(raw_bans)
                    for ban in loaded_bans:
                        self._tool_ban_list.add(str(ban))
                    if loaded_bans:
                        self.log.info(f"[TOOL BAN] Loaded {len(loaded_bans)} persistent ban(s) from previous phase: {loaded_bans}")
        except Exception as _load_err:
            self.log.debug(f"Failed to load persistent cross-phase data: {_load_err}")
        # ─────────────────────────────────────────────────────────────────────────────

        # Metrics Tracking (Resilient to None session)
        metrics_path = config_paths.TOOL_METRICS_FILE
        if session and hasattr(session, 'results_dir'):
            results_dir = Path(session.results_dir) if isinstance(session.results_dir, str) else session.results_dir
            metrics_path = results_dir / "tool_metrics.json"
        
        self.tool_tracker = ToolSuccessTracker(db_path=metrics_path)

        self._ssh = getattr(self.tools, "remote", None) if self.tools else None
        self._stealth = getattr(self.session, "stealth_config", {}) if self.session else {}
        self._infra_rules = self._get_infra_rules()

        self._ip_rotator: IpRotator | None = None
        if self._stealth.get("rotate_ip"):
            if self.tools.ensure_installed("tor"):
                self._ip_rotator = IpRotator(ssh_executor=self._ssh, rules=self._infra_rules)
                self._ip_rotator.ensure_tor_ready()
            else:
                self.log.warning("IP rotation requested but 'tor' installation failed. Continuing without rotation.")

        self._waf_ghost: WafGhostEngine | None = None
        if self._stealth.get("ghost_mode"):
            self._waf_ghost = WafGhostEngine(ssh_executor=self._ssh, rules=self._infra_rules)

        self._waf_evasion = WafEvasionEngine()
        self._waf_orchestrator = WafBypassOrchestrator(
            state_store=self.store
        )
        self._waf_learner = WafLearner()
        
        # ── Unified Intelligence Layer ──
        self.analyzer = StructuredAnalyzer(ai_backend=self.ai)
        self.reasoning = ReasoningEngine(ai_backend=self.ai, state_store=self.store)
        self.awareness = SelfAwarenessModule(state_store=self.store)
        self.advisor = StrategicAdvisor(state_store=self.store, ai_backend=self.ai)
        
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

    def should_abort(self) -> bool:
        """
        Check if the engagement should be aborted due to critical VPS health issues.
        Consults the global state updated by the HealthMonitor.
        """
        try:
            health = self.store.get_global_data("vps_health")
            if health and not health.get("healthy", True):
                self.log.error(f"ABORT SIGNAL: VPS health critical. Issues: {', '.join(health.get('issues', []))}")
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
        if not self.store or not self.session or not hasattr(self.session, "engagement_id"):
            return True, ""  # Can't validate without store, assume okay
        
        phase = self.name.lower()
        
        # ── EXPLOITATION requires: Open ports, subdomains, or directories from Recon ──
        if phase == "exploitation":
            recon_data = self.store.get_phase_data(self.session.engagement_id, "recon")
            
            if not recon_data or not isinstance(recon_data, dict):
                return False, "Recon phase data missing or corrupted"
            
            open_ports = recon_data.get("open_ports") or recon_data.get("ports_found")
            subdomains = recon_data.get("subdomains", [])
            dirs = recon_data.get("directories", [])
            endpoints = recon_data.get("endpoints", [])
            
            has_ports = isinstance(open_ports, list) and len(open_ports) > 0
            has_subs = isinstance(subdomains, list) and len(subdomains) > 0
            has_dirs = isinstance(dirs, list) and len(dirs) > 0
            has_endpoints = isinstance(endpoints, list) and len(endpoints) > 0
            
            if not any([has_ports, has_subs, has_dirs, has_endpoints]):
                return False, "No usable targets (ports, subdomains, directories) discovered in Recon"
            
            self.log.info(f"[GATE] Exploitation prerequisites met. Usable data discovered.")
            return True, ""
        
        # ── PERSISTENCE requires: Shell access from Exploitation ──
        if phase == "persistence":
            exploit_data = self.store.get_phase_data(self.session.engagement_id, "exploitation")
            
            # Check 1: Data exists
            if exploit_data is None:
                return False, "Exploitation phase not completed"
            
            # Check 2: Data is correct type
            if not isinstance(exploit_data, dict):
                return False, f"Exploitation data corrupted: {type(exploit_data).__name__}"
            
            # Check 3: Shell access field exists and is dict
            shell_access = exploit_data.get("shell_access")
            if not isinstance(shell_access, dict):
                return False, f"shell_access field invalid: {type(shell_access).__name__}"
            
            # Check 4: Shell access achieved
            if not shell_access.get("achieved"):
                return False, "No shell access achieved in Exploitation phase"
            
            self.log.info(f"[GATE] Persistence prerequisites met: Shell access verified")
            return True, ""
        
        # ── REPORTING requires: Findings from prior phases ──
        if phase == "reporting":
            all_findings = self.store.get_all_findings(self.session.engagement_id) or []
            
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
            
            self.log.info(f"[GATE] Reporting prerequisites met: {len(all_findings)} finding(s) valid")
            return True, ""
        
        # Default: all other phases can proceed
        return True, ""

    def _on_message(self, from_agent: str, payload: dict):
        self.log.debug(f"Message from {from_agent}: {str(payload)[:200]}")
        self._handle_message(from_agent, payload)

    def _provision_target_wordlist(self, recon_data: dict = None) -> str | None:
        """
        V6 Autonomous Wordlist Provisioning.
        Uses AI to prescribe a highly-targeted wordlist or generate a micro-wordlist
        based on the discovered technology stack, completely removing hardcoded fallback URLs.
        """
        tech_context = ""
        if recon_data:
            findings = self.store.get_all_findings(self.session.engagement_id)
            tech_stack = [f["detail"] for f in findings if f["type"] == "tech_stack"]
            tech_context = f"Tech Stack: {', '.join(tech_stack)}"
        
        # Autonomous environment context
        env_snapshot = self._get_environment_snapshot()
        env_context = f"--- RUNTIME ENVIRONMENT ---\n{env_snapshot}\n\n" if env_snapshot else ""
        
        prompt = f"""{env_context}### CONTEXT
We need a wordlist for web directory/file brute-forcing (e.g., gobuster, ffuf).
{tech_context}
Target: {self.session.target}

### MISSION
You are an autonomous offensive AI. Determine the absolute BEST wordlist approach.
WAF PRESENCE: High probability. DO NOT USE massive generic lists (e.g. dirb_common with 60k words) as they will get blocked instantly.

You MUST choose one of two options and return a STRICT JSON response. No markdown wrappers.

Option 1 (Generate - RECOMMENDED): Generate a highly-targeted micro-wordlist (50-500 entries max) specific to the tech stack (e.g., WordPress config files, specific API endpoints).
Option 2 (Fetch): Provide a one-liner bash command to download a highly-relevant, SMALL wordlist from a reliable source to '{config_paths.VPS_TEMP_DIR}/ai_wordlist.txt'.

### RESPONSE SCHEMA
{{
  "type": "fetch" | "generate",
  "bash_command": "curl -sL https://... -o {config_paths.VPS_TEMP_DIR}/ai_wordlist.txt" (if fetch),
  "wordlist": ["/admin", "/api/v1", ".env", "wp-config.php.bak"] (if generate)
}}
"""
        # BUG FIX: Never use pathlib.Path for VPS paths - Path() on Windows converts
        # forward slashes to backslashes, producing \\tmp\\antigravity\\ai_wordlist.txt
        # which is invalid on the Linux VPS. Always use posixpath for remote paths.
        import posixpath
        target_path = posixpath.join(config_paths.VPS_TEMP_DIR, "ai_wordlist.txt") if USE_REMOTE_VPS else str(Path(self.session.results_dir) / "raw" / "ai_wordlist.txt")
        
        try:
            ai_resp = self.think(prompt).strip()
            # Clean possible markdown JSON wrappers
            if ai_resp.startswith("```json"): ai_resp = ai_resp[7:]
            if ai_resp.startswith("```"): ai_resp = ai_resp[3:]
            if ai_resp.endswith("```"): ai_resp = ai_resp[:-3]
            ai_resp = ai_resp.strip()
            
            data = json.loads(ai_resp, strict=False)
            action_type = data.get("type")
            
            if action_type == "fetch" and data.get("bash_command"):
                cmd = data["bash_command"]
                self.log.info(f"[AI WORDLIST] Executing fetch command: {cmd}")
                if USE_REMOTE_VPS and self.tools.remote:
                    ec, out, err = self.tools.remote.execute(cmd, timeout=TOOL_DEFAULT_TIMEOUT)
                    if ec != 0:
                        self.log.warning(f"Wordlist fetch failed: {err}")
                        return None
                else:
                    import subprocess
                    subprocess.run(cmd, shell=True, timeout=TOOL_DEFAULT_TIMEOUT, capture_output=True)
                    
            elif action_type == "generate" and data.get("wordlist"):
                words = data["wordlist"]
                self.log.info(f"[AI WORDLIST] Generating micro-wordlist with {len(words)} entries.")
                if USE_REMOTE_VPS and self.tools.remote:
                    # Write in chunks to avoid command line length limits
                    chunk_size = 20
                    self.tools.remote.execute(f"rm -f {target_path}") # Ensure fresh file
                    for i in range(0, len(words), chunk_size):
                        chunk = "\n".join(words[i:i+chunk_size])
                        safe_chunk = shlex.quote(chunk + "\n")
                        self.tools.remote.execute(f"echo -n {safe_chunk} >> {target_path}")
                else:
                    import os
                    os.makedirs(os.path.dirname(target_path), exist_ok=True)
                    with open(target_path, "w", encoding="utf-8") as f:
                        f.write("\n".join(words) + "\n")
            else:
                self.log.warning(f"AI returned invalid wordlist schema: {data}")
                return None
                
            # Verification Step
            if USE_REMOTE_VPS and self.tools.remote:
                ec, out, _ = self.tools.remote.execute(f"[ -s {target_path} ] && wc -l < {target_path}")
                if ec == 0 and out.strip().isdigit() and int(out.strip()) >= 5:
                    self.log.info(f"[AI WORDLIST] Provisioned successfully at {target_path}")
                    return target_path
            else:
                import os
                if os.path.exists(target_path) and os.path.getsize(target_path) > 10:
                    self.log.info(f"[AI WORDLIST] Provisioned successfully at {target_path}")
                    return target_path
                    
        except Exception as e:
            self.log.error(f"AI Wordlist provisioning failed: {e}")
            
        return None

    def _provision_target_wordlist_async(self, recon_data: dict = None, max_retries: int = 3) -> str | None:
        """
        Provision wordlist with retry logic and exponential backoff.
        Handles network timeouts and transient failures gracefully.
        """
        import time
        
        for attempt in range(max_retries):
            try:
                wordlist_path = self._provision_target_wordlist(recon_data)
                
                if wordlist_path is None:
                    self.log.warning(f"[ASYNC WORDLIST] Attempt {attempt+1}/{max_retries}: provisioning returned None")
                    if attempt < max_retries - 1:
                        wait_time = 2 ** attempt  # Exponential backoff: 1s, 2s, 4s
                        self.log.info(f"[ASYNC WORDLIST] Waiting {wait_time}s before retry...")
                        time.sleep(wait_time)
                    continue
                
                # Verify file exists and has content
                if self.tools.remote and hasattr(self.tools.remote, 'execute'):
                    size_code, size_out, _ = self.tools.remote.execute(f"wc -c < {wordlist_path}", timeout=TOOL_DEFAULT_TIMEOUT)
                    if size_code == 0 and size_out.strip().isdigit():
                        file_size = int(size_out.strip())
                        if file_size > 0:
                            self.log.info(f"[ASYNC WORDLIST] Successfully provisioned wordlist: {wordlist_path} ({file_size} bytes)")
                            return wordlist_path
                else:
                    # Local verification
                    import os
                    if os.path.exists(wordlist_path) and os.path.getsize(wordlist_path) > 0:
                        self.log.info(f"[ASYNC WORDLIST] Successfully provisioned wordlist: {wordlist_path}")
                        return wordlist_path
                
                self.log.warning(f"[ASYNC WORDLIST] Attempt {attempt+1}/{max_retries}: file verification failed")
                if attempt < max_retries - 1:
                    wait_time = 2 ** attempt
                    self.log.info(f"[ASYNC WORDLIST] Waiting {wait_time}s before retry...")
                    time.sleep(wait_time)
            
            except Exception as e:
                self.log.warning(f"[ASYNC WORDLIST] Attempt {attempt+1}/{max_retries} exception: {e}")
                if attempt < max_retries - 1:
                    wait_time = 2 ** attempt
                    self.log.info(f"[ASYNC WORDLIST] Waiting {wait_time}s before retry...")
                    time.sleep(wait_time)
        
        # All retries exhausted, fall back to micro-wordlist
        self.log.warning("[ASYNC WORDLIST] All provisioning attempts failed, generating micro-wordlist as fallback")
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
            target_path = posixpath.join(config_paths.VPS_TEMP_DIR, f"micro_wordlist_{int(time.time())}.txt")
            
            content = "\n".join(common_words)
            
            if self.tools.remote and hasattr(self.tools.remote, 'execute'):
                cmd = f"cat > {target_path} << 'EOF'\n{content}\nEOF"
                returncode, _, stderr = self.tools.remote.execute(cmd, timeout=TOOL_DEFAULT_TIMEOUT)
                
                if returncode == 0:
                    self.log.info(f"[MICRO WORDLIST] Generated at {target_path} ({len(common_words)} entries)")
                    return target_path
                else:
                    self.log.error(f"[MICRO WORDLIST] Failed to write: {stderr}")
                    return None
            else:
                # Local fallback
                import os
                os.makedirs(os.path.dirname(target_path), exist_ok=True)
                with open(target_path, "w", encoding="utf-8") as f:
                    f.write("\n".join(common_words) + "\n")
                self.log.info(f"[MICRO WORDLIST] Generated locally at {target_path} ({len(common_words)} entries)")
                return target_path
        
        except Exception as e:
            self.log.error(f"[MICRO WORDLIST] Failed to generate: {e}")
            return None

    def _handle_message(self, from_agent: str, payload: dict) -> None:
        pass

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

    def _track_and_return(self, result: ToolResult):
        self._track_failure(result)
        return result

    def _track_failure(self, result: ToolResult):
        if not result or result.status == ResultStatus.SUCCESS:
            return
        err_snippet = str(result.stderr or result.stdout)[:150].strip()
        tool_name = result.tool or "unknown"
        # V6: Consistent snippet format so safe_run_tool can detect it
        ctx = f"[SESSION] tool={tool_name} status={result.status} | err={err_snippet}"
        
        if not self._recent_failures or self._recent_failures[-1] != ctx:
            self._recent_failures.append(ctx)
            if len(self._recent_failures) > 20: # Increased history
                self._recent_failures.pop(0)
            
            # Increment failure counts for proactive learning
            host = self._extract_host(result.command) or "unknown"
            fail_key = f"{tool_name}@{host}"
            self._tool_failure_counts[fail_key] = self._tool_failure_counts.get(fail_key, 0) + 1

            try:
                self.store.record_failure_pattern(
                    engagement_id=self.session.engagement_id,
                    agent_id=self.name,
                    tool=result.tool or "unknown",
                    error_type=result.status.value if hasattr(result.status, "value") else str(result.status),
                    command=result.command,
                    stderr=result.stderr,
                    root_cause=ctx,
                    severity="warning" if result.status in (ResultStatus.TIMEOUT, ResultStatus.BLOCKED) else "error",
                    avoid_next=f"Avoid {result.tool or 'unknown'} if it consistently fails",
                )
                
                # Persist to local failure history file as backup for cross-session learning
                history_file = config_paths.FAILURE_HISTORY_FILE
                local_data = {"recent_failures": [], "tool_failure_counts": {}, "timeout_escalation": {}}
                if history_file.exists():
                    try:
                        local_data = json.loads(history_file.read_text())
                        if isinstance(local_data, list): # Migrate old format
                            local_data = {"recent_failures": [f"tool={r.get('tool')} status={r.get('status')}" for r in local_data], "tool_failure_counts": {}, "timeout_escalation": {}}
                    except Exception as e:
                        self.log.error(f"CRITICAL: Failed to parse failure history JSON: {e}", exc_info=True)
                        raise
                
                # Update recent failures
                recent = local_data.get("recent_failures", [])
                recent.append(ctx)
                local_data["recent_failures"] = recent[-50:]
                
                # Update counts
                local_data["tool_failure_counts"] = self._tool_failure_counts
                local_data["timeout_escalation"] = self._timeout_escalation
                local_data["nuclei_timeout_count"] = self._nuclei_timeout_count
                
                history_file.write_text(json.dumps(local_data, indent=2))

                # Also persist nuclei count to StateStore for cross-phase persistence
                if self.store and self.session and hasattr(self.session, "engagement_id"):
                    self.store.set(f"{self.session.engagement_id}:nuclei_timeout_count", str(self._nuclei_timeout_count))
                
            except Exception as e:
                self.log.debug(f"Failed to persist failure pattern: {e}")
        
        # Log to tool tracker
        tool_name = result.tool or "unknown"
        error_type = result.status.value if hasattr(result.status, "value") else str(result.status)
        try:
            target_type = "unknown"
            if self.session and hasattr(self.session, 'target'):
                target_str = str(self.session.target).lower()
                if 'wordpress' in target_str or 'wp-' in target_str:
                    target_type = "wordpress"
                elif 'apache' in target_str:
                    target_type = "apache"
                elif 'nginx' in target_str:
                    target_type = "nginx"
                elif 'cloudflare' in target_str or 'cdn' in target_str:
                    target_type = "cdn"
                else:
                    target_type = "generic"
            self.tool_tracker.log_tool_result(
                tool_name=tool_name,
                success=False,
                target_type=target_type,
                target=self.session.target if self.session and hasattr(self.session, 'target') else "",
                error_type=error_type,
            )
        except Exception as e2:
            self.log.debug(f"Failed to log tool failure: {e2}")

    def add_finding(self, finding_type: str, target: str, detail: str,
                    severity: str = "info", source_tool: str = None, command: str = None):
        with self._findings_lock:
            detail_prefix = detail[:120]
            dedup_detail = re.sub(r'https?://\S+', '', detail_prefix).strip().lower()
            dedup_key = f"{finding_type}::{target}::{dedup_detail[:120]}"
            if dedup_key in self._findings_seen:
                self._finding_dedup_counts[dedup_key] = self._finding_dedup_counts.get(dedup_key, 0) + 1
                return
            self._findings_seen.add(dedup_key)
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
            finding_node = f"finding:{finding_type}:{hashlib.md5(detail.encode()).hexdigest()[:8]}"
            
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
                    confidence = 0.9 if severity in {"high", "critical"} else 0.6 if severity == "medium" else 0.4
                    self.advisor.record_finding(
                        finding_type=finding_type,
                        target=target,
                        detail=detail,
                        severity=severity,
                        confidence=confidence,
                    )
                except Exception as _advisor_err:
                    self.log.debug(f"Advisor finding record failed: {_advisor_err}")
        agent_msg(self.name, f"[{severity.upper()}] {finding_type} on {target}: {detail[:100]}")

    def flush_dedup_stats(self) -> None:
        if self._finding_dedup_counts:
            total = sum(self._finding_dedup_counts.values())
            self.log.info(f"Dedup summary: {total} duplicates suppressed across {len(self._finding_dedup_counts)} categories.")
            self._finding_dedup_counts.clear()

    def finish_phase(self, results: dict, status: ResultStatus = ResultStatus.SUCCESS, message: str = "") -> PhaseResult:
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
        if self.store and self.session and hasattr(self.session, "engagement_id"):
            status_val = status.value if hasattr(status, "value") else str(status)
            self.store.set_phase_status(self.session.engagement_id, self.name, status_val, message)
            self.store.set_phase_data(self.session.engagement_id, self.name, results)

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
            self.log.error(f"[FIX 3.6] PHASE CONTRACT VIOLATION ({self.name}): {error_detail}")
            # FIX #3.6: Return error PhaseResult instead of invalid result
            return PhaseResult(
                phase=self.name,
                status=ResultStatus.VALIDATION_ERROR,
                timestamp=_time_module.time(),
                data={},  # Empty data - invalid data doesn't propagate
                error_message=f"Phase result validation failed: {error_detail}"
            )
        
        return phase_res

    def _clean_command(self, command: str) -> str:
        if not command:
            return ""
        command = re.sub(r'[^\x20-\x7E\n\t]', '', command.strip())
        if re.search(r'(?:rm\s+-rf|mkfs|dd)\s', command, re.IGNORECASE):
            raise ValueError("Dangerous command sequence detected")
        return command

    def _repair_common_tool_flags(self, tool: str, command: str) -> str:
        """Restore required flags for common CLI tools without changing the command family."""
        if not command:
            return command

        repaired = command
        tool_name = (tool or "").lower()

        # Remove synthetic quiet flags that are not supported consistently across tools.
        if tool_name in {"sqlmap", "sslscan"}:
            repaired = re.sub(r"(?<!\S)-q(?!\S)", "", repaired)

        if tool_name == "nuclei":
            repaired = re.sub(r"(?<!\S)-q(?!\S)", "", repaired)
            if "/path/to/" in repaired or "actual/path/to/" in repaired or "/full/path/to/" in repaired:
                repaired = re.sub(
                    r"-t\s+\S+",
                    f"-t {self._nuclei_templates_path()}",
                    repaired,
                )
            if " -t " not in repaired:
                repaired = f"{repaired} -t {self._nuclei_templates_path()}".strip()

        if tool_name == "sslscan":
            # sslscan expects host:port, not http://host
            repaired = re.sub(r"https?://", "", repaired)
            # Remove trailing slashes
            repaired = re.sub(r"/+$", "", repaired)

        if tool_name == "whatweb":
            # whatweb's -a is an aggression level only.
            repaired = re.sub(r"(?<!\S)-a\s+(?![123](?:\s|$))\S+", "-a 3", repaired)
            if " -a " not in repaired:
                repaired = f"{repaired} -a 3".strip()

        # Fix AI inventing invalid wordlist paths - resolve dynamically from config
        if tool_name in {"gobuster", "ffuf", "dirsearch"}:
            # Extract wordlist type from command
            wordlist_match = re.search(r"-w\s+(\S+)", repaired)
            if wordlist_match:
                requested_path = wordlist_match.group(1)
                # Resolve from config instead of assuming paths
                resolved_path = self._resolve_wordlist_path(tool_name, requested_path)
                if resolved_path:
                    repaired = re.sub(r"-w\s+\S+", f"-w {resolved_path}", repaired)

        return repaired

    def _resolve_wordlist_path(self, tool: str, requested_path: str) -> str:
        """Dynamically resolve wordlist path from config, download if needed."""
        from config_paths import get_vps_wordlist, VPS_TEMP_DIR
        from core.config_loader import get_config
        
        # Check if path exists on VPS
        if self.tools and self.tools.remote:
            try:
                ec, _, _ = self.tools.remote.execute(f"[ -f {requested_path} ] && echo YES", timeout=5)
                if ec == 0:
                    return requested_path
            except Exception as _vps_check_err:
                self.log.debug(f"VPS file existence check failed for '{requested_path}': {_vps_check_err}")
        
        # Try to resolve from configured wordlist paths
        wordlist_type = "common" if "common" in requested_path.lower() else "directory"
        vps_wordlist = get_vps_wordlist(wordlist_type, self.tools.remote if self.tools else None)
        if vps_wordlist:
            return vps_wordlist
        
        # Fallback: return AI wordlist path (should be auto-downloaded by recon phase)
        return f"{VPS_TEMP_DIR}/ai_wordlist.txt"

    def _normalize_command_targets(self, command: str) -> str:
        if not command:
            return command

        normalized = command

        # Collapse repeated or nested schemes inside commands.
        while True:
            updated = re.sub(r"(?i)(https?://)(?:https?://)+", r"\1", normalized)
            if updated == normalized:
                break
            normalized = updated

        return normalized

    def _canonicalize_tool_command(self, tool: str, command: str, target: str = None) -> str:
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
            except Exception:
                url_target = target
                host_target = target

            if tool_name in {"curl", "nikto", "gobuster", "ffuf", "nuclei", "whatweb", "wafw00f", "dirsearch", "dirb"}:
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
                # by "://" (i.e. it is a standalone bare-host token, not inside a URL).
                escaped = re.escape(variant)
                canonical = re.sub(
                    r"(?<!://)(?<![a-zA-Z0-9._-])" + escaped + r"(?![a-zA-Z0-9._/-])",
                    preferred_target,
                    canonical,
                )

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
                remainder = canonical.split("nmap ", 1)[-1] if "nmap " in canonical else canonical
                canonical = f"nmap {prefix} {remainder}".strip()

            canonical = re.sub(r'\s{2,}', ' ', canonical).strip()

        return canonical

    def _nuclei_templates_path(self) -> str:
        return os.getenv("NUCLEI_TEMPLATES", "~/nuclei-templates/")

    def _extract_host(self, command: str) -> str | None:
        """Extract the target URL or host from a CLI command string.
        
        Searches for URL patterns (https://host, http://host) or bare IPs/domains
        within the command - never feeds the entire command to a host:port parser.
        """
        if not command:
            return None
        
        import re
        # Priority 1: Find full URLs (http://... or https://...)
        # We handle stacked schemes explicitly here since standard regex stops short
        url_matches = re.findall(r'(?:https?://)+[a-zA-Z0-9._-]+(?::[0-9]+)?', command, flags=re.IGNORECASE)
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
        domains = re.findall(r'\b([a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?\.(?:[a-zA-Z]{2,}))(?::\d+)?\b', command)
        if domains:
            return domains[0]
        
        return None

    def safe_run_tool(self, tool: str, command: str, target: str = None,
                      output_path: str | Path = None, silent: bool = False,
                      timeout: int = 120):
        from core.scope_enforcer import ScopeViolation

        # ── Proactive Kill-Switch Check ──────────────────────────────────────
        if self.should_abort():
            return ToolResult(tool=tool, command=command, stdout="",
                              stderr="Engagement aborted: VPS resource critical.",
                              exit_code=-1, duration_seconds=0, status=ResultStatus.BLOCKED)

        # ── V6 CRITICAL: Check ban list BEFORE anything else ──────────────────
        # The ban list is populated when a tool times out 3+ times. We must gate
        # here - after cross-phase load in __init__ - so bans from a prior phase
        # (e.g., nuclei banned during Recon) prevent execution in Exploitation too.
        _run_host = self._extract_host(command) or target or "unknown"
        _ban_key_specific = f"{tool}@{_run_host}"
        _ban_key_global = f"{tool}@GLOBAL"
        if _ban_key_specific in self._tool_ban_list or _ban_key_global in self._tool_ban_list:
            matched_key = _ban_key_specific if _ban_key_specific in self._tool_ban_list else _ban_key_global
            self.log.warning(f"[TOOL BAN GATE] '{tool}' is banned (key={matched_key}). Skipping execution.")
            return ToolResult(tool=tool, command=command, stdout="",
                              stderr=f"Tool '{tool}' is permanently banned for this engagement (3+ timeouts).",
                              exit_code=-1, duration_seconds=0, status=ResultStatus.BLOCKED)
        # ─────────────────────────────────────────────────────────────────────

        if target:
            try:
                self.scope.check_target(target)
            except ScopeViolation as e:
                self.log.warning(f"SCOPE BLOCK: {e}")
                return ToolResult(tool=tool, command=command, stdout="", stderr=str(e),
                                  exit_code=-1, duration_seconds=0, status=ResultStatus.BLOCKED)

        # ── V6 HARDENED URL normalization (no naive str.replace on bare hosts) ──
        if target and isinstance(target, str):
            ctx = TargetContext.from_input(target)

            # Expanded set: ALL tools that accept/require a full URL with scheme
            SCHEME_TOOLS = {
                "curl", "nikto", "gobuster", "ffuf", "nuclei",
                "whatweb", "wafw00f", "dirb", "sqlmap", "wfuzz",
                "feroxbuster", "dirsearch", "httpx",
            }

            if tool.lower() in SCHEME_TOOLS:
                target = ctx.base_url   # e.g. "https://novalink.lk"
            else:
                target = ctx.host       # bare hostname/IP for nmap, masscan, etc.

            # ── SAFE command sanitization: collapse any stacked schemes already
            # present in the command string without touching other text.
            # Example: "dirb https://http://novalink.lk/ ..." -> "dirb https://novalink.lk/ ..."
            # We do NOT use str.replace(old_bare_host, new_full_url) because that
            # turns "https://novalink.lk/" into "https://http://novalink.lk/".
            if command:
                # Pass 1: collapse stacked schemes (e.g. https://http://, http://https://)
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
            _host_for_validation, _ = FragileParseFixer.safe_port_extraction(target)
            
            if not _host_for_validation:
                self.log.warning(f"VALIDATION BLOCK: Could not extract host from '{target}'")
                return ToolResult(tool=tool, command=command, stdout="",
                                  stderr=f"Invalid target format: {target}", exit_code=-1,
                                  duration_seconds=0, status=ResultStatus.FAILURE)

            if not is_valid_target(_host_for_validation):
                self.log.warning(f"VALIDATION BLOCK: '{_host_for_validation}' is not a valid domain or IP.")
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
                    f"(TLS dead, retry in {TLS_BREAKER_BACKOFF_SECS - elapsed:.0f}s)"
                )
                return ToolResult(tool=tool, command=command, stdout="",
                                  stderr="TLS blocked by circuit breaker",
                                  exit_code=35, duration_seconds=0, status=ResultStatus.BLOCKED)
            elif breaker_info["retries"] >= TLS_BREAKER_MAX_RETRIES:
                self.log.warning(
                    f"[TLS CIRCUIT BREAKER] Permanently blocked: {cmd_host} "
                    f"({breaker_info['retries']}/{TLS_BREAKER_MAX_RETRIES} retries exhausted)"
                )
                return ToolResult(tool=tool, command=command, stdout="",
                                  stderr="TLS blocked permanently after max retries",
                                  exit_code=35, duration_seconds=0, status=ResultStatus.BLOCKED)
            else:
                self.log.info(
                    f"[TLS CIRCUIT BREAKER] Backoff expired for {cmd_host}. "
                    f"Clearing block for clean retry (attempt {breaker_info['retries'] + 1}/{TLS_BREAKER_MAX_RETRIES})..."
                )
                self._tls_blocked_hosts[cmd_host]["retries"] += 1
                del self._tls_blocked_hosts[cmd_host]

        # ── V6: COMMAND DEDUPLICATION & PROACTIVE LEARNING ──
        # We'll use the tool+target as a key for failure tracking
        clean_host = self._extract_host(command) or target or "unknown"
        fail_key = f"{tool}@{clean_host}"
        fail_count = self._tool_failure_counts.get(fail_key, 0)
        
        # ── Historical Memory: Check cross-engagement failures ──
        historical_timeout = False
        for pattern in self._recent_failures:
            if f"tool={tool}" in pattern and "TIMEOUT" in pattern.upper():
                historical_timeout = True
                break
        
        # If this tool has failed multiple times on this target, 
        # or if we have historical memory of a timeout, proactively lighten
        effective_fail_count = fail_count
        if historical_timeout or effective_fail_count >= 1:
            reason = "historical memory" if historical_timeout else f"recent failure ({effective_fail_count})"
            self.log.info(f"[PROACTIVE LEARNING] Tool {tool} previously timed out ({reason}). Lightening command.")
            command = self._make_command_lighter(tool, command, effective_fail_count + (1 if historical_timeout else 0))

        # ── V6: Automated WAF Evasion integration ──
        if self._waf_ghost and tool.lower() in HTTP_TOOLS:
            # Check if WAF is present in current context
            ctx_data = self.store.get_phase_data(self.session.engagement_id, "recon") or {}
            if ctx_data.get("waf_present"):
                self.log.info(f"[WAF EVASION] WAF detected on target. Applying Ghost Engine mutations to {tool}.")
                command = self._waf_ghost.transform(command, tool, level=2)

        # ── V6: PRE-EMPTIVE RETARGETING (Mandatory Bypass Adoption) ──
        if tool.lower() in HTTP_TOOLS:
            try:
                recon_data = self.store.get_phase_data(self.session.engagement_id, "recon") or {}
                bypass_url = recon_data.get("waf_bypass_url")
                if bypass_url:
                    bypass_url = bypass_url.rstrip('/')
                    original_host = self._extract_host(command)
                    if original_host and original_host.rstrip('/') != bypass_url:
                        self.log.info(f"[RETARGETING] Adopting discovered bypass for {tool}: {original_host} -> {bypass_url}")
                        escaped_host = re.escape(original_host)
                        command = re.sub(
                            r'(?<![a-zA-Z0-9/._:-])' + escaped_host + r'(?![a-zA-Z0-9._/-])',
                            bypass_url,
                            command,
                        )
                        
                        # ── V6: HOST HEADER INJECTION (Critical for Direct IP Access) ──
                        # If retargeting to an IP, ensure we have a Host header for HTTP compliance
                        is_ip = re.search(r'\d+\.\d+\.\d+\.\d+', bypass_url)
                        if is_ip and not "Host:" in command:
                            clean_domain = original_host.replace("http://","").replace("https://","").split('/')[0]
                            if tool_name in ("curl", "gobuster", "ffuf", "dirsearch"):
                                # Ensure we don't duplicate -H
                                if tool_name == "curl":
                                    command = command.replace("curl ", f'curl -H "Host: {clean_domain}" ')
                                elif tool_name == "gobuster":
                                    if "gobuster dir " in command:
                                        command = command.replace("gobuster dir ", f'gobuster dir -H "Host: {clean_domain}" ')
                                    elif "gobuster vhost " in command:
                                        command = command.replace("gobuster vhost ", f'gobuster vhost -H "Host: {clean_domain}" ')
                                    else:
                                        command = command.replace("gobuster ", f'gobuster -H "Host: {clean_domain}" ')
                                else:
                                    command += f' -H "Host: {clean_domain}"'
                                self.log.debug(f"[RETARGETING] Injected Host header: {clean_domain}")
            except Exception as _retarget_err:
                self.log.debug(f"Pre-emptive retargeting error: {_retarget_err}")

        # ── V6: PREFLIGHT ADJUSTMENT ──
        # Detect wildcards or environmental issues before first run
        command_tool = (self._extract_primary_tool(command) or tool or "").lower()

        current_command = self._repair_common_tool_flags(
            command_tool,
            self._normalize_command_targets(self._clean_command(clean_text(command)))
        )
        current_command = self._preflight_adjust_for_wildcard(command_tool, current_command, target or cmd_host)
        current_command = self._repair_common_tool_flags(command_tool, current_command)
        current_command = self._canonicalize_tool_command(command_tool, current_command, target=target or cmd_host)
        # FINAL scheme collapse: WAF ghost transform and preflight may reintroduce stacked
        # schemes (e.g. https://http://). Apply one last collapse pass after ALL transforms.
        _prev = None
        while _prev != current_command:
            _prev = current_command
            current_command = re.sub(r"(?i)(https?://)(?:https?://)+", r"\1", current_command)

        validated_command, validation_reason = block_or_repair(
            current_command,
            target or cmd_host or (self.session.target if self.session and hasattr(self.session, "target") else ""),
        )
        if not validated_command:
            self.log.warning(f"[COMMAND GUARDIAN] {validation_reason}")
            return ToolResult(
                tool=tool,
                command=current_command,
                stdout="",
                stderr=validation_reason,
                exit_code=-1,
                duration_seconds=0,
                status=ResultStatus.BLOCKED,
            )
        current_command = validated_command
        current_command = self._repair_common_tool_flags(command_tool, current_command)
        current_command = self._canonicalize_tool_command(command_tool, current_command, target=target or cmd_host)

        cmd_hash = hashlib.sha256(current_command.encode()).hexdigest()[:16]
        now = _time_module.time()
        if cmd_hash in self._command_history:
            prior = self._command_history[cmd_hash]
            elapsed = now - prior["ts"]
            prior_status = prior.get("status", "unknown")
            # Only hard-block if the previous run was NOT a timeout
            # (timeouts get a lighter-command retry via _make_command_lighter)
            if elapsed < 300 and prior_status != ResultStatus.TIMEOUT.value:
                self.log.warning(f"[COMMAND DEDUP] Exact command already tried {elapsed:.0f}s ago (status={prior_status}). Rejecting.")
                return ToolResult(tool=tool, command=current_command, stdout="",
                                  stderr="Command rejected: identical command already failed within 5 minutes",
                                  exit_code=-1, duration_seconds=0, status=ResultStatus.BLOCKED)
        
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
            # We've tried this command+tool+target 3+ times. Force a different approach.
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
                
                # Python/scripting tools (FIX #3.2: Added missing script execution fallbacks)
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
                next_tool = available_fallbacks[0]  # Start with first available
                self.log.info(f"[CYCLE RECOVERY] Tool chain for '{tool}': {fallback_chain}")
                self.log.info(f"[CYCLE RECOVERY] Switching from '{tool}' to '{next_tool}' (attempt 1/{len(available_fallbacks)})")
                
                # Ask AI to translate the command
                translated_cmd = self._translate_command_for_fallback(tool, next_tool, current_command)
                if translated_cmd:
                    current_command = translated_cmd
                    cmd_hash = hashlib.sha256(current_command.encode()).hexdigest()[:16]
                    self.log.info(f"[CYCLE RECOVERY] Translated command: {current_command} (New hash: {cmd_hash})")
                
                tool = next_tool
            else:
                self.log.warning(f"[CYCLE RECOVERY] No fallback defined for {tool}. Abandoning this approach.")
                return ToolResult(tool=tool, command=current_command, stdout="",
                                  stderr=f"Cycle detection: {tool} failed {cycle_count} times. Cannot recover.",
                                  exit_code=-1, duration_seconds=0, status=ResultStatus.BLOCKED)
        # ──────────────────────────────────────────────────────────────────
        
        # Record this command attempt (will be updated with final status after run)
        self._command_history[cmd_hash] = {"ts": now, "status": "running"}

        repair_count = 0
        max_repairs = 3
        last_result = None
        # Enforce minimum timeout for heavy scanners to prevent premature AI kill-switches
        heavy_tools = {"nmap", "gobuster", "ffuf", "nuclei", "sqlmap", "masscan", "feroxbuster", "wfuzz"}
        if tool.lower() in heavy_tools and timeout < 600:
            self.log.info(f"Escalating dangerously low AI timeout ({timeout}s) to 600s for heavy tool: {tool}")
            timeout = 600

        current_timeout = timeout
        timeout_cap = max(timeout * 4, timeout + 900)

        while True:
            if repair_count > 0:
                self.log.info(f"Repair attempt #{repair_count} for tool '{tool}'")

            if tool in VIRTUAL_TOOLS:
                command_to_run = current_command
                result = self.tools.run(
                    "ssh_cmd", command_to_run, self.name,
                    timeout=current_timeout, save_raw=True,
                    output_path=output_path, silent=silent
                )
            else:
                result = self.tools.run(
                    tool, current_command, self.name,
                    timeout=current_timeout, save_raw=True,
                    output_path=output_path, silent=silent
                )

            if result is None:
                self.log.error(f"Tool '{tool}' returned None - this should never happen.")
                result = ToolResult(
                    tool=tool, command=current_command, stdout="",
                    stderr="Tool manager returned None", exit_code=-2,
                    duration_seconds=0, status=ResultStatus.FAILURE
                )
                self._track_failure(result)
                return result

            if result.success:
                # Update dedup record: mark as succeeded so future identical commands are allowed
                self._command_history[cmd_hash] = {"ts": now, "status": ResultStatus.SUCCESS.value}
                if hasattr(self, "awareness"):
                    self.awareness.register_tool_outcome(current_command, "tool_execution", success=True)
                # Record in advisor for strategic learning
                if hasattr(self, "advisor") and self.advisor:
                    try:
                        self.advisor.record_tool_outcome(
                            tool=tool,
                            target=target or cmd_host or "unknown",
                            success=True,
                            duration=getattr(result, "duration_seconds", 0.0) or 0.0,
                            phase=self.name,
                        )
                    except Exception as _advisor_err:
                        self.log.debug(f"Advisor success record failed: {_advisor_err}")

                if tool.lower() in HTTP_TOOLS:
                    try:
                        recon_bundle = self.store.get_phase_data(
                            self.session.engagement_id, "recon"
                        ) if hasattr(self, 'store') and hasattr(self.session, 'engagement_id') else {}
                        waf_fingerprint = (recon_bundle or {}).get("waf_fingerprint") or {}
                        waf_present = (recon_bundle or {}).get("waf_present", False)
                        if waf_present or waf_fingerprint:
                            host_for_learning = cmd_host or self._extract_host(current_command) or target or "default"
                            if self._waf_ghost:
                                self._waf_ghost.feedback(host_for_learning, tool, blocked=False)
                            if self._waf_learner:
                                waf_id = "generic"
                                if isinstance(waf_fingerprint, dict):
                                    waf_id = waf_fingerprint.get("waf_type") or waf_fingerprint.get("id") or "generic"
                                self._waf_learner.update_tactic_effectiveness("header_mutation", True, waf_id=str(waf_id))
                    except Exception as _waf_learn_err:
                        self.log.debug(f"WAF learning success feedback error (non-fatal): {_waf_learn_err}")
                return result

            last_result = result
            if repair_count >= max_repairs:
                self._track_failure(last_result)
                if hasattr(self, "awareness"):
                    self.awareness.register_tool_outcome(current_command, "tool_execution", success=False)
                # Record in advisor for strategic learning
                if hasattr(self, "advisor") and self.advisor:
                    try:
                        self.advisor.record_tool_outcome(
                            tool=tool,
                            target=target or cmd_host or "unknown",
                            success=False,
                            duration=getattr(last_result, "duration_seconds", 0.0) or 0.0,
                            phase=self.name,
                        )
                    except Exception as _advisor_err:
                        self.log.debug(f"Advisor failure record failed: {_advisor_err}")
                return last_result

            if result.exit_code in NETWORK_UNFIXABLE_EXITS:
                self.log.warning(f"Unfixable network error for {tool} ({result.status}). Skipping repair.")
                self._track_failure(last_result)
                return last_result

            if self._should_rate_limit(result, cmd_host):
                self._wait_rate_limit(result, cmd_host)
                repair_count += 1
                continue

            if result.status not in (ResultStatus.FAILURE, "failed", ResultStatus.TIMEOUT, "timeout", ResultStatus.BLOCKED, "blocked", ResultStatus.ERROR, "error") or not should_retry(result):
                self._track_failure(last_result)
                return last_result

            if result.status in (ResultStatus.BLOCKED, "blocked"):
                # ── WAF EVASION ENGINE: activate learned evasion tactics on any block ──
                # WafEvasionEngine picks the best tactic based on recon fingerprint data.
                # Actual command mutation is handled by WafGhostEngine (the transformer).
                try:
                    recon_bundle = self.store.get_phase_data(
                        self.session.engagement_id, "recon"
                    ) if hasattr(self, 'store') and hasattr(self.session, 'engagement_id') else {}
                    waf_fingerprint = (recon_bundle or {}).get("waf_fingerprint") or {}
                    waf_present = (recon_bundle or {}).get("waf_present", False)
                    if waf_present or waf_fingerprint:
                        evasion_strategy = self._waf_evasion.build_evasion_strategy(
                            waf_fingerprint or {"waf_type": "generic", "block_frequency": 0.8}
                        )
                        tactic = (evasion_strategy.get("evasion_tactics") or ["header_mutation"])[0]
                        self._waf_evasion.rotate_tactic()
                        self.log.info(f"[WAF EVASION] Block detected. Applying tactic '{tactic}'. WAF: {waf_fingerprint.get('waf_type', 'generic')}")
                        try:
                            host_for_learning = cmd_host or self._extract_host(current_command) or target or "default"
                            if self._waf_ghost:
                                self._waf_ghost.feedback(host_for_learning, tool, blocked=True)
                            if self._waf_learner:
                                waf_id = "generic"
                                if isinstance(waf_fingerprint, dict):
                                    waf_id = waf_fingerprint.get("waf_type") or waf_fingerprint.get("id") or "generic"
                                self._waf_learner.update_tactic_effectiveness(str(tactic), False, waf_id=str(waf_id))
                        except Exception as _waf_block_learn_err:
                            self.log.debug(f"WAF learning block feedback error (non-fatal): {_waf_block_learn_err}")
                except Exception as _waf_evasion_err:
                    self.log.debug(f"WAF evasion engine error (non-fatal): {_waf_evasion_err}")

                # ── V6: WAF ORCHESTRATOR ESCALATION (Proactive Bypass) ──
                if hasattr(self, "_waf_orchestrator") and self._waf_orchestrator:
                    try:
                        self.log.info(f"[WAF ORCHESTRATOR] Block detected for {tool}. Escalating...")
                        # Only run if we haven't maxed out repairs for this specific command run
                        if repair_count < 2:
                            bypass_res = self._waf_orchestrator.execute_bypass(
                                self.session.engagement_id, target
                            )
                            
                            if bypass_res.get("success"):
                                bypass_url = bypass_res.get("bypass_url")
                                self.log.info(f"[WAF ORCHESTRATOR] Bypass SUCCEEDED via {bypass_res.get('strategy')}")
                                
                                # ── V6: PERSIST BYPASS TO STATE STORE ──
                                # This is critical: ensures subsequent tools adoption
                                try:
                                    recon_data = self.store.get_phase_data(self.session.engagement_id, "recon") or {}
                                    recon_data["waf_bypass_url"] = bypass_url
                                    recon_data["waf_bypass_strategy"] = bypass_res.get("strategy")
                                    self.store.set_phase_data(self.session.engagement_id, "recon", recon_data)
                                    self.log.info(f"[WAF PERSISTENCE] Persisted bypass URL {bypass_url} to StateStore.")
                                except Exception as _persist_err:
                                    self.log.debug(f"Failed to persist bypass: {_persist_err}")
                                    
                                if bypass_url:
                                    host_match = self._extract_host(current_command)
                                    if host_match and host_match.rstrip('/') != bypass_url.rstrip('/'):
                                        self.log.info(f"[WAF ORCHESTRATOR] Re-targeting retry: {host_match} -> {bypass_url}")
                                        escaped_host = re.escape(host_match)
                                        current_command = re.sub(
                                            r'(?<![a-zA-Z0-9/._:-])' + escaped_host + r'(?![a-zA-Z0-9._/-])',
                                            bypass_url.rstrip('/'),
                                            current_command,
                                        )
                                
                                repair_count += 1
                                continue
                            else:
                                self.log.warning(f"[WAF ORCHESTRATOR] Strategy '{bypass_res.get('strategy')}' failed. Escalating tier.")
                                self._waf_orchestrator.increment_evasion_tier(target)
                    except Exception as _orc_err:
                        self.log.debug(f"WAF orchestrator escalation error (non-fatal): {_orc_err}")

                if self._waf_ghost:
                    self.log.info("Command blocked. Escalating WafGhost mutation...")
                    current_command = self._waf_ghost.transform(current_command, tool)
                    repair_count += 1
                    continue

                # ── V6: AI-DRIVEN REPAIR (Final Failsafe) ──
                if self.ai and repair_count >= max_repairs - 1:
                    self.log.info(f"[AI REPAIR] Standard repairs failed for {tool}. Asking AI for creative mutation...")
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
                        ai_mutation = self.ai.query(system_prompt="You are an expert in WAF bypass and command-line tool optimization.", user_message=prompt)
                        if ai_mutation and ai_mutation.strip() and ai_mutation.strip() != current_command:
                            self.log.info(f"[AI REPAIR] AI suggested mutation: {ai_mutation.strip()}")
                            current_command = ai_mutation.strip()
                            repair_count += 1
                            continue
                    except Exception as _ai_err:
                        self.log.debug(f"AI repair failed: {_ai_err}")

            if self._stealth.get("rotate_ip") and self._ip_rotator and result.status in (ResultStatus.BLOCKED, "blocked"):
                self._ip_rotator.rotate(force=True)
                self.log.info("IP rotated due to block.")
                repair_count += 1
                continue

            # ── V6: TIMEOUT ESCALATION (if command timed out, automatically make it lighter) ──
            if result.status in (ResultStatus.TIMEOUT, "timeout"):
                tool_target_key = f"{tool}@{cmd_host or target or 'unknown'}"
                
                self._tool_failure_counts[tool_target_key] = self._tool_failure_counts.get(tool_target_key, 0) + 1
                
                fail_count = self._tool_failure_counts[tool_target_key]
                
                # Ban tool after 3 consecutive failures
                if fail_count >= 3:
                    self._tool_ban_list.add(tool_target_key)
                    self.log.warning(f"[TOOL BAN] {tool} banned for {cmd_host or target} after 3 timeouts.")
                    # ── V6 CROSS-PHASE PERSISTENCE: write ban to StateStore ──────────────
                    if self.store and self.session and hasattr(self.session, "engagement_id"):
                        try:
                            existing_bans: list = self.store.get(f"{self.session.engagement_id}:tool_bans") or []
                            if isinstance(existing_bans, str):
                                import json as _json
                                existing_bans = _json.loads(existing_bans)
                            if tool_target_key not in existing_bans:
                                existing_bans.append(tool_target_key)
                            import json as _json
                            self.store.set(f"{self.session.engagement_id}:tool_bans", _json.dumps(existing_bans))
                        except Exception as _ban_err:
                            self.log.debug(f"[TOOL BAN] Could not persist ban to store: {_ban_err}")
                    # ────────────────────────────────────────────────────────────────────
                    dur = getattr(result, "duration_seconds", getattr(result, "duration", 0.0))
                    return ToolResult(tool=tool, command=current_command, stdout="",
                                      stderr=f"Tool {tool} auto-banned: 3+ consecutive timeouts on this target",
                                      exit_code=-1, duration_seconds=dur, status=ResultStatus.BLOCKED)

                # Apply timeout escalation: make command lighter and increase timeout
                self.log.info(f"[TIMEOUT ESCALATION] Attempt #{fail_count} for {tool}. Making command lighter...")
                lighter_cmd = self._make_command_lighter(tool, current_command, fail_count)
                
                if lighter_cmd != current_command:
                    current_command = self._repair_common_tool_flags(tool, lighter_cmd)
                    current_command = self._canonicalize_tool_command(tool, current_command, target=target or cmd_host)
                    cmd_hash = hashlib.sha256(current_command.encode()).hexdigest()[:16]
                    self.log.info(f"[TIMEOUT ESCALATION] Reduced scope/flags: {current_command[:120]}... (New hash: {cmd_hash})")
                    current_timeout = min(timeout_cap, max(current_timeout + 60, int(current_timeout * 1.5)))
                else:
                    self.log.warning(f"[TIMEOUT ESCALATION] No lighter version available. Increasing timeout...")
                    current_timeout = min(timeout_cap, max(current_timeout + 120, int(current_timeout * 2)))
                
                # Update dedup record with TIMEOUT status so a lighter-version retry is allowed
                self._command_history[cmd_hash] = {"ts": now, "status": ResultStatus.TIMEOUT.value}
                # Track in history for AI awareness
                self._recent_failures.append(f"[TIMEOUT] {tool} on {cmd_host or target} (attempt {fail_count})")
                repair_count += 1
                continue

            # Ghost Protocol AI repair
            suggestion = self._ai_repair_tool(tool, current_command, result)
            if suggestion and suggestion != current_command:
                current_command = self._repair_common_tool_flags(tool, self._clean_command(suggestion))
                current_command = self._canonicalize_tool_command(tool, current_command, target=target or cmd_host)
                cmd_hash = hashlib.sha256(current_command.encode()).hexdigest()[:16]
                self.log.info(f"AI suggested command repair. (New hash: {cmd_hash})")
                repair_count += 1
                continue
            else:
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
            # Remove non-printable characters
            cleaned = re.sub(r'[^\x20-\x7E\n\t]', '', cmd.strip())

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
                    self.log.warning(f"[HARDEN] Rejected dangerous command pattern '{pattern}': {cleaned[:80]}")
                    return ""

            # Reject commands that try to exfiltrate to unknown external hosts
            # (allow our known VPS tools but block ad-hoc curl/wget to random IPs)
            EXFIL_PATTERN = r'(?:curl|wget)\s+.*?(?:\d{1,3}\.){3}\d{1,3}(?!.*(?:target|scope))'
            if re.search(EXFIL_PATTERN, cleaned, re.IGNORECASE):
                # Check if it's targeting our scope - if not, warn but allow (tools may use IPs)
                self.log.debug(f"[HARDEN] Potential external IP in command (non-fatal): {cleaned[:80]}")

            # Enforce max command length
            if len(cleaned) > 4096:
                self.log.warning(f"[HARDEN] Command too long ({len(cleaned)} chars), truncating.")
                cleaned = cleaned[:4096]

            return cleaned
        except Exception as e:
            self.log.error(f"[HARDEN] Command hardening failed: {e}")
            return ""

    def _should_rate_limit(self, result: ToolResult, host: str) -> bool:
        if not host:
            return False
        if result.status in (ResultStatus.RATE_LIMITED, ResultStatus.BLOCKED):
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
            r = requests.get(url, headers=headers, timeout=timeout, allow_redirects=True)
            length = len(r.content) if r.content is not None else 0
            return r.status_code, length, dict(r.headers or {})
        except Exception:
            return 0, 0, {}

    def _preflight_adjust_for_wildcard(self, tool: str, command: str, target: str) -> str:
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

        if lower not in ("gobuster", "ffuf"):
            return command

        # Prepare probe URLs
        try:
            ctx = TargetContext.from_input(target)
            base = ctx.base_url
        except Exception:
            base = target

        # Probe the base URL and a random non-existent path
        import uuid
        rand_path = str(uuid.uuid4())
        probe_base = base if base.endswith("/") else base + "/"
        probe_url_existing = probe_base
        probe_url_random = probe_base + rand_path

        st_base, len_base, _hbase = self._http_probe(probe_url_existing, timeout=6)
        st_rand, len_rand, _hrand = self._http_probe(probe_url_random, timeout=6)

        # Heuristic: if random path returns same status and similar length, it's wildcard
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
        self.log.info(f"[PREFLIGHT] Wildcard-like responses detected for {base} (st={st_base}, rand={st_rand}); adapting {lower} command.")

        # AI engine now explicitly injects `{WORDLIST}` templates which get translated to actual paths
        # in the agent loop. There is no need for `_harden_shell_cmd` to force wordlist overrides anymore.

        if lower == "gobuster":
            if " dir " in command:
                if "--wildcard" not in command:
                    command = f"{command} --wildcard"
                
                # If wildcard is an error code, simply blacklist it
                if st_rand in [403, 500, 503, 400]:
                    if "-b " in command:
                        command = re.sub(r'-b\s+([\d,]+)', f'-b \\1,{st_rand}', command)
                    else:
                        command += f" -b 404,{st_rand}"
                elif len_rand > 0:
                    # For 200 OK wildcards, exclude the exact lengths (±5 jitter instead of ±30 which crashes it)
                    exclude_lengths = ",".join(str(len_rand + d) for d in range(-5, 6) if (len_rand + d) > 0)
                    if "--exclude-length" not in command:
                        command += f" --exclude-length {exclude_lengths}"
            return command

        if lower == "ffuf":
            # Auto-calibrate and add wide size filter for WAF dynamic tokens
            new = re.sub(r'-t\s*\d+', '-t 5', command)
            if '-t' not in new:
                new += ' -t 5'
            if '-ac' not in new:
                new += ' -ac'
            if len_rand > 0 and '-fs' not in new and '-fc' not in new:
                min_len = max(1, len_rand - 30)
                max_len = len_rand + 30
                new += f' -fs {min_len}-{max_len}'
            return new

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
            self._host_rate_limits[host] = self._host_rate_limits.get(host, RATE_LIMIT_INITIAL_BACKOFF) * 2
            wait = min(self._host_rate_limits[host], RATE_LIMIT_MAX_BACKOFF)
        self.log.info(f"Rate limit detected on {host}. Waiting {wait}s...")
        _time_module.sleep(wait)

    def _post_scan_cooldown(self, scan_type: str) -> None:
        """
        Post-scan cooldown: wait after a heavy scan (e.g. Nuclei) to evade WAF/IPS.
        """
        if POST_HEAVY_SCAN_COOLDOWN > 0:
            agent_msg(self.name, f"WAF-Awareness: Heavy scan '{scan_type}' completed. Cooling down for {POST_HEAVY_SCAN_COOLDOWN}s to evade detection...")
            self.log.info(f"Post-scan cooldown for {scan_type}: {POST_HEAVY_SCAN_COOLDOWN}s")
            _time_module.sleep(POST_HEAVY_SCAN_COOLDOWN)

    def reset_context(self):
        """
        Implement Contextual Isolation.
        Clears short-term conversation context between discrete tasks
        to prevent LLM hallucination and context window overflow.
        """
        self.log.info(f"[{self.name}] Contextual isolation: resetting short-term memory.")
        self.session.clear_transient_context()

    def _extract_primary_tool(self, command: str) -> str | None:
        cmd = (command or "").strip()
        if not cmd:
            return None

        # Trim wrapper prefixes like "export ... && tool ..." or "VAR=1 && tool ..."
        parts = [p.strip() for p in re.split(r"\s*&&\s*", cmd) if p.strip()]
        while parts:
            head = parts[0]
            if head.startswith("export ") or re.match(r"^[A-Za-z_][A-Za-z0-9_]*=.*$", head):
                parts.pop(0)
                continue
            cmd = head
            break

        m = re.search(r'^(?:timeout\s+\d+\s+|sudo\s+)*([\w.-]+)', cmd, re.IGNORECASE)
        if not m:
            return None
        return m.group(1).lower()

    def _make_command_lighter(self, tool: str, command: str, attempt: int) -> str:
        """
        FIX #2.4: Timeout Escalation with SCOPE REDUCTION
        Progressive reduction of scanning scope instead of just slowing down.
        Tier 1: Remove options, Tier 2: Reduce counts, Tier 3: Break into subtasks
        """
        effective_tool = tool
        if tool in {"ai_dynamic_recon", "ssh_cmd", "remote_exec", "react_payload", "python", "python3"}:
            effective_tool = self._extract_primary_tool(command) or tool
        
        tier = min(3, attempt if attempt > 0 else 1)
        cmd = command

        if effective_tool == "nmap":
            if tier == 1:
                # Tier 1: Remove script scanning, keep version detection
                cmd = cmd.replace("-sC", "").replace("-sV -sC", "-sV")
                self.log.info(f"[ESCALATION T1] nmap: Removed script scanning")
            elif tier == 2:
                # Tier 2: Reduce port range dramatically (top 100 instead of 1000)
                cmd = cmd.replace("-p 1-1000", "-p 1-100").replace("-p 1-10000", "-p 1-1000")
                cmd = cmd.replace("-p 1-65535", "-p 1-100").replace("-p-", "-p 1-100")
                cmd = cmd.replace("-sV", "")  # Drop version detection
                self.log.info(f"[ESCALATION T2] nmap: Scanning only top 100 ports")
            elif tier >= 3:
                # Tier 3: Only scan web ports (80, 443)
                cmd = f"nmap -p 80,443 {re.search(r'nmap\s+(.+)', command).group(1) if re.search(r'nmap\s+(.+)', command) else ''}"
                self.log.info(f"[ESCALATION T3] nmap: Only scanning web ports (80,443)")

        elif effective_tool == "nuclei":
            if tier == 1:
                # Tier 1: Reduce concurrency
                cmd = cmd.replace("-c 50", "-c 5").replace("-c 20", "-c 2")
                if "-c " not in cmd: cmd += " -c 2"
                self.log.info(f"[ESCALATION T1] nuclei: Reduced concurrency to 2")
            elif tier == 2:
                # Tier 2: Single CVE year only
                cmd = re.sub(r'-t\s+cves/\d+', '-t cves/2024', cmd)
                self.log.info(f"[ESCALATION T2] nuclei: Only scanning 2024 CVEs")
            elif tier >= 3:
                # Tier 3: Single template only
                target_match = re.search(r'-u\s+([^\s]+)', command)
                target_arg = target_match.group(1) if target_match else "http://target"
                cmd = f"nuclei -u {target_arg} -t cves/2024/CVE-2024-1000 -silent"
                self.log.info(f"[ESCALATION T3] nuclei: Single known CVE scan only")

        elif effective_tool == "gobuster":
            if tier == 1:
                # Tier 1: Reduce threads
                cmd = cmd.replace("-t 50", "-t 5").replace("-t 20", "-t 5")
                if "-t " not in cmd: cmd += " -t 5"
                self.log.info(f"[ESCALATION T1] gobuster: Reduced threads to 5")
            elif tier == 2:
                # Tier 2: Add delay
                if "--delay" not in cmd: cmd += " --delay 500ms"
                self.log.info(f"[ESCALATION T2] gobuster: Added 500ms delay")
            elif tier >= 3:
                # Tier 3: Add WAF evasion headers instead of overriding AI wordlist
                if "-H" not in cmd: cmd += ' -H "X-Forwarded-For: 127.0.0.1"'
                self.log.info(f"[ESCALATION T3] gobuster: Applied strict WAF headers")

        elif effective_tool == "ffuf":
            if tier == 1:
                # Tier 1: Reduce delay
                cmd = cmd.replace("-d 0", "-d 100").replace("-p 0", "-p 100")
                if "-p " not in cmd: cmd += " -p 100"
                self.log.info(f"[ESCALATION T1] ffuf: Added delay between requests")
            elif tier == 2:
                # Tier 2: Reduce thread count
                cmd = cmd.replace("-t 40", "-t 5").replace("-t 50", "-t 5")
                if "-t " not in cmd: cmd += " -t 5"
                self.log.info(f"[ESCALATION T2] ffuf: Reduced threads to 5")
            elif tier >= 3:
                # Tier 3: Add WAF evasion headers instead of overriding AI wordlist
                if "-H" not in cmd: cmd += ' -H "X-Forwarded-For: 127.0.0.1"'
                self.log.info(f"[ESCALATION T3] ffuf: Applied strict WAF headers")

        elif effective_tool == "nikto":
            if tier == 1:
                # Tier 1: Reduce scan time
                cmd = cmd.replace("-maxtime 1h", "-maxtime 5m")
                self.log.info(f"[ESCALATION T1] nikto: Reduced time limit to 5m")
            elif tier == 2:
                # Tier 2: Skip SSL verification (faster)
                if "-nossl" not in cmd: cmd += " -nossl"
                self.log.info(f"[ESCALATION T2] nikto: Skipping SSL verification")
            elif tier >= 3:
                # Tier 3: Basic plugin check only
                host_match = re.search(r'-h\s+([^\s]+)', command)
                if host_match:
                    cmd = f"nikto -h {host_match.group(1)} -Tuning 1"
                    self.log.info(f"[ESCALATION T3] nikto: Basic checks only")

        elif effective_tool == "masscan":
            if tier == 1:
                # Tier 1: Reduce rate
                cmd = cmd.replace("--rate=1000", "--rate=100").replace("--rate=500", "--rate=100")
                self.log.info(f"[ESCALATION T1] masscan: Reduced rate to 100 pps")
            elif tier == 2:
                # Tier 2: Reduce port range
                cmd = cmd.replace("1-10000", "1-1000").replace("1-65535", "1-1000")
                self.log.info(f"[ESCALATION T2] masscan: Reduced port range to 1-1000")
            elif tier >= 3:
                # Tier 3: Only web ports
                cmd = re.sub(r'-p\s+[0-9,-]+', '-p 80,443,8080,8443', cmd)
                self.log.info(f"[ESCALATION T3] masscan: Only scanning web ports")

        return self._canonicalize_tool_command(effective_tool, cmd)


    def _build_evidence_context(self) -> str:
        """
        FIX #2.5: Build evidence-driven context with TYPE SAFETY
        Safely extracts findings from StateStore with null/type checking.
        Handles None, [], and "" uniformly.
        """
        if not self.store or not self.session or not hasattr(self.session, "engagement_id"):
            return ""
        
        try:
            evidence = []
            
            # ── Extract Recon Findings (with type safety) ──
            recon_data = self.store.get_phase_data(self.session.engagement_id, "recon")
            if recon_data and isinstance(recon_data, dict):
                # Type-safe port extraction
                ports = recon_data.get("open_ports")
                if ports and isinstance(ports, list):
                    port_strs = [str(p) for p in ports[:10] if isinstance(p, (int, str))]
                    if port_strs:
                        evidence.append(f"[RECON] Open ports: {', '.join(port_strs)}")
                
                # Type-safe tech stack
                tech_stack = recon_data.get("tech_stack")
                if tech_stack and isinstance(tech_stack, list):
                    tech_strs = [str(t) for t in tech_stack[:5] if isinstance(t, (str, dict))]
                    if tech_strs:
                        evidence.append(f"[RECON] Tech stack: {', '.join(tech_strs)}")
                
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
                        evidence.append(f"[RECON] Services: {', '.join(service_names)}")
                
                # Type-safe CVEs
                cves = recon_data.get("identified_cves")
                if cves and isinstance(cves, list) and len(cves) > 0:
                    evidence.append(f"[RECON] CVEs identified: {len(cves)} total")
            
            # ── Extract Weaponization Findings (with type safety) ──
            weapon_data = self.store.get_phase_data(self.session.engagement_id, "weaponization")
            if weapon_data and isinstance(weapon_data, dict):
                exploits = weapon_data.get("exploits_ready")
                if exploits and isinstance(exploits, list) and len(exploits) > 0:
                    evidence.append(f"[WEAPONIZATION] {len(exploits)} exploits prepared")
                
                payloads = weapon_data.get("payloads")
                if payloads and isinstance(payloads, list) and len(payloads) > 0:
                    evidence.append(f"[WEAPONIZATION] {len(payloads)} payloads available")
            
            # ── Extract Exploitation Findings (with type safety) ──
            exploit_data = self.store.get_phase_data(self.session.engagement_id, "exploitation")
            if exploit_data and isinstance(exploit_data, dict):
                successful = exploit_data.get("successful_exploits")
                if successful and isinstance(successful, list) and len(successful) > 0:
                    evidence.append(f"[EXPLOITATION] Successful exploits: {len(successful)}")
                    for exp in successful[:2]:
                        if isinstance(exp, dict):
                            cve_name = exp.get("cve") or exp.get("name", "unknown")
                            evidence.append(f"  - {cve_name}")
                
                shell_access = exploit_data.get("shell_access")
                if shell_access and isinstance(shell_access, dict) and shell_access.get("achieved") is True:
                    shell_type = shell_access.get("shell_type", "unknown")
                    evidence.append(f"[EXPLOITATION] Shell access: {shell_type}")
            
            # ── FIX 3.4: Sliding Window for Recent Findings ──
            # Cap findings to the last 100 to avoid O(n) performance degradation.
            # Format the last 20 for prompt size optimization.
            all_findings = self.store.get_all_findings(self.session.engagement_id) or []
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
                    evidence.append(f"[RECENT FINDINGS] (sliding window: last {len(unique_recent)} findings)")
                    for f in unique_recent:
                        evidence.append(
                            f"  - [{f.get('severity', 'info').upper()}] {f.get('type')}: "
                            f"{f.get('target')} -> {f.get('detail')[:100]}"
                        )
            
            # ── Extract Previous Phase Failures (with type safety) ──
            if hasattr(self, '_recent_failures') and isinstance(self._recent_failures, list):
                recent_fails = self._recent_failures[-5:]
                if recent_fails:
                    fail_strs = [str(f)[:80] for f in recent_fails[:3]]
                    evidence.append(f"[FAILURES] Recent: {'; '.join(fail_strs)}")
            
            return "\n".join(evidence) if evidence else ""
        except Exception as e:
            self.log.debug(f"Failed to build evidence context: {e}")
            return ""

    def _ai_repair_tool(self, tool: str, command: str, result: ToolResult) -> tuple[bool, str] | None:
        # V6: Enhanced prompt engineering with evidence context (FIX #9)
        err = (result.stderr or result.stdout or "Unknown error")[:300]
        
        is_timeout = result.status in (ResultStatus.TIMEOUT, "timeout")
        repair_tool = (self._extract_primary_tool(command) or tool or "").lower()
        
        # Build context-aware prompt with environment snapshot + evidence
        env_snapshot = self._get_environment_snapshot()
        env_context = f"--- RUNTIME ENVIRONMENT ---\n{env_snapshot}\n\n" if env_snapshot else ""
        
        # ── FIX #9: Inject Evidence Context ──
        evidence_context = self._build_evidence_context()
        evidence_section = f"--- PHASE EVIDENCE ---\n{evidence_context}\n\n" if evidence_context else ""
        
        # ── Check repair history (FIX #5): Learn from repeated failures ──
        cmd_hash = hashlib.sha256(command.encode()).hexdigest()[:16]
        repair_history = self._repair_attempts_history.get(cmd_hash, [])
        history_summary = ""
        if len(repair_history) >= 2:
            # Extract error patterns
            unique_errors = list(set([e[:80] for e in repair_history]))
            history_summary = f"\nThis command has failed {len(repair_history)} times with errors:\n"
            history_summary += "\n".join([f"  - {e}" for e in unique_errors[:3]])
            history_summary += "\nTry a fundamentally different approach (different tool, different scope, etc.)"
        
        if is_timeout:
            prompt = (
                f"{env_context}{evidence_section}CRITICAL: The previous command TIMED OUT after {result.duration:.0f}s.\n"
                f"Tool: {repair_tool}\nFailed command: {command}\n{history_summary}\n"
                f"REPAIR RULES:\n"
                f"- Do not return the same command or same breadth of scan.\n"
                f"- Prefer a lighter variant of the same tool first; if that is still risky, pick a different approved tool that can answer the same question.\n"
                f"- If the command is URL-like but the tool expects a host or host:port, normalize it accordingly.\n"
                f"- Preserve scope and target, but reduce concurrency, breadth, or template count.\n"
                f"- Use discovered evidence from previous phases to scope the scan (e.g., only scan open ports, only scan known tech).\n"
                f"- Use available runtime paths and wordlists from the environment snapshot instead of inventing paths.\n\n"
                f"IMPORTANT: Return the single best repaired command string only.\n"
                f"Previous failures to avoid: {self._recent_failures[-3:]}\n\n"
                f"Return ONLY the new command string, no explanation."
            )
        else:
            # Standard error repair (non-timeout)
            prompt = (
                f"{env_context}{evidence_section}Tool: {repair_tool}\nCommand: {command}\nError Output: {err}\n{history_summary}\n"
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
        if cmd_hash in self._command_history:
            prior = self._command_history[cmd_hash]
            # _command_history stores {ts: float, status: str} - extract ts safely
            prior_ts = prior["ts"] if isinstance(prior, dict) else float(prior)
            elapsed = _time_module.time() - prior_ts
            if elapsed < 300:
                self.log.warning("[AI REPAIR SKIPPED] Same command already tried recently.")
                # ── FIX #5: Track repair attempt in history ──
                self._repair_attempts_history[cmd_hash] = repair_history + [err]
                return None
        
        try:
            suggestion = self.ai.query("You are a pentest CLI repair assistant.", prompt)
            if suggestion and suggestion != command:
                import re
                cleaned = suggestion.strip()
                cleaned = re.sub(r"^```(?:bash|sh|cmd)?\s*", "", cleaned)
                cleaned = re.sub(r"\s*```$", "", cleaned.strip())
                # ── Repair-output dedup: skip if this exact repair was already tried ──
                # This closes the loop where two different original failures produce
                # the same AI suggestion. Without this, the repaired cmd fires again
                # because each original has a different input hash.
                repaired_hash = hashlib.sha256(cleaned.encode()).hexdigest()[:16]
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
            self.log.debug(f"Repair strategy failed for cmd hash {cmd_hash}: {_repair_err}")
        
        # ── FIX #5: Track all repair attempts for learning ──
        self._repair_attempts_history[cmd_hash] = repair_history + [err]
        return None

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
            self.log.warning("Prompt oversized; truncating user message.")
            user = user[:MAX_PROMPT - len(system) - 50] + "\n...[truncated]"
        try:
            return self.ai.query(system, user)
        except Exception as e:
            self.log.error(f"AI query failed: {e}")
            return ""

    def _compact_ai_context(self, text: str, max_chars: int, label: str) -> str:
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
        important = [line for line in lines if line and any(marker in line.lower() for marker in markers)]
        keep_each_side = max(15, min(50, len(lines) // 10 or 15))
        head = lines[:keep_each_side]
        tail = lines[-keep_each_side:] if len(lines) > keep_each_side else []

        chunks = [f"[{label} COMPRESSED: {len(text)} chars -> {max_chars} chars budget]"]
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
        return (
            f"### ENGAGEMENT CONTEXT\n{ctx}\n\n"
            f"### PREVIOUS ACTIONS\n{history}\n\n"
            f"### LATEST OBSERVATION\n{observation}\n\n"
            f"Based on the observation above, what should you do next?\n"
            f"Return either:\n"
            f"1. A JSON action: {{'capability': '...', 'target_url': '...', 'params': {{...}}, 'reason': '...'}}\n"
            f"2. A completion marker: {{'status': 'complete', 'summary': '...'}}\n"
        )

    def _execute_v6_action(self, action: ReActAction) -> str:
        cap_name = action.capability
        target_url = action.target_url
        params = action.params or {}

        risk_needed = RiskLevel(params.get("risk", "low"))
        destructive_ok = self.session.is_destructive_allowed() if hasattr(self.session, "is_destructive_allowed") else False
        tool = self.cap_reg.resolve(cap_name, risk_cap=risk_needed, destructive_allowed=destructive_ok)

        if not tool:
            ai_fallback = self.cap_reg.discover_custom_tool(cap_name)
            if ai_fallback:
                tool = ai_fallback
            else:
                return f"ERROR: No tool available for capability '{cap_name}'. Tried AI discovery - also failed."

        cmd = self._build_command_from_capability(tool, target_url, params)
        if not cmd:
            return f"ERROR: Could not build command for {tool.name} on {target_url}"

        if self._waf_ghost:
            cmd = self._waf_ghost.transform(cmd, tool.name, level=params.get("evasion_level", 1))

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
                f"FAILED: tool={tool.name} exit={result.exit_code} status={result.status}\n"
                f"STDERR: {result.stderr[:500]}\n"
                f"STDOUT: {result.stdout[:500]}"
            )

        dur = getattr(result, "duration_seconds", getattr(result, "duration", 0.0))
        obs = f"SUCCESS: tool={tool.name} duration={dur:.1f}s\n"
        if result.stdout:
            obs += f"OUTPUT:\n{result.stdout[:2000]}\n"
        if result.stderr:
            obs += f"ERRORS:\n{result.stderr[:500]}\n"
        self._auto_ingest(tool.name, target_url, result.stdout)
        return obs

    def _build_command_from_capability(self, tool, target_url: str, params: dict) -> str | None:
        t = tool.name
        p = params

        # ── Canonical URL and host extraction (never use raw .replace chains) ──
        try:
            tc = TargetContext.from_input(target_url)
            clean_url = tc.base_url        # e.g. https://target.com
            clean_host = tc.netloc          # e.g. target.com or target.com:8443
            clean_host_only = tc.host       # bare hostname/IP (no port)
        except Exception:
            # Absolute fallback - strip scheme manually
            clean_url = TargetContext.normalize_url(target_url)
            clean_host = re.sub(r"^https?://", "", clean_url).rstrip("/")
            clean_host_only = clean_host.split(":")[0]

        # ── VPS wordlist lookup ──────────────────────────────────────────
        def _wl(wl_type: str = "directory") -> str:
            vps_wl = config_paths.get_vps_wordlist(wl_type, ssh_executor=self._ssh)
            return vps_wl or p.get("wordlist") or f"{config_paths.VPS_TEMP_DIR}/ai_wordlist.txt"

        if t == "curl":
            return f"curl -sI --max-time {p.get('timeout', 10)} {shlex.quote(clean_url)}"
        if t == "nmap":
            ports = p.get("ports", "1-1000")
            flags = p.get("flags", "-sV -sC")
            return f"nmap {flags} -p {ports} {shlex.quote(clean_host)}"
        if t == "gobuster":
            wordlist = p.get("wordlist") or "{WORDLIST}"
            return f"gobuster dir -u {shlex.quote(clean_url)} -w {wordlist} -t 20 -q"
        if t == "ffuf":
            wordlist = p.get("wordlist") or "{WORDLIST}"
            fuzz_url = clean_url.rstrip("/") + "/FUZZ"
            return f"ffuf -u {shlex.quote(fuzz_url)} -w {wordlist} -mc 200,301,302,403 -ac -t 20"
        if t == "nuclei":
            sev = p.get("severity", "medium,high,critical")
            templates = p.get("templates") or self._nuclei_templates_path()
            return f"nuclei -t {templates} -u {shlex.quote(clean_url)} -severity {sev} -jsonl -silent -ni"
        if t == "subfinder":
            return f"subfinder -d {shlex.quote(clean_host_only)} -silent -all"
        if t == "dig":
            record = p.get("record", "A")
            return f"dig +short {record} {shlex.quote(clean_host_only)}"
        if t == "nikto":
            return f"nikto -h {shlex.quote(clean_url)} -maxtime {p.get('maxtime', 120)}"
        if t == "sqlmap":
            return f"sqlmap -u {shlex.quote(clean_url)} --batch --level=1 --risk=1"
        if t == "hydra":
            userlist = p.get("userlist") or _wl("usernames")
            passlist = p.get("passlist") or _wl("passwords")
            return f"hydra -L {shlex.quote(userlist)} -P {shlex.quote(passlist)} ssh://{shlex.quote(clean_host_only)} -t 4 -f -q"
        if t == "sslscan":
            return f"sslscan {shlex.quote(clean_host_only)}"
        if t == "whatweb":
            return f"whatweb {shlex.quote(clean_url)} -a 3"
        if t == "wafw00f":
            return f"wafw00f {shlex.quote(clean_url)}"
        if t == "theharvester":
            return f"theHarvester -d {shlex.quote(clean_host_only)} -b all"
        if t == "masscan":
            return f"sudo masscan {shlex.quote(clean_host_only)} -p1-10000 --rate=1000"
        if t == "wfuzz":
            wordlist = p.get("wordlist") or _wl("directory")
            fuzz_url = clean_url.rstrip("/") + "/FUZZ"
            return f"wfuzz -c -z file,{shlex.quote(wordlist)} --hc 404 {shlex.quote(fuzz_url)}"
        if t == "amass":
            return f"amass enum -passive -d {shlex.quote(clean_host_only)} -timeout 5"
        if t == "httpx":
            return f"echo {shlex.quote(clean_host_only)} | httpx -silent -status-code -title -tech-detect"
        if t == "feroxbuster":
            wordlist = p.get("wordlist") or _wl("directory")
            return f"feroxbuster -u {shlex.quote(clean_url)} -w {shlex.quote(wordlist)} -q --no-state"
        if "raw_command" in p:
            return p["raw_command"]
        self.log.warning(f"No command builder for tool '{t}'. Params: {p}")
        return None


    def _auto_ingest(self, tool_name: str, target_url: str, stdout: str) -> None:
        ctx = self.session.target_context if hasattr(self.session, "target_context") else None
        if not ctx:
            return
        text = stdout.lower()
        for match in re.findall(r'([a-z0-9][-a-z0-9]*\.[a-z0-9][-a-z0-9]*\.[a-z]{2,})', stdout):
            if match != ctx.host and ctx.host in match:
                ctx.add_subdomain(match)
                self.add_finding("subdomain", match, f"Discovered via {tool_name}", "info")
        for path_match in re.findall(r'(\/[-a-zA-Z0-9_./]+\.(php|asp|aspx|jsp|json|xml|yaml|env))', stdout):
            ctx.add_endpoint(path_match[0])
        for auth_path in re.findall(r'(/(?:login|signin|auth|admin|wp-login|api/auth)[^\s\"\'<>]*)', stdout, re.IGNORECASE):
            ctx.add_auth_endpoint(auth_path.rstrip("/"))
            self.add_finding("auth_endpoint", f"{ctx.base_url}{auth_path.rstrip('/')}", f"Detected via {tool_name}", "medium")
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
        if any(k in text for k in ("cloudflare", "akamai", "incapsula", "sucuri", "fortinet", "barracuda")):
            ctx.waf_detected = True
            for waf in ("cloudflare", "akamai", "incapsula", "sucuri", "fortinet", "barracuda"):
                if waf in text:
                    ctx.waf_type = waf.title()
                    break
        for port_match in re.findall(r'(\d+)/(tcp|udp)\s+open', stdout):
            ctx.add_endpoint(f":{int(port_match[0])}")

    def _get_target_context_json(self) -> str:
        ctx = self.session.target_context if hasattr(self.session, "target_context") else None
        if ctx:
            return ctx.to_json(indent=0)
        return "{}"

    def _format_history(self) -> str:
        lines = []
        for h in self._react_history[-5:]:
            if "action" in h:
                a = h["action"]
                lines.append(f"- Action: {a.get('capability')} on {a.get('target_url')} -> {a.get('result_summary', '?')}")
            elif "observation" in h:
                obs = str(h.get("observation", ""))[:200]
                lines.append(f"  Observation: {obs}...")
        return "\n".join(lines) if lines else "No prior actions."

    def _compile_phase_result(self) -> dict:
        return {
            "phase": self.name,
            "findings_count": len(self._findings),
            "iterations": len(self._react_history),
            "findings": self._findings,
            "target_context": self.session.target_context.to_dict() if hasattr(self.session, "target_context") else {},
        }

    def run_react(self) -> dict:
        """V6 ReAct loop. Subclasses should call this if they want AI-driven exploration."""
        self.store.set_phase_status(self.session.engagement_id, self.name, "running")
        iteration = 0
        consecutive_failures = 0
        system_prompt, user_prompt = self._build_initial_prompt()

        while iteration < self._max_react_iterations:
            iteration += 1
            self.log.info(f"[{self.name}] ReAct iteration {iteration}/{self._max_react_iterations}")
            ai_response = self._query_ai(system_prompt, user_prompt)
            if not ai_response:
                break
            parsed = self._parse_ai_response(ai_response)
            if isinstance(parsed, dict) and parsed.get("status") in ("complete", "done", "finished"):
                self._react_history.append({"iteration": iteration, "type": "completion", "data": parsed})
                break
            if isinstance(parsed, ReActAction):
                if not self._is_action_allowed(parsed):
                    obs = f"BLOCKED: Capability '{parsed.capability}' not permitted."
                    self._react_history.append({"iteration": iteration, "action": parsed.to_dict(), "observation": obs})
                    user_prompt = self._build_observation_prompt(obs)
                    continue
                self._react_history.append({"iteration": iteration, "action": parsed.to_dict()})
                observation = self._execute_v6_action(parsed)
                if "ERROR" in observation or "FAILED" in observation:
                    consecutive_failures += 1
                    if consecutive_failures >= self._max_repeat_failures:
                        observation += (
                            "\n\n[SYSTEM HINT] You have failed repeatedly. CHANGE STRATEGY. "
                            "Do not repeat the same tool.")
                else:
                    consecutive_failures = 0
                self._react_history[-1]["observation"] = observation
                user_prompt = self._build_observation_prompt(observation)
                continue
            break

        result = self._compile_phase_result()
        self.store.set_phase_status(self.session.engagement_id, self.name, "complete", json.dumps(result, default=str)[:500])
        self.flush_dedup_stats()
        return result

    def _is_action_allowed(self, action: ReActAction) -> bool:
        roe = self.session.rules_of_engagement if hasattr(self.session, "rules_of_engagement") else {}
        if action.capability in ("sql_injection_test", "credential_brute") and not roe.get("allow_exploitation"):
            return False
        tool = self.cap_reg.resolve(action.capability, destructive_allowed=True)
        if tool and tool.risk == RiskLevel.DESTRUCTIVE:
            if not self.session.is_destructive_allowed():
                return False
        return True

    # ═══════════════════════════════════════════════════════════════════
    # REQUIRED BY ORCHESTRATOR - backward-compat default
    # ═══════════════════════════════════════════════════════════════════
    def _get_environment_snapshot(self) -> str:
        """
        VPS-AWARE environment snapshot. Clearly separates:
          - LOCAL paths  (where this Python process runs - Windows)
          - REMOTE paths (where all SSH commands execute - Linux VPS)

        Provides the AI with verified tool availability, wordlists, and
        failure pattern warnings so it never generates paths for the wrong
        machine or repeats commands that are already known to fail.
        """
        try:
            lines = []

            # ── 1. Execution Architecture ─────────────────────────────────
            lines.append("=== EXECUTION ARCHITECTURE ===")
            lines.append("LOCAL  (Python/orchestrator): Windows - DO NOT USE local paths in tool commands.")
            lines.append("REMOTE (SSH/tool execution):  Linux VPS - ALL tool commands run here via SSH.")
            lines.append("RULE: Every command you generate is executed on the REMOTE VPS, not locally.")

            # ── 2. Target Context ─────────────────────────────────────────
            if hasattr(self, "session") and getattr(self.session, "target", None):
                try:
                    tc = TargetContext.from_input(self.session.target)
                    lines.append(f"\n=== TARGET ===")
                    lines.append(f"Base URL  : {tc.base_url}")
                    lines.append(f"Host/IP   : {tc.netloc}")
                    lines.append(f"Full URL  : {tc.full_url}")
                    lines.append(f"Tech Stack: {', '.join(tc.tech_stack) or 'unknown'}")
                    if tc.waf_detected:
                        lines.append(f"WAF       : {tc.waf_type or 'detected'} - use evasion flags")
                except Exception as _tc_err:
                    self.log.debug(f"TargetContext error: {_tc_err}")

            # ── 3. Remote VPS Paths (what matters for command generation) ─
            lines.append("\n=== REMOTE VPS PATHS (use these in all commands) ===")
            lines.append(f"  Tool base      : {config_paths.VPS_TOOL_PATH}")
            lines.append(f"  Temp/work dir  : {config_paths.VPS_TEMP_DIR}/")
            lines.append(f"  Buffer logs    : {config_paths.VPS_TEMP_DIR}/buffers/")
            lines.append(f"  Results output : {config_paths.VPS_RESULTS_DIR}/")

            # ── 4. Verified VPS Wordlists (live-checked) ──────────────────
            lines.append("\n=== REMOTE WORDLISTS (verified on VPS) ===")
            wl_found = False
            for wl_type in ("directory", "common", "passwords", "subdomains"):
                vps_wl = config_paths.get_vps_wordlist(wl_type, ssh_executor=self._ssh)
                if vps_wl:
                    lines.append(f"  {wl_type:<12}: {vps_wl}")
                    wl_found = True
            if not wl_found:
                lines.append(f"  WARNING: No standard wordlists found - use {config_paths.VPS_TEMP_DIR}/ai_wordlist.txt")
                lines.append(f"  To provision: 'mkdir -p {config_paths.VPS_TEMP_DIR} && echo admin > {config_paths.VPS_TEMP_DIR}/ai_wordlist.txt'")

            # ── 5. Tool Availability (live VPS check for critical tools) ──
            lines.append("\n=== TOOL AVAILABILITY (remote VPS) ===")
            critical_tools = [
                "nmap", "gobuster", "ffuf", "nuclei", "subfinder",
                "nikto", "sqlmap", "hydra", "wfuzz", "amass",
                "whatweb", "wafw00f", "dirsearch", "httpx", "feroxbuster",
            ]
            if self._ssh:
                available_tools = []
                missing_tools = []
                try:
                    # Batch check with a single SSH call for efficiency
                    check_cmds = " && ".join(
                        f"(which {t} > /dev/null 2>&1 && echo 'FOUND:{t}' || echo 'MISSING:{t}')"
                        for t in critical_tools
                    )
                    ec, out, _ = self._ssh.execute(check_cmds, timeout=TOOL_VERIFY_TIMEOUT)
                    for line in out.splitlines():
                        if line.startswith("FOUND:"):
                            available_tools.append(line[6:].strip())
                        elif line.startswith("MISSING:"):
                            missing_tools.append(line[8:].strip())
                except Exception:
                    available_tools = []
                    missing_tools = critical_tools

                if available_tools:
                    lines.append(f"  Available : {', '.join(available_tools)}")
                if missing_tools:
                    lines.append(f"  MISSING   : {', '.join(missing_tools)}")
                    lines.append("  RULE: Do NOT use missing tools - pick an available alternative.")
            else:
                lines.append("  (SSH not connected - cannot verify tool availability)")

            # ── 6. Tool Effectiveness (from tracker) ──────────────────────
            if hasattr(self, "tool_tracker"):
                try:
                    summary = self.tool_tracker.summarize_effectiveness()
                    if summary:
                        lines.append("\n=== TOOL EFFECTIVENESS (this session) ===")
                        for tool, score in list(summary.items())[:8]:
                            bar = "[+]" if score >= 0.5 else "[x]"
                            lines.append(f"  {bar} {tool:<16}: {score:.0%}")
                except Exception as _eff_err:
                    self.log.debug(f"Tool effectiveness summary unavailable: {_eff_err}")

            # ── 7. Known Failure Patterns (inject from history) ───────────
            if self._recent_failures:
                lines.append("\n=== KNOWN FAILURE PATTERNS (do NOT repeat these) ===")
                for snippet in self._recent_failures[-8:]:
                    lines.append(f"  [!] {snippet}")

            # ── 8. Banned tools for this session ─────────────────────────
            if self._tool_ban_list:
                banned_str = ", ".join(sorted(self._tool_ban_list)[:10])
                lines.append(f"\n=== SESSION-BANNED TOOLS ===")
                lines.append(f"  DO NOT USE: {banned_str}")

            return "\n".join(lines)

        except Exception as e:
            self.log.debug(f"Environment snapshot error: {e}")
            return (
                "=== EXECUTION ARCHITECTURE ===\n"
                "LOCAL: Windows (Python). REMOTE: Linux VPS (all tool commands).\n"
                "RULE: Generate commands for the Linux VPS only - never use Windows paths."
            )


    def think(self, prompt: str, system: str = "You are an expert offensive security AI assistant. Be concise and actionable.") -> str:
        """Convenience wrapper for AI query used by all legacy agents."""
        try:
            # Inject autonomous environment snapshot
            env_snapshot = self._get_environment_snapshot()
            if env_snapshot:
                env_snapshot = self._compact_ai_context(env_snapshot, 6000, "ENVIRONMENT")
                prompt = f"--- RUNTIME ENVIRONMENT ---\n{env_snapshot}\n\n--- TASK ---\n{prompt}"
            
            # Inject self-awareness context if available
            if hasattr(self, "awareness"):
                report = self.awareness.get_confidence_report()
                report = self._compact_ai_context(report, 4000, "SELF-AWARENESS")
                prompt = f"--- SYSTEM SELF-AWARENESS ---\n{report}\n\n{prompt}"
            
            # Inject strategic knowledge from previous engagements
            if hasattr(self, "advisor"):
                kb_report = self.advisor.get_confidence_report()
                kb_report = self._compact_ai_context(kb_report, 4000, "STRATEGIC KB")
                prompt = f"--- STRATEGIC KNOWLEDGE BASE ---\n{kb_report}\n\n{prompt}"

            prompt = self._compact_ai_context(prompt, 16000, "TASK")
            
            return self.ai.query(system, prompt)
        except Exception as e:
            self.log.error(f"AI think() failed: {e}")
            return ""

    def _preflight(self) -> tuple[bool, str]:
        """Default preflight: subclasses may override. Returns (can_proceed, reason)."""
        return True, ""
