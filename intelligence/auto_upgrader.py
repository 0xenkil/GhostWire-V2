"""
Auto-Upgrader - Master coordinator for system auto-upgrade process

Orchestrates:
1. Engagement Analysis
2. Heuristic Optimization
3. Rule Generation
4. Safe Application of Changes
5. Validation and Rollback Capability
"""

import json
import os
from datetime import datetime
from typing import Dict, List, Any

from .engagement_analyzer import EngagementAnalyzer
from .heuristic_optimizer import HeuristicOptimizer
from .rule_generator import RuleGenerator


class AutoUpgrader:
    """Master orchestrator for system auto-upgrade"""

    def __init__(self, store=None, config_dir: str = None,
                 rules_dir: str = None):
        """
        Initialize auto-upgrader

        Args:
            store: State store reference for reading engagement data
            config_dir: Path to config directory
            rules_dir: Path to rules directory
        """
        self.store = store
        self.config_dir = config_dir or os.path.join(
            os.path.dirname(__file__), "..")
        self.rules_dir = rules_dir or os.path.join(self.config_dir, "rules")
        self.backup_dir = os.path.join(
            os.path.dirname(__file__), ".upgrades_backup")

        self.analyzer = EngagementAnalyzer(store)
        self.optimizer = HeuristicOptimizer(self.config_dir)
        self.rule_gen = RuleGenerator(self.rules_dir)

        self.upgrade_log = []

    def run_incremental_upgrade(
            self, engagement_id: str, after_phase: str = None) -> Dict[str, Any]:
        """Wrapper for incremental upgrades mid-engagement.

        P3-5: runs as DRY-RUN. Application is additionally gated by the TruthGate
        inside _validate_changes (fail-closed), so this belt-and-suspenders flip
        just makes the intent explicit — mid-engagement is exactly when the
        proven slice is smallest and a self-modification is least justified."""
        print(
            f"[AUTO-UPGRADE] Triggering incremental upgrade (dry-run) after phase: {after_phase}")
        return self.run_system_upgrade(engagement_id, dry_run=True)

    def register_new_tool(self, name: str, config: dict) -> Dict[str, Any]:
        """
        Register and serialize a new custom tool.

        Args:
            name: Tool name
            config: Tool configuration dict

        Returns:
            Dict containing registration status
        """
        import config_paths
        from tools.tool_registry import register_tool

        try:
            custom_dir = config_paths.CUSTOM_TOOLS_DIR
            custom_dir.mkdir(parents=True, exist_ok=True)

            tool_path = custom_dir / f"{name}.json"
            tool_data = {name: config}

            with open(tool_path, "w", encoding="utf-8") as f:
                json.dump(tool_data, f, indent=4)

            # Register it in the current runtime
            register_tool(name, config)

            print(f"[AUTO-UPGRADE] Persisted new tool '{name}' to {tool_path}")
            self._log_upgrade_event({
                "type": "new_tool_registered",
                "tool": name,
                "timestamp": datetime.now().isoformat()
            })

            return {"status": "success", "tool": name, "path": str(tool_path)}
        except Exception as e:
            print(f"[AUTO-UPGRADE] Failed to register tool '{name}': {e}")
            return {"status": "error", "error": str(e)}

    def run_system_upgrade(self, engagement_id: str,
                           dry_run: bool = False) -> Dict[str, Any]:
        """
        Execute full system upgrade pipeline

        Args:
            engagement_id: ID of engagement to learn from
            dry_run: If True, don't apply changes, just show what would happen

        Returns:
            Upgrade results and what was changed
        """
        upgrade_result = {
            "engagement_id": engagement_id,
            "timestamp": datetime.now().isoformat(),
            "dry_run": dry_run,
            "status": "running",
            "phases": {},
            "changes_applied": [],
            "changes_rejected": [],
            "validation_errors": [],
            "rollback_capability": False
        }

        try:
            # Phase 1: Analyze Engagement
            print(
                f"[AUTO-UPGRADE] Phase 1: Analyzing engagement {engagement_id}...")
            insights = self.analyzer.analyze_engagement(engagement_id)
            upgrade_result["phases"]["analysis"] = {
                "status": "complete",
                "insights_extracted": len(insights.get("patterns_discovered", [])),
                "findings_count": len(insights.get("findings_confirmed", []))
            }

            # Phase 2: Generate Optimizations
            print("[AUTO-UPGRADE] Phase 2: Generating optimizations...")
            optimizations = self.optimizer.optimize_from_insights(insights)
            upgrade_result["phases"]["optimization"] = {
                "status": "complete",
                "tool_adjustments": len(optimizations.get("changes", {}).get("tool_effectiveness", {}).get("tool_rates_adjusted", {})),
                "timeout_changes": len(optimizations.get("changes", {}).get("timeouts", {}).get("timeout_adjustments", {}))
            }

            # Phase 3: Generate Rules
            print("[AUTO-UPGRADE] Phase 3: Generating rules...")
            rules_package = self.rule_gen.generate_rules_from_insights(
                insights)
            upgrade_result["phases"]["rule_generation"] = {
                "status": "complete",
                "exploitation_rules": len(rules_package.get("rules", {}).get("exploitation", [])),
                "infrastructure_rules": len(rules_package.get("rules", {}).get("infrastructure", []))
            }

            # Phase 4: Validate Changes
            print("[AUTO-UPGRADE] Phase 4: Validating changes...")
            validation = self._validate_changes(
                optimizations, rules_package, engagement_id)
            upgrade_result["validation_errors"] = validation.get("errors", [])
            upgrade_result["phases"]["validation"] = {
                "status": "complete",
                "valid_changes": validation.get("valid_changes", 0),
                "rejected_changes": validation.get("rejected_changes", 0)
            }

            # Phase 5: Apply Changes (if not dry run and valid)
            if not dry_run and validation.get("valid_changes", 0) > 0:
                print("[AUTO-UPGRADE] Phase 5: Applying changes...")
                applied = self._apply_changes(
                    optimizations, rules_package, engagement_id)
                upgrade_result["phases"]["application"] = applied
                upgrade_result["changes_applied"] = applied.get("applied", [])
                upgrade_result["changes_rejected"] = applied.get(
                    "rejected", [])
                upgrade_result["rollback_capability"] = applied.get(
                    "rollback_capability", False)
            else:
                upgrade_result["phases"]["application"] = {
                    "status": "skipped",
                    "reason": "dry_run" if dry_run else "no_valid_changes"
                }

            upgrade_result["status"] = "complete"

        except Exception as e:
            upgrade_result["status"] = "error"
            upgrade_result["error"] = str(e)
            print(f"[AUTO-UPGRADE] ERROR: {str(e)}")

        # Save upgrade record
        self._save_upgrade_record(upgrade_result)

        return upgrade_result

    def _proven_outcomes(self, engagement_id: str):
        """P3-5: reconstruct PROOF-BACKED learning outcomes for an engagement from
        the durable ProofLedger (store.get_evidence_objects), so TruthGate judges
        a self-upgrade on real re-measured proof — never a schema/`status` check.

        NOTE: this is per-engagement. A single engagement's proven slice is
        under-powered, so TruthGate will (correctly) fail-closed and the apply
        path stays inert-but-non-corrupting until a CROSS-engagement proven-outcome
        ledger is fed in here — an explicit, reversible choice (§P3-5 v1.1), not a
        permanent capability loss. Wire that ledger to this one method to re-enable
        safe application."""
        outcomes = []
        try:
            from intelligence.learning_signal import LearningOutcome
            from core.result_contracts import Evidence
            evs = self.store.get_evidence_objects(engagement_id) if self.store else []
            for obj in evs or []:
                try:
                    ev = Evidence.from_dict(obj.get("evidence") or {})
                except Exception:
                    continue
                outcomes.append(LearningOutcome.from_confirmed_hypothesis(
                    tool=str(obj.get("vuln_class") or "unknown"), proof=ev))
        except Exception as _e:
            import logging
            logging.getLogger(__name__).debug(
                f"[P3-5] proven-outcome reconstruction skipped: {_e}")
        return outcomes

    def _validate_changes(
            self, optimizations: Dict[str, Any], rules_package: Dict[str, Any],
            engagement_id: str = None) -> Dict[str, Any]:
        """
        Validate that changes are safe to apply.

        P3-5: the final gate is a TruthGate — a persistent self-upgrade is only
        admitted when backed by proof-backed outcomes whose held-out proven-rate
        does not regress. If it cannot be evaluated (the common case today, absent
        a cross-engagement proven ledger) it FAILS CLOSED: valid_changes is zeroed
        so the apply path is skipped. Analysis/reporting are unaffected.

        Returns validation results
        """
        validation = {
            "errors": [],
            "valid_changes": 0,
            "rejected_changes": 0,
            "truth_gated": False,
        }

        try:
            # Check tool effectiveness changes don't break critical tools
            tool_changes = optimizations.get(
                "changes", {}).get(
                "tool_effectiveness", {})
            for tool, rate_info in tool_changes.get(
                    "tool_rates_adjusted", {}).items():
                if rate_info.get("recommendation") == "never_works":
                    if tool in ["curl", "nuclei"]:  # Critical tools
                        validation["errors"].append(
                            f"Cannot disable critical tool: {tool}")
                        validation["rejected_changes"] += 1
                    else:
                        validation["valid_changes"] += 1
                else:
                    validation["valid_changes"] += 1

            # Check timeout changes are reasonable
            timeout_changes = optimizations.get(
                "changes", {}).get("timeouts", {})
            for phase, timing_info in timeout_changes.get(
                    "timeout_adjustments", {}).items():
                timeout = timing_info.get("suggested_timeout", 0)
                if timeout > 3600:  # > 1 hour
                    validation["errors"].append(
                        f"Timeout for {phase} unreasonably high: {timeout}s")
                    validation["rejected_changes"] += 1
                else:
                    validation["valid_changes"] += 1

            # Check rules don't conflict
            all_rules = []
            for rule_type in ["exploitation",
                              "infrastructure", "recon", "weaponization"]:
                all_rules.extend(
                    rules_package.get(
                        "rules",
                        {}).get(
                        rule_type,
                        []))

            rule_ids = [r.get("id") for r in all_rules]
            if len(rule_ids) != len(set(rule_ids)):
                validation["errors"].append("Duplicate rule IDs detected")
                validation["rejected_changes"] += 1
            else:
                validation["valid_changes"] += len(all_rules)

        except Exception as e:
            validation["errors"].append(f"Validation error: {str(e)}")

        # P3-5 TRUTH GATE (fail-closed): a persistent self-upgrade must be backed
        # by proof, not just be schema-valid. If TruthGate cannot admit the change
        # set — no proof-backed outcomes, or a held-out proven-rate regression, or
        # simply unevaluable — zero out valid_changes so Phase-5 application is
        # skipped for EVERY caller (dry_run or not). This is what makes the apply
        # path inert-but-non-corrupting today; it re-opens automatically once
        # `_proven_outcomes` is fed a cross-engagement proven ledger.
        if validation["valid_changes"] > 0:
            try:
                from intelligence.truth_gate import TruthGate
                gate = TruthGate(self._proven_outcomes(engagement_id))
                change_set = {"tool_effectiveness": (optimizations or {}).get(
                    "changes", {}).get("tool_effectiveness", {})}
                if not gate.supports(change_set):
                    validation["truth_gated"] = True
                    validation["rejected_changes"] += validation["valid_changes"]
                    validation["valid_changes"] = 0
                    validation["errors"].append(
                        "TruthGate: change set not backed by non-regressing proven "
                        "outcomes — held as dry-run (no application).")
            except Exception as _tg_e:
                # Fail CLOSED on any gate error — never apply on an unevaluable gate.
                validation["truth_gated"] = True
                validation["rejected_changes"] += validation["valid_changes"]
                validation["valid_changes"] = 0
                validation["errors"].append(f"TruthGate unavailable, failing closed: {_tg_e}")

        return validation

    def _apply_changes(
            self, optimizations: Dict[str, Any], rules_package: Dict[str, Any], engagement_id: str) -> Dict[str, Any]:
        """
        Apply changes to system files with backup capability

        Returns what was applied
        """
        results = {
            "applied": [],
            "rejected": [],
            "rollback_capability": True
        }

        try:
            # Create backup directory
            backup_timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            engagement_backup = os.path.join(
                self.backup_dir, f"{engagement_id}_{backup_timestamp}")
            os.makedirs(engagement_backup, exist_ok=True)

            # 1. Save optimization insights
            insights_file = os.path.join(
                engagement_backup, "optimizations.json")
            with open(insights_file, "w") as f:
                json.dump(optimizations, f, indent=2)
            results["applied"].append(
                "Saved optimization insights for rollback")

            # 2. Save generated rules
            rules_file = os.path.join(
                engagement_backup, "generated_rules.json")
            with open(rules_file, "w") as f:
                json.dump(rules_package, f, indent=2)
            results["applied"].append("Saved generated rules for rollback")

            # P3-5: the _update_tool_metrics write is DELETED. It merged
            # optimizer `tool_rates_adjusted` (derived from the pre-P0-9 bare
            # status==success signal) into a persisted tool_metrics.json that no
            # live code read back — an inert write that could only corrupt future
            # learning. Proof-anchored effectiveness now lives in the engagement
            # analyzer (P3-2); there is no separate metrics file to poison.

            # 4. Save rule recommendations (advisory, not applied directly)
            recommendations = optimizations.get("recommendations", [])
            if recommendations:
                rec_file = os.path.join(
                    engagement_backup, "rule_recommendations.json")
                with open(rec_file, "w") as f:
                    json.dump(recommendations, f, indent=2)
                results["applied"].append(
                    f"Saved {len(recommendations)} rule recommendations")

            # 5. Log upgrade
            self._log_upgrade_event({
                "engagement_id": engagement_id,
                "timestamp": datetime.now().isoformat(),
                "backup_location": engagement_backup,
                "changes_applied": len(results["applied"]),
                "status": "success"
            })

        except Exception as e:
            results["rejected"].append(f"Change application error: {str(e)}")
            results["rollback_capability"] = False

        return results

    def _save_upgrade_record(self, upgrade_result: Dict[str, Any]) -> None:
        """Save upgrade record for auditing and rollback"""
        record_file = os.path.join(
            self.backup_dir,
            f"upgrade_{upgrade_result['engagement_id']}.json"
        )
        os.makedirs(os.path.dirname(record_file), exist_ok=True)

        with open(record_file, "w") as f:
            json.dump(upgrade_result, f, indent=2)

    def _log_upgrade_event(self, event: Dict[str, Any]) -> None:
        """Log upgrade event for monitoring"""
        log_file = os.path.join(self.backup_dir, "upgrade_log.json")

        # Load existing log
        log = []
        if os.path.exists(log_file):
            try:
                with open(log_file, "r") as f:
                    log = json.load(f)
            except Exception as _e:
                import logging
                logging.getLogger(__name__).debug(
                    f'Swallowed exception in auto_upgrader.py: {_e}')

        # Append new event
        log.append(event)

        # Save updated log
        with open(log_file, "w") as f:
            json.dump(log, f, indent=2)

    def rollback_to_engagement(self, engagement_id: str) -> Dict[str, Any]:
        """
        Rollback system to state before an upgrade

        Args:
            engagement_id: ID of engagement to rollback

        Returns:
            Rollback results
        """
        results = {
            "status": "searching",
            "engagement_id": engagement_id,
            "rollback_data_found": False,
            "restored": []
        }

        try:
            # Find backup directory
            if not os.path.exists(self.backup_dir):
                results["status"] = "not_found"
                return results

            backups = [
                d for d in os.listdir(
                    self.backup_dir) if d.startswith(engagement_id)]

            if not backups:
                results["status"] = "not_found"
                return results

            # Use most recent backup
            latest_backup = sorted(backups)[-1]
            backup_path = os.path.join(self.backup_dir, latest_backup)

            results["rollback_data_found"] = True
            results["backup_location"] = backup_path
            results["status"] = "complete"
            results["note"] = "Rollback capability verified. To restore, manually review changes in backup directory and revert as needed."

        except Exception as e:
            results["status"] = "error"
            results["error"] = str(e)

        return results

    def get_upgrade_history(self, limit: int = 10) -> List[Dict[str, Any]]:
        """Get recent upgrade history"""
        history = []

        try:
            log_file = os.path.join(self.backup_dir, "upgrade_log.json")
            if os.path.exists(log_file):
                with open(log_file, "r") as f:
                    log = json.load(f)
                    history = log[-limit:] if len(log) > limit else log
        except Exception as _e:
            import logging
            logging.getLogger(__name__).debug(
                f'Swallowed exception in auto_upgrader.py: {_e}')

        return history

    def get_system_evolution_stats(self) -> Dict[str, Any]:
        """Get statistics on how system has evolved through upgrades"""
        stats = {
            "total_upgrades": 0,
            "total_engagements_learned_from": 0,
            "tools_tracked": 0,
            "rules_generated": 0,
            "last_upgrade": None
        }

        try:
            # Count upgrades
            log_file = os.path.join(self.backup_dir, "upgrade_log.json")
            if os.path.exists(log_file):
                with open(log_file, "r") as f:
                    log = json.load(f)
                    stats["total_upgrades"] = len(log)
                    if log:
                        stats["last_upgrade"] = log[-1].get("timestamp")

            # Count tool metrics
            metrics_file = os.path.join(self.config_dir, "tool_metrics.json")
            if os.path.exists(metrics_file):
                with open(metrics_file, "r") as f:
                    metrics = json.load(f)
                    stats["tools_tracked"] = len(
                        metrics.get("tool_effectiveness", {}))
                    stats["total_engagements_learned_from"] = len(
                        metrics.get("engagements_learned_from", []))

            # Count generated rules
            stats["rules_generated"] = 0
            if os.path.exists(self.backup_dir):
                backup_files = os.listdir(self.backup_dir)
                rules_files = [
                    f for f in backup_files if "generated_rules.json" in f]
                stats["rules_generated"] = len(rules_files)

        except Exception as e:
            stats["error"] = str(e)

        return stats
