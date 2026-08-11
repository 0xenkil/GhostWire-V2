"""
WAF Learner - Auto-discovery and learning for new WAFs

Integrates with auto-upgrade to:
1. Discover new WAF types not in the database
2. Learn which evasion tactics work against each WAF
3. Update tactic effectiveness scores
4. Generate new fingerprints from discovered behaviors
5. Share learnings across all future engagements
"""

import json
import os
import time
from typing import Dict, List, Any
from collections import defaultdict
import contextlib


class WafLearner:
    """Learns new WAF types and evasion techniques from engagements"""

    def __init__(self, database_file: str = None):
        """Initialize WAF learner"""
        if database_file is None:
            from config_paths import WAF_DATABASE_FILE
            self.database_file = str(WAF_DATABASE_FILE)
        else:
            self.database_file = database_file
        self.learnings = []

    def learn_from_engagement(self, engagement_id: str,
                              engagement_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Extract learnings from engagement for future use

        Args:
            engagement_id: ID of completed engagement
            engagement_data: Data from engagement (WAF behavior, tool results, etc.)

        Returns:
            Learning summary with new fingerprints and tactic updates
        """
        learning_summary = {
            "engagement_id": engagement_id,
            "timestamp": time.time(),
            "new_fingerprints": [],
            "updated_tactics": [],
            "tactic_effectiveness": {},
            "discovered_behaviors": [],
            "recommendations": []
        }

        try:
            # Extract WAF fingerprint from engagement
            fingerprint = engagement_data.get("waf_fingerprint", {})

            # Extract Retry-After for 429 Recovery
            headers = engagement_data.get("headers", {})
            retry_after = headers.get(
                "Retry-After") or headers.get("retry-after")
            if retry_after:
                try:
                    delay = int(retry_after)
                    fingerprint["rate_limit_delay"] = delay
                    behaviors = fingerprint.setdefault("behaviors", {})
                    if "rate_limiting" not in behaviors:
                        behaviors["rate_limiting"] = f"Detected Retry-After: {delay}s"
                except ValueError:
                    pass

            # Check if this is a new WAF
            if self._is_new_waf(fingerprint):
                new_fp = self._create_new_fingerprint(
                    engagement_id, fingerprint)
                learning_summary["new_fingerprints"].append(new_fp)

                # Save to database
                self._save_new_fingerprint(new_fp)

            # Extract tactic effectiveness from tool runs
            tool_runs = engagement_data.get("tool_runs", [])
            if tool_runs:
                tactic_updates = self._analyze_tactic_effectiveness(
                    tool_runs, fingerprint)
                learning_summary["updated_tactics"] = tactic_updates

                # Update database
                self._update_tactic_effectiveness(tactic_updates)

            # Identify new behaviors
            behaviors = fingerprint.get("behaviors", {})
            new_behaviors = self._identify_new_behaviors(behaviors)
            if new_behaviors:
                learning_summary["discovered_behaviors"] = new_behaviors

            # Generate recommendations for system improvement
            recommendations = self._generate_recommendations(
                fingerprint, tool_runs, tactic_updates
            )
            learning_summary["recommendations"] = recommendations

        except Exception as e:
            learning_summary["error"] = str(e)

        self.learnings.append(learning_summary)
        return learning_summary

    def _is_new_waf(self, fingerprint: Dict[str, Any]) -> bool:
        """Check if this WAF is already in the database"""
        if not fingerprint:
            return False

        # Load existing database
        db = self._load_database()
        db.get("fingerprints", {})

        # If no similar fingerprint found, it's new
        similar = fingerprint.get("similar_to_known", [])

        # If high confidence match to existing: not new
        for match in similar:
            if "100%" in match or "90%" in match:
                return False

        return True

    def _create_new_fingerprint(
            self, engagement_id: str, fingerprint: Dict[str, Any]) -> Dict[str, Any]:
        """Create a new WAF fingerprint entry"""
        import uuid
        new_fp = {
            "id": f"learned_waf_{engagement_id}_{uuid.uuid4().hex}",
            "discovered_in_engagement": engagement_id,
            "discovered_at": time.time(),
            "confidence": fingerprint.get("confidence", 0),
            "behaviors": fingerprint.get("behaviors", {}),
            "patterns": fingerprint.get("detected_patterns", []),
            "evasion_tactics": fingerprint.get("evasion_candidates", []),
            "rate_limit_delay": fingerprint.get("rate_limit_delay", None),
            "tactics_tested": {},
            "effectiveness_data": {},
            "similar_to": fingerprint.get("similar_to_known", [])
        }

        return new_fp

    def _analyze_tactic_effectiveness(self, tool_runs: List[Dict[str, Any]],
                                      fingerprint: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Analyze which evasion tactics worked"""
        updates = []

        tactics_used = defaultdict(
            lambda: {
                "successes": 0,
                "failures": 0,
                "total": 0})

        for run in tool_runs:
            if not isinstance(run, dict):
                continue

            # Extract tactic info from tool run. P3-3: normalize the batch key
            # through the SAME canonicalizer as the live block/success path, so a
            # revived batch pass accumulates onto the same entries (not a second,
            # differently-cased set). "none"/"" stays the skip sentinel.
            evasion_raw = run.get("evasion_applied") or "none"
            evasion = ("none" if str(evasion_raw).strip().lower() in ("none", "")
                       else self._normalize_tactic(evasion_raw))
            success = run.get("success", False)

            tactics_used[evasion]["total"] += 1
            if success:
                tactics_used[evasion]["successes"] += 1
            else:
                tactics_used[evasion]["failures"] += 1

        # Create updates for each tactic
        waf_id = fingerprint.get("id", "unknown_waf")
        for tactic_name, stats in tactics_used.items():
            if tactic_name == "none":
                continue

            success_rate = stats["successes"] / \
                stats["total"] if stats["total"] > 0 else 0

            update = {
                "tactic": tactic_name,
                "waf_id": waf_id,
                "success_rate": success_rate,
                "successes": stats["successes"],
                "failures": stats["failures"],
                "total_runs": stats["total"],
                "recommendation": self._rate_tactic(success_rate)
            }
            updates.append(update)

        return updates

    def _identify_new_behaviors(self, behaviors: Dict[str, Any]) -> List[str]:
        """Identify any new WAF behaviors we haven't seen before"""
        db = self._load_database()
        known_behaviors = set()

        # Collect all known behaviors
        for fp_data in db.get("fingerprints", {}).values():
            if isinstance(fp_data, dict):
                known_behaviors.update(fp_data.get("behaviors", {}).keys())

        # Find new ones
        new_behaviors = []
        for behavior_name in behaviors.keys():
            if behavior_name not in known_behaviors:
                new_behaviors.append(behavior_name)

        return new_behaviors

    def _generate_recommendations(self, fingerprint: Dict[str, Any],
                                  tool_runs: List[Dict[str, Any]],
                                  tactic_updates: List[Dict[str, Any]]) -> List[str]:
        """Generate system improvement recommendations"""
        recommendations = []

        # Recommendation 1: If high success tactic found, prioritize it
        for update in tactic_updates:
            if update.get("success_rate", 0) >= 0.8:
                recommendations.append(
                    f"Tactic '{
                        update['tactic']}' is highly effective ({
                        update['success_rate']:.0%}) "
                    f"against this WAF - prioritize in future"
                )

        # Recommendation 2: If multiple tactics needed, create combination rule
        if len(tactic_updates) > 3:
            successful_tactics = [
                u["tactic"] for u in tactic_updates if u.get(
                    "success_rate", 0) > 0.5]
            if successful_tactics:
                recommendations.append(
                    f"Multiple evasion tactics needed. Consider combination: {
                        ' + '.join(
                            successful_tactics[
                                :3])}"
                )

        # Recommendation 3: If fingerprint confidence low, need more testing
        if fingerprint.get("confidence", 0) < 0.6:
            recommendations.append(
                "WAF fingerprint confidence is low - recommend additional probing on next engagement"
            )

        # Recommendation 4: If new WAF detected, flag for manual review
        similar = fingerprint.get("similar_to_known", [])
        if not similar:
            recommendations.append(
                "New WAF detected with no known similarities - recommend manual analysis and documentation"
            )

        # Recommendation 4.5: Rate limiting
        delay = fingerprint.get("rate_limit_delay")
        if delay:
            recommendations.append(
                f"WAF enforces rate limiting. Suggested delay per request: {delay}s"
            )

        # Recommendation 5: Tool-specific tactics
        tools_used = set()
        for run in tool_runs:
            if isinstance(run, dict):
                tools_used.add(run.get("tool", "unknown"))

        if "nuclei" in tools_used and "nuclei" in fingerprint.get(
                "evasion_candidates", []):
            recommendations.append(
                "nuclei struggles against this WAF - consider using curl/wget instead"
            )

        return recommendations

    def _rate_tactic(self, success_rate: float) -> str:
        """Rate effectiveness of a tactic"""
        if success_rate >= 0.9:
            return "highly_effective"
        elif success_rate >= 0.7:
            return "effective"
        elif success_rate >= 0.5:
            return "moderate"
        elif success_rate > 0:
            return "limited_effectiveness"
        else:
            return "ineffective"

    @contextlib.contextmanager
    def _database_lock(self):
        """Atomic lock for read-modify-write operations."""
        lock_dir = self.database_file + ".lock"
        # The lock dir lives beside the database file; on the very first run that
        # parent dir may not exist yet, and os.mkdir(lock_dir) would then raise
        # FileNotFoundError (NOT FileExistsError) on every call — silently failing
        # every WAF-learning write. Ensure the parent exists before contending.
        _parent = os.path.dirname(self.database_file)
        if _parent:
            os.makedirs(_parent, exist_ok=True)
        for _ in range(50):
            try:
                os.mkdir(lock_dir)
                break
            except FileExistsError:
                time.sleep(0.1)
        else:
            print(f"Timeout acquiring lock for {self.database_file}")
            yield False
            return

        try:
            yield True
        finally:
            try:
                os.rmdir(lock_dir)
            except Exception as e:
                import logging
                logging.getLogger(__name__).debug(f"Ignored error: {e}")

    def _save_new_fingerprint(self, fingerprint: Dict[str, Any]) -> bool:
        """Save new fingerprint to database"""
        try:
            # The ENTIRE read-modify-write must stay inside the lock, or the
            # lock is decorative: it previously released right after the read,
            # so concurrent block/success updates clobbered each other and could
            # interleave-corrupt waf_database.json (which _load_database then
            # silently swallows -> all learned WAF tactics wiped).
            with self._database_lock() as locked:
                if not locked:
                    return False
                db = self._load_database()

                if "fingerprints" not in db:
                    db["fingerprints"] = {}

                db["fingerprints"][fingerprint["id"]] = {
                    "behaviors": fingerprint.get("behaviors", {}),
                    "patterns": fingerprint.get("patterns", []),
                    "confidence": fingerprint.get("confidence", 0),
                    "discovered_in": fingerprint.get("discovered_in_engagement"),
                    "discovered_at": fingerprint.get("discovered_at"),
                    "evasion_tactics": fingerprint.get("evasion_tactics", [])
                }

                # Save back (inside the lock — atomic read-modify-write)
                self._save_database(db)
            return True
        except Exception as e:
            print(f"Error saving fingerprint: {e}")
            return False

    @staticmethod
    def _normalize_tactic(tactic: Any) -> str:
        """P3-3 — ONE canonical tactic key so a tactic's successes and failures
        ALWAYS land on the same DB entry.

        WAFLEARN-KEYSPLIT: the block path debited `str(tactic)` — which is the
        stringified DICT `"{'name': 'header_mutation'}"` when the tactic is a dict
        — while the success path credited the hardcoded literal `"header_mutation"`.
        The two keys never matched, so every tactic's per-WAF success_rate was
        computed over a split, meaningless denominator. Normalizing both sides
        through here (dict → its name, then lower/underscore) collapses them onto
        one key."""
        if isinstance(tactic, dict):
            name = tactic.get("name") or tactic.get("tactic") or ""
        else:
            name = str(tactic or "")
        name = name.strip().lower().replace(" ", "_")
        return name or "unknown"

    def record_outcome(self, outcome: Any, tactic: Any = None,
                       waf_id: str = "generic") -> bool:
        """P3-3 — the SINGLE per-run entry point for WAF-tactic learning, so a
        tactic's credits and debits ALWAYS accumulate under ONE normalized key.

        `outcome` is a `LearningOutcome` (preferred — the credit is then gated on
        a real proof / clean-execution signal via `.proven`, not merely "the tool
        exited 0") or a bare bool for the simplest callers. `tactic` names the
        tactic; when omitted, `outcome.evasion_tactic` is used. Best-effort — the
        WAF-learning write is telemetry and must never raise into the hot loop."""
        try:
            src = tactic if tactic is not None else getattr(
                outcome, "evasion_tactic", None)
            name = self._normalize_tactic(src)
            if name == "unknown":
                return False
            if isinstance(outcome, bool):
                success = outcome
            else:
                # LearningOutcome: only a proof-/clean-execution-backed run got
                # PAST the WAF; a still-blocked or empty run is a tactic failure.
                success = bool(getattr(outcome, "proven", False))
            return self.update_tactic_effectiveness(
                name, success, waf_id=str(waf_id or "generic"))
        except Exception:
            return False

    def update_tactic_effectiveness(self, tactic_name: str, success: bool,
                                    waf_id: str = "generic") -> bool:
        """Public convenience wrapper used by agents on every block/success.

        The underlying _update_tactic_effectiveness expects a PRE-AGGREGATED
        snapshot per (tactic, waf), so we read the prior counts, fold in this one
        outcome, and persist the new totals. Best-effort; never raises.
        """
        try:
            # P3-3: normalize here too, so even a direct caller (not via
            # record_outcome) lands on the one canonical key. Idempotent.
            tactic_name = self._normalize_tactic(tactic_name)
            prev = (
                self._load_database()
                .get("tactics", {})
                .get(tactic_name, {})
                .get("per_waf", {})
                .get(waf_id, {})
            )
            successes = int(prev.get("successes", 0)) + (1 if success else 0)
            failures = int(prev.get("failures", 0)) + (0 if success else 1)
            total_runs = int(prev.get("total_runs", 0)) + 1
            return self._update_tactic_effectiveness([{
                "tactic": tactic_name,
                "waf_id": waf_id,
                "success_rate": (successes / total_runs) if total_runs else 0.0,
                "successes": successes,
                "failures": failures,
                "total_runs": total_runs,
            }])
        except Exception:
            return False

    def _update_tactic_effectiveness(
            self, updates: List[Dict[str, Any]]) -> bool:
        """Update tactic effectiveness scores in database"""
        try:
            # Keep the whole read-modify-write inside the lock (see
            # _save_new_fingerprint) so concurrent per-block updates don't
            # clobber each other or corrupt the shared database.
            with self._database_lock() as locked:
                if not locked:
                    return False
                db = self._load_database()

                if "tactics" not in db:
                    db["tactics"] = {}

                for update in updates:
                    tactic_name = update.get("tactic", "")
                    waf_id = update.get("waf_id", "")

                    if not tactic_name or not waf_id:
                        continue

                    # Initialize tactic entry if needed
                    if tactic_name not in db["tactics"]:
                        db["tactics"][tactic_name] = {
                            "overall_success_rate": 0,
                            "per_waf": {}
                        }

                    # Update per-WAF effectiveness
                    db["tactics"][tactic_name]["per_waf"][waf_id] = {
                        "success_rate": update.get("success_rate", 0),
                        "successes": update.get("successes", 0),
                        "failures": update.get("failures", 0),
                        "total_runs": update.get("total_runs", 0),
                        "last_updated": time.time()
                    }

                    # Recalculate overall success rate
                    all_stats = db["tactics"][tactic_name]["per_waf"]
                    total_successes = sum(s.get("successes", 0)
                                          for s in all_stats.values())
                    total_runs = sum(s.get("total_runs", 0)
                                     for s in all_stats.values())

                    if total_runs > 0:
                        db["tactics"][tactic_name]["overall_success_rate"] = total_successes / total_runs

                self._save_database(db)
            return True
        except Exception as e:
            print(f"Error updating tactic effectiveness: {e}")
            return False

    def _load_database(self) -> Dict[str, Any]:
        """Load WAF database"""
        if os.path.exists(self.database_file):
            try:
                with open(self.database_file, "r") as f:
                    return json.load(f)
            except Exception as _e:
                import logging
                logging.getLogger(__name__).debug(
                    f'Swallowed exception in waf_learner.py: {_e}')

        return {"fingerprints": {}, "tactics": {}}

    def _save_database(self, db: Dict[str, Any]) -> bool:
        """Save WAF database atomically (temp file + os.replace).

        A direct truncate-and-write leaves a half-written, invalid-JSON file if
        the process dies mid-dump; _load_database then swallows the decode error
        and returns an empty DB, wiping every learned fingerprint/tactic. Writing
        to a sibling temp file and atomically renaming guarantees the live file
        is always a complete, valid snapshot.
        """
        try:
            os.makedirs(os.path.dirname(self.database_file), exist_ok=True)
            tmp = f"{self.database_file}.{os.getpid()}.tmp"
            with open(tmp, "w") as f:
                json.dump(db, f, indent=2)
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp, self.database_file)
            return True
        except Exception as e:
            print(f"Error saving database: {e}")
            try:
                if 'tmp' in dir() and os.path.exists(tmp):
                    os.remove(tmp)
            except Exception:
                pass
            return False

    def get_learning_summary(self) -> Dict[str, Any]:
        """Get summary of all learnings"""
        summary = {
            "total_engagements_analyzed": len(self.learnings),
            "new_fingerprints_discovered": 0,
            "new_behaviors_discovered": 0,
            "tactics_updated": 0,
            "recommendations_generated": 0
        }

        for learning in self.learnings:
            summary["new_fingerprints_discovered"] += len(
                learning.get("new_fingerprints", []))
            summary["new_behaviors_discovered"] += len(
                learning.get("discovered_behaviors", []))
            summary["tactics_updated"] += len(
                learning.get("updated_tactics", []))
            summary["recommendations_generated"] += len(
                learning.get("recommendations", []))

        return summary

    def export_learnings(self, filepath: str = None) -> str:
        """Export all learnings to file"""
        import uuid
        if not filepath:
            filepath = os.path.join(
                os.path.dirname(self.database_file),
                f"waf_learnings_{uuid.uuid4().hex}.json"
            )

        export_data = {
            "timestamp": time.time(),
            "learnings": self.learnings,
            "summary": self.get_learning_summary()
        }

        os.makedirs(os.path.dirname(filepath), exist_ok=True)
        with open(filepath, "w") as f:
            json.dump(export_data, f, indent=2)

        return filepath
