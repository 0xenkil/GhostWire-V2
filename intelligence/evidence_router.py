"""
Evidence Router module.

P5-1 (D-DEL-1): the `EvidenceRouter` class + its static `ROUTING_RULES` table
were deleted (dead phantom code). `TechStackRouter` survives; it is live via
exploitation_agent._gather_cve_seeds.

P5-11 (ROUTER-CMD-DEMOTED) + P5-13 (CVE-1): the ~90-LOC hardcoded exploit-COMMAND
table (`_exploit_type_to_command`) and all `command` string-building were DELETED.
The sole caller already discarded the commands (keeping only tech/version/
description/priority), and running hardcoded `/etc/passwd`/Drupalgeddon probes
violates the Evidence-first contract. `route_tech_stack` now emits pure LEADS,
and the CVE feed is a pluggable `CVESource` Protocol — a new feed (NVD, a file, an
API) slots in with zero core edits, and its output is ALWAYS an unproven lead the
Evidence spine must confirm with a measured differential, never a proven finding.
"""

from typing import Dict, List, Optional, Protocol, runtime_checkable

from intelligence.cve_database import find_cves_for_tech


@runtime_checkable
class CVESource(Protocol):
    """Pluggable tech→CVE-lead feed (P5-13). A source is any callable
    ``(tech_name, version) -> list[dict]``; each dict may carry ``cves``,
    ``description``, ``severity``. Output is ALWAYS unproven leads — a confirmed
    status only ever comes from the Evidence spine's measured differential."""

    def __call__(self, tech_name: str, version: Optional[str]) -> List[Dict]:
        ...


def _default_cve_source(tech_name: str, version: Optional[str]) -> List[Dict]:
    """Interim default source: the existing offline table. A live feed can replace
    it without touching TechStackRouter (that's the point of the Protocol)."""
    return find_cves_for_tech(tech_name, version)


class TechStackRouter:
    """Maps detected tech+version to known-CVE LEADS (never commands, never
    proven). Interim lead generator; leads flow into the hypothesis engine and
    must be confirmed by an Evidence differential before any 'proven' status."""

    @staticmethod
    def route_tech_stack(tech_stack: list, cve_source: CVESource = None) -> list:
        """
        Given detected technologies, produce unproven LEADS.

        Args:
            tech_stack: strings like ["WordPress 5.8", "CMS: WordPress", "PHP 7.4"]
            cve_source: a pluggable CVESource (default: the offline table).

        Returns:
            List of lead dicts: {tech, version, description, cves, priority, status}.
            NEVER a runnable command and NEVER a proven status.
        """
        src = cve_source or _default_cve_source
        leads = []
        seen: set = set()

        for tech_info in tech_stack:
            if not isinstance(tech_info, str):
                continue

            # Normalise: strip prefixes like "CMS: ", "SPA Framework: ".
            clean = tech_info
            for prefix in ("CMS: ", "SPA Framework: ", "Server: ", "Tech: "):
                if clean.startswith(prefix):
                    clean = clean[len(prefix):]
                    break

            parts = clean.split()
            if not parts:
                continue
            tech_name = parts[0].lower()
            version = parts[1] if len(parts) > 1 else None

            try:
                cve_infos = src(tech_name, version) or []
            except Exception:
                cve_infos = []

            for cve_info in cve_infos:
                cves = cve_info.get("cves", []) or []
                label = ", ".join(cves) if cves else f"{tech_name} generic"
                key = (tech_name, label)
                if key in seen:
                    continue
                seen.add(key)
                leads.append({
                    "tech": tech_name,
                    "version": version or "all",
                    "description": cve_info.get("description") or f"Known CVE lead: {label}",
                    "cves": cves,
                    "priority": cve_info.get("severity", "medium"),
                    "status": "lead",  # unproven — needs an Evidence differential
                })

        return leads
