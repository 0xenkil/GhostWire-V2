"""
AttackFrontier — a scored, self-expanding work queue for "what to do next".

The engine used to dump all discovered surface (subdomains, endpoints, params)
into one big AI prompt and trust the model to pick well under token pressure —
with priority signals that were often dead (see the subdomains-discovered-then-
forgotten bug). The frontier replaces that with an explicit, inspectable priority
queue: every concrete actionable item carries an `attack_priority` (caller- or
signal-derived), a `novelty` factor (untried first), and a `momentum` bonus
(boosted when nearby work paid off). A loop pops the top item, the caller acts on
THAT item, records the outcome, and pushes back whatever it learned as new scored
items. Used by BOTH recon (what to enumerate next) and exploitation (what to
attack next) so the two phases share one spine.

Scoring-agnostic: callers SET `attack_priority` (e.g. from the existing AI
subdomain classifier / ReasoningEngine). A generic, target-agnostic signal
heuristic is provided only as a FALLBACK when no score is supplied — the same
"AI-primary, heuristic-fallback" pattern as ReasoningEngine.analyze_tool_failure.
The heuristic is never the decision authority and carries no per-target logic.
"""
from dataclasses import dataclass, field
import re

# Generic, target-agnostic attack-interest tokens (FALLBACK scoring only). These
# mirror the categories the existing AI subdomain-classifier prompt already uses;
# (no hardcoded "what's valuable" keyword lists — that judgment is the AI's job.)


def signal_score(text: str) -> float:
    """STRUCTURAL fallback score in [0,1], used ONLY when the caller supplies no
    priority. It makes NO value judgment about names — there is deliberately no
    hardcoded "admin/api/dev is important" keyword list; deciding what is
    high-value for THIS target is the AI's job (the caller passes an AI-derived
    priority). This scores only OBJECTIVE attack-SURFACE structure: an endpoint
    that takes parameters, or an id-bearing path, is more injectable surface than
    a bare page. Everything else gets a neutral score so ranking is driven by the
    caller's AI priority + evidence-based momentum, not by us guessing from a name.
    """
    t = (text or "").lower()
    score = 0.4  # neutral — value ranking belongs to the AI, not to this function
    if re.search(r'[?&][\w.\-]+=', t) or "id=" in t:
        score += 0.15   # takes query parameters -> injectable surface
    if re.search(r'/\d+(?:/|$)', t):
        score += 0.10   # id-bearing path -> IDOR / object-level surface
    return round(min(1.0, score), 3)


@dataclass
class FrontierItem:
    key: str                       # dedup identity (normalized)
    kind: str                      # subdomain | endpoint | param | host | service
    value: str                     # the concrete actionable string (url/host/path)
    parent: str = ""               # host/parent for momentum grouping
    attack_priority: float = 0.0   # 0..1 — caller-set (AI) or signal fallback
    novelty: float = 1.0           # 1.0 untried; decays as attempted
    momentum: float = 0.0          # boosted when nearby work produced findings
    status: str = "pending"        # pending | active | done | abandoned
    attempts: int = 0
    source: str = ""
    meta: dict = field(default_factory=dict)

    def effective(self) -> float:
        """Rank = priority gated by novelty (so we don't re-hammer tried items)
        plus a momentum reward for productive neighborhoods."""
        return round(
            self.attack_priority * (0.4 + 0.6 * self.novelty)
            + 0.25 * self.momentum, 4)

    def to_dict(self) -> dict:
        return {
            "kind": self.kind, "value": self.value, "parent": self.parent,
            "attack_priority": self.attack_priority, "novelty": self.novelty,
            "momentum": round(self.momentum, 3), "status": self.status,
            "attempts": self.attempts, "effective": self.effective(),
            "source": self.source,
        }


class AttackFrontier:
    """A priority queue of scored, deduplicated, self-expanding work items."""

    def __init__(self, phase: str = "exploitation"):
        self.phase = phase
        self._items: dict[str, FrontierItem] = {}

    @staticmethod
    def _norm_key(kind: str, value: str) -> str:
        v = (value or "").strip().lower().rstrip("/")
        v = re.sub(r'^https?://', '', v)
        return f"{kind}:{v}"

    def push(self, kind: str, value: str, *, parent: str = "",
             priority: float = None, source: str = "", meta: dict = None) -> FrontierItem:
        """Add an item (or merge into an existing one, keeping the higher score)."""
        if not value:
            return None
        key = self._norm_key(kind, value)
        pr = float(priority) if priority is not None else signal_score(value)
        pr = max(0.0, min(1.0, pr))
        existing = self._items.get(key)
        if existing:
            if pr > existing.attack_priority:
                existing.attack_priority = pr
            if meta:
                existing.meta.update(meta)
            if parent and not existing.parent:
                existing.parent = parent
            return existing
        item = FrontierItem(key=key, kind=kind, value=value, parent=parent or "",
                            attack_priority=pr, source=source, meta=meta or {})
        self._items[key] = item
        return item

    def push_many(self, items) -> int:
        """items: iterable of dicts with at least {kind, value}."""
        n = 0
        for it in (items or []):
            if not isinstance(it, dict):
                continue
            r = self.push(
                it.get("kind", "endpoint"), it.get("value", ""),
                parent=it.get("parent", ""), priority=it.get("priority"),
                source=it.get("source", ""), meta=it.get("meta"))
            if r is not None:
                n += 1
        return n

    def pop(self) -> FrontierItem:
        """Return the highest effective-priority PENDING item, mark it active."""
        pending = [it for it in self._items.values() if it.status == "pending"]
        if not pending:
            return None
        pending.sort(key=lambda it: it.effective(), reverse=True)
        top = pending[0]
        top.status = "active"
        top.attempts += 1
        return top

    def record_outcome(self, item, *, produced_findings: bool = False,
                       confirmed: bool = False, exhausted: bool = False) -> None:
        """Update an item after acting on it; boost productive neighborhoods."""
        it = item if isinstance(item, FrontierItem) else self._items.get(item)
        if not it:
            return
        it.novelty = max(0.0, it.novelty - 0.5)
        if confirmed:
            it.momentum += 1.0
            self._boost_neighbors(it, 0.5)
        elif produced_findings:
            it.momentum += 0.4
            self._boost_neighbors(it, 0.2)
        if exhausted or it.novelty <= 0.0:
            it.status = "done"
        else:
            it.status = "pending"   # revisitable, but at lower novelty

    def _boost_neighbors(self, item: "FrontierItem", amount: float) -> None:
        parent = item.parent or item.value
        if not parent:
            return
        p = parent.lower()
        for it in self._items.values():
            if it.key == item.key or it.status in ("done", "abandoned"):
                continue
            if (it.parent and it.parent.lower() == p) or p in it.value.lower():
                it.momentum += amount

    def expand(self, items) -> int:
        """Push items discovered while acting (subdomains, params, endpoints)."""
        return self.push_many(items)

    def boost_for_objective(self, keywords, amount: float = 0.3) -> None:
        """ObjectiveLedger hook: bump items relevant to an unmet objective."""
        kw = [str(k).lower() for k in (keywords or []) if k]
        if not kw:
            return
        for it in self._items.values():
            if it.status in ("done", "abandoned"):
                continue
            blob = (it.value + " " + str(it.meta)).lower()
            if any(k in blob for k in kw):
                it.momentum += amount

    def pending(self) -> list:
        return sorted(
            [it for it in self._items.values() if it.status == "pending"],
            key=lambda it: it.effective(), reverse=True)

    def snapshot_for_prompt(self, top: int = 12, title: str = None) -> str:
        items = self.pending()[:top]
        if not items:
            return ""
        hdr = title or ("### 🎯 ATTACK FRONTIER (scored — work these top-down; "
                        "highest-value targets first)")
        lines = [hdr]
        for it in items:
            e = it.effective()
            tag = "HIGH" if e >= 0.6 else ("MED" if e >= 0.4 else "LOW")
            mom = f" +momentum" if it.momentum > 0 else ""
            lines.append(f"[{tag} {e:.2f}] {it.kind}: {it.value}{mom}")
        return "\n".join(lines) + "\n"

    def stats(self) -> dict:
        by_status: dict = {}
        for it in self._items.values():
            by_status[it.status] = by_status.get(it.status, 0) + 1
        return {"total": len(self._items), "by_status": by_status,
                "top": [it.to_dict() for it in self.pending()[:5]]}

    def to_list(self) -> list:
        """Serializable ranked snapshot (for the recon→exploitation handoff)."""
        return [it.to_dict() for it in
                sorted(self._items.values(),
                       key=lambda it: it.effective(), reverse=True)]
