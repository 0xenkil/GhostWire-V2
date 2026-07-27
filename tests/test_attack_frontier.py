"""Tests for the AttackFrontier — scored, self-expanding work queue (2026-06-21)."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from intelligence.attack_frontier import AttackFrontier, signal_score, FrontierItem  # noqa: E402


def test_signal_score_is_structural_not_name_based():
    # NO hardcoded "what's valuable" name judgments: admin/api/www all score the
    # same neutral base (deciding value is the AI's job, not a keyword list).
    base = signal_score("anything.target.com")
    assert signal_score("admin.target.com") == base
    assert signal_score("api.target.com") == base
    assert signal_score("www.target.com") == base
    # Only OBJECTIVE attack-surface structure bumps the score.
    assert signal_score("/orders/123") > base            # id-bearing path
    assert signal_score("/search?q=1") > base            # takes query params
    assert signal_score("/api/users?id=1") > signal_score("/api/users")


def test_push_dedups_and_keeps_higher_priority():
    f = AttackFrontier()
    f.push("subdomain", "admin.t.com", priority=0.4)
    f.push("subdomain", "https://admin.t.com/", priority=0.9)  # same asset, normalized
    assert len(f._items) == 1
    assert f.pending()[0].attack_priority == 0.9


def test_pop_returns_highest_effective_first():
    f = AttackFrontier()
    f.push("subdomain", "www.t.com", priority=0.2)
    f.push("subdomain", "admin.t.com", priority=0.85)
    f.push("subdomain", "shop.t.com", priority=0.55)
    order = [f.pop().value for _ in range(3)]
    assert order[0] == "admin.t.com"
    assert order[1] == "shop.t.com"
    assert order[2] == "www.t.com"


def test_novelty_decays_so_tried_items_sink():
    f = AttackFrontier()
    a = f.push("endpoint", "/a", priority=0.8)
    f.push("endpoint", "/b", priority=0.7)
    top = f.pop()                      # /a (0.8)
    assert top.value == "/a"
    f.record_outcome(top, produced_findings=False)   # novelty 1.0 -> 0.5
    # /a re-pending but now ranks below /b because novelty dropped
    nxt = f.pop()
    assert nxt.value == "/b"


def test_confirmed_finding_boosts_neighbors_momentum():
    f = AttackFrontier()
    win = f.push("endpoint", "/api/orders/1", parent="api.t.com", priority=0.6)
    sib = f.push("endpoint", "/api/orders/2", parent="api.t.com", priority=0.6)
    other = f.push("endpoint", "/blog/post", parent="www.t.com", priority=0.6)
    f.pop()  # mark something active is fine; we record directly
    f.record_outcome(win, confirmed=True)
    assert sib.momentum > 0          # same parent neighborhood got boosted
    assert other.momentum == 0       # unrelated neighborhood untouched
    assert win.momentum >= 1.0


def test_expand_pushes_discovered_items():
    f = AttackFrontier()
    f.push("subdomain", "api.t.com", priority=0.85)
    added = f.expand([
        {"kind": "param", "value": "id", "parent": "api.t.com"},
        {"kind": "endpoint", "value": "/api/users?id=1", "parent": "api.t.com"},
    ])
    assert added == 2
    assert len(f._items) == 3


def test_objective_boost_targets_relevant_items():
    f = AttackFrontier()
    a = f.push("endpoint", "/admin/login", priority=0.5)
    b = f.push("endpoint", "/static/app.js", priority=0.5)
    f.boost_for_objective(["admin", "login"], amount=0.4)
    assert a.momentum > 0
    assert b.momentum == 0


def test_snapshot_for_prompt_is_ranked_and_tagged():
    f = AttackFrontier()
    f.push("subdomain", "admin.t.com", priority=0.85)
    f.push("subdomain", "www.t.com", priority=0.2)
    s = f.snapshot_for_prompt()
    assert "ATTACK FRONTIER" in s
    # admin appears before www
    assert s.index("admin.t.com") < s.index("www.t.com")
    assert "HIGH" in s


def test_to_list_is_serializable_ranked():
    f = AttackFrontier()
    f.push("subdomain", "admin.t.com", priority=0.85)
    f.push("subdomain", "www.t.com", priority=0.2)
    lst = f.to_list()
    assert isinstance(lst, list) and lst[0]["value"] == "admin.t.com"
    import json
    json.dumps(lst)  # must be JSON-serializable for the recon->exploit handoff
