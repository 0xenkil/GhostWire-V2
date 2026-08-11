"""Phase 5 — P5-9 event-bus late-subscriber replay (BUS-1)."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.message_bus import MessageBus, _REPLAY_BUFFER_PER_CHANNEL  # noqa: E402


class _Store:
    def log_message(self, *a, **k):
        pass


def _bus():
    return MessageBus(_Store(), "eng1")


def test_late_subscriber_receives_past_event():
    bus = _bus()
    bus.publish("recon", "findings", {"n": 1})     # published BEFORE anyone subscribed
    got = []
    bus.subscribe("findings", lambda frm, p: got.append(p))
    assert got == [{"n": 1}]                        # late subscriber still got it


def test_live_and_replayed_both_delivered_once():
    bus = _bus()
    got = []
    bus.subscribe("c", lambda frm, p: got.append(p["i"]))
    bus.publish("a", "c", {"i": 1})                 # live to existing subscriber
    late = []
    bus.subscribe("c", lambda frm, p: late.append(p["i"]))
    bus.publish("a", "c", {"i": 2})
    assert got == [1, 2]                             # existing sub: no double delivery
    assert late == [1, 2]                            # late sub: replay of 1 + live 2


def test_replay_buffer_is_bounded_drops_oldest():
    bus = _bus()
    for i in range(_REPLAY_BUFFER_PER_CHANNEL + 10):
        bus.publish("a", "c", {"i": i})
    seen = []
    bus.subscribe("c", lambda frm, p: seen.append(p["i"]))
    assert len(seen) == _REPLAY_BUFFER_PER_CHANNEL   # bounded
    assert seen[-1] == _REPLAY_BUFFER_PER_CHANNEL + 9  # newest kept
    assert 0 not in seen                              # oldest dropped, not newest


def test_replay_can_be_opted_out():
    bus = _bus()
    bus.publish("a", "c", {"i": 1})
    got = []
    bus.subscribe("c", lambda frm, p: got.append(p), replay=False)
    assert got == []


def test_reply_channels_are_not_buffered():
    bus = _bus()
    bus.publish("a", "reply_abcd1234", {"i": 1})
    got = []
    bus.subscribe("reply_abcd1234", lambda frm, p: got.append(p))
    assert got == []   # ephemeral reply channels are never replayed
