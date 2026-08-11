from collections import defaultdict, deque
from threading import Lock
from typing import Callable
from utils.logger import get_logger

log = get_logger("message_bus")

# P5-9 (BUS-1): per-channel bounded replay buffer so a subscriber that attaches
# AFTER an event was published still receives it. Bounded (drops OLDEST, keeps
# newest); ephemeral reply_* channels are NOT buffered (unique per request).
_REPLAY_BUFFER_PER_CHANNEL = 50


class MessageBus:
    def __init__(self, state_store, engagement_id: str):
        self._subscribers: dict[str, list[Callable]] = defaultdict(list)
        self._buffer: dict[str, deque] = defaultdict(
            lambda: deque(maxlen=_REPLAY_BUFFER_PER_CHANNEL))
        self._lock = Lock()
        self._store = state_store
        self._engagement_id = engagement_id

    def subscribe(self, channel: str, handler: Callable, replay: bool = True):
        """Register a handler. P5-9: by default REPLAY the channel's buffered past
        events to this handler so a late subscriber isn't blind to what already
        happened. Replay runs OUTSIDE the lock (a handler may re-enter the bus)."""
        with self._lock:
            self._subscribers[channel].append(handler)
            buffered = list(self._buffer.get(channel, ())) if replay else []
        for from_agent, payload in buffered:
            try:
                handler(from_agent, payload)
            except Exception as e:
                log.error(
                    f"Replay to late subscriber on '{channel}' failed: {e}")

    def publish(self, from_agent: str, channel: str, payload: dict):
        """
        Publish a message. All subscribers on that channel receive it — plus any
        FUTURE late subscriber, via the bounded replay buffer (P5-9).
        Also logs to state store for audit trail.
        """
        import json
        content = json.dumps(payload)
        log.debug(f"[BUS] {from_agent} -> {channel}: {content[:200]}")
        self._store.log_message(
            self._engagement_id, from_agent, channel, content
        )
        with self._lock:
            # Buffer for late subscribers (bounded). Skip ephemeral reply channels.
            if not channel.startswith("reply_"):
                self._buffer[channel].append((from_agent, payload))
            handlers = list(self._subscribers.get(channel, []))
        for handler in handlers:
            try:
                handler(from_agent, payload)
            except Exception as e:
                import traceback
                log.error(f"Message handler error on channel '{channel}': {e}")
                log.error(traceback.format_exc())

    def request_reply(self, from_agent: str, to_agent: str, payload: dict,
                      reply_handler: Callable, timeout: float = 30.0):
        """
        Send a message and wait for a reply on a temporary reply channel.
        Used when an agent needs a response from another agent.
        """
        import threading
        import uuid
        reply_channel = f"reply_{uuid.uuid4().hex[:8]}"
        result = {}
        event = threading.Event()

        def on_reply(sender, data):
            try:
                # First, call the provided reply_handler if present
                if callable(reply_handler):
                    try:
                        reply_handler(sender, data)
                    except Exception as e:
                        log.error(f"reply_handler raised: {e}")
                # Store the data and signal waiter
                result["data"] = data
                event.set()
            finally:
                # Unsubscribe this temporary handler to avoid memory leaks
                with self._lock:
                    handlers = self._subscribers.get(reply_channel, [])
                    if on_reply in handlers:
                        handlers.remove(on_reply)
                        self._subscribers[reply_channel] = handlers

        # Register temporary reply handler (no replay — ephemeral channel).
        self.subscribe(reply_channel, on_reply, replay=False)
        payload["_reply_to"] = reply_channel
        # Publish the request
        self.publish(from_agent, to_agent, payload)

        got_reply = event.wait(timeout=timeout)
        if not got_reply:
            # Timeout: clean up temporary subscription if still present
            with self._lock:
                handlers = self._subscribers.get(reply_channel, [])
                if on_reply in handlers:
                    handlers.remove(on_reply)
                    self._subscribers[reply_channel] = handlers
            log.warning(f"request_reply timeout: {from_agent} -> {to_agent}")
            return None
        return result.get("data")
