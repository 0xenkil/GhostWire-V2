from collections import defaultdict
from threading import Lock
from typing import Callable
from utils.logger import get_logger

log = get_logger("message_bus")

class MessageBus:
    def __init__(self, state_store, engagement_id: str):
        self._subscribers: dict[str, list[Callable]] = defaultdict(list)
        self._lock = Lock()
        self._store = state_store
        self._engagement_id = engagement_id

    def subscribe(self, channel: str, handler: Callable):
        with self._lock:
            self._subscribers[channel].append(handler)

    def publish(self, from_agent: str, channel: str, payload: dict):
        """
        Publish a message. All subscribers on that channel receive it.
        Also logs to state store for audit trail.
        """
        import json
        content = json.dumps(payload)
        log.debug(f"[BUS] {from_agent} -> {channel}: {content[:200]}")
        self._store.log_message(
            self._engagement_id, from_agent, channel, content
        )
        with self._lock:
            handlers = list(self._subscribers.get(channel, []))
        for handler in handlers:
            try:
                handler(from_agent, payload)
            except Exception as e:
                log.error(f"Message handler error on channel '{channel}': {e}")

    def request_reply(self, from_agent: str, to_agent: str, payload: dict,
                       reply_handler: Callable, timeout: float = 30.0):
        """
        Send a message and wait for a reply on a temporary reply channel.
        Used when an agent needs a response from another agent.
        """
        import threading, uuid
        reply_channel = f"reply_{uuid.uuid4().hex[:8]}"
        result = {}
        event = threading.Event()

        def on_reply(sender, data):
            result["data"] = data
            event.set()

        self.subscribe(reply_channel, on_reply)
        payload["_reply_to"] = reply_channel
        self.publish(from_agent, to_agent, payload)

        got_reply = event.wait(timeout=timeout)
        if not got_reply:
            log.warning(f"request_reply timeout: {from_agent} → {to_agent}")
            return None
        return result.get("data")
