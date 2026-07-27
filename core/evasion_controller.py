"""
Adaptive Latency Controller
Dynamically adjusts request delays to evade WAF/IPS detection.
"""
import time
import random


class EvasionController:
    def __init__(self, base_delay: float = 1.0, max_delay: float = 10.0):
        self.base_delay = base_delay
        self.max_delay = max_delay
        self.current_delay = base_delay
        self.strike_count = 0

    def record_success(self):
        """Reduce latency on success."""
        self.strike_count = max(0, self.strike_count - 1)
        self.current_delay = max(self.base_delay, self.current_delay * 0.8)

    def record_block(self):
        """Increase latency exponentially on block."""
        self.strike_count += 1
        jitter = random.uniform(0.1, 0.5)
        self.current_delay = min(
            self.max_delay,
            (self.current_delay * 2) + jitter)

    def wait(self):
        """Wait for the calculated latency period."""
        time.sleep(self.current_delay)
