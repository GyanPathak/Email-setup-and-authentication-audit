
import math
import threading
import time

from collections import deque


class InMemoryRateLimiter:
    def __init__(
        self,
        limit: int = 10,
        window_seconds: int = 60,
    ):
        self.limit = limit
        self.window_seconds = window_seconds
        self.requests: dict[str, deque[float]] = {}
        self.lock = threading.Lock()
        self.last_cleanup = 0.0

    def is_allowed(self, client_ip: str) -> tuple[bool, int]:
        now = time.monotonic()
        cutoff = now - self.window_seconds

        with self.lock:
            # Periodically remove inactive IP addresses.
            if now - self.last_cleanup >= self.window_seconds:
                expired_ips = [
                    ip
                    for ip, timestamps in self.requests.items()
                    if not timestamps or timestamps[-1] <= cutoff
                ]

                for ip in expired_ips:
                    del self.requests[ip]

                self.last_cleanup = now

            timestamps = self.requests.setdefault(
                client_ip, deque()
            )

            # Remove requests outside the rolling time window.
            while timestamps and timestamps[0] <= cutoff:
                timestamps.popleft()

            if len(timestamps) >= self.limit:
                retry_after = math.ceil(
                    self.window_seconds - (now - timestamps[0])
                )

                return False, max(1, retry_after)

            timestamps.append(now)
            return True, 0

    def reset(self) -> None:
        """Reset stored requests. Useful for isolated tests."""
        with self.lock:
            self.requests.clear()
            self.last_cleanup = 0.0
