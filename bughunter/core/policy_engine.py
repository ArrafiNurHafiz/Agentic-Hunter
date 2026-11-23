"""Thread-safe rate, concurrency, request budget and error controls."""
import threading
import time
from contextlib import contextmanager


class PolicyEngine:
    def __init__(self, rps=5, concurrency=2, error_threshold=5, budget=1000):
        if rps <= 0 or concurrency < 1 or error_threshold < 1 or budget < 1:
            raise ValueError('policy limits must be positive')
        self.rps, self.error_threshold, self.budget = rps, error_threshold, budget
        self._lock = threading.Lock()
        self._semaphore = threading.BoundedSemaphore(concurrency)
        self._next = 0.0
        self.errors = 0
        self.used = 0

    @contextmanager
    def request(self):
        with self._semaphore:
            with self._lock:
                if self.errors >= self.error_threshold:
                    raise RuntimeError('circuit breaker open')
                if self.used >= self.budget:
                    raise RuntimeError('request budget exhausted')
                self.used += 1
                now = time.monotonic()
                delay = max(0, self._next - now)
                self._next = max(now, self._next) + 1 / self.rps
            time.sleep(delay)
            yield

    def record(self, status):
        with self._lock:
            self.errors = self.errors + 1 if status >= 500 else 0
