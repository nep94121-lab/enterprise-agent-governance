"""
Domain A: Programming Safety Relays Framework
Provides circuit breakers to prevent infinite loops, resource exhaustion, and cascading failures.
"""
import time
import functools

class SafetyRelayException(Exception):
    pass

class LoopBreaker:
    def __init__(self, max_iterations=10000):
        self.max_iterations = max_iterations
        self.count = 0

    def tick(self):
        self.count += 1
        if self.count > self.max_iterations:
            raise SafetyRelayException(f"Infinite loop detected. Iterations exceeded {self.max_iterations}.")

class CascadeBreaker:
    def __init__(self, failure_threshold=5, recovery_timeout=30):
        self.failure_threshold = failure_threshold
        self.recovery_timeout = recovery_timeout
        self.failures = 0
        self.last_failure_time = 0
        self.state = "CLOSED"  # CLOSED, OPEN, HALF_OPEN

    def call(self, func, *args, **kwargs):
        now = time.time()
        if self.state == "OPEN":
            if now - self.last_failure_time > self.recovery_timeout:
                self.state = "HALF_OPEN"
            else:
                raise SafetyRelayException("Cascade breaker is OPEN.")
        
        try:
            result = func(*args, **kwargs)
            if self.state == "HALF_OPEN":
                self.state = "CLOSED"
                self.failures = 0
            return result
        except Exception as e:
            self.failures += 1
            self.last_failure_time = now
            if self.failures >= self.failure_threshold:
                self.state = "OPEN"
            raise e

def with_lock_timeout(timeout=5.0):
    def decorator(func):
        @functools.wraps(func)
        def wrapper(lock, *args, **kwargs):
            if not lock.acquire(timeout=timeout):
                raise SafetyRelayException(f"Lock acquisition timed out after {timeout} seconds.")
            try:
                return func(lock, *args, **kwargs)
            finally:
                lock.release()
        return wrapper
    return decorator
