import time
from collections import defaultdict
from threading import Lock
from fastapi import Request, HTTPException, status


class IPRateLimiter:
    """
    In-memory thread-safe sliding-window rate limiter by client IP.
    """
    def __init__(self, max_requests: int = 10, window_seconds: int = 60):
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self._requests = defaultdict(list)
        self._lock = Lock()

    def get_client_ip(self, request: Request) -> str:
        forwarded = request.headers.get("x-forwarded-for")
        if forwarded:
            ip = forwarded.split(",")[0].strip()
            if ip:
                return ip
        if request.client and request.client.host:
            return request.client.host
        return "127.0.0.1"

    async def __call__(self, request: Request):
        client_ip = self.get_client_ip(request)
        now = time.monotonic()
        cutoff = now - self.window_seconds

        with self._lock:
            # Filter timestamps within current window
            valid_timestamps = [t for t in self._requests[client_ip] if t > cutoff]
            if len(valid_timestamps) >= self.max_requests:
                oldest_in_window = valid_timestamps[0]
                retry_after = max(1, int(oldest_in_window + self.window_seconds - now))
                raise HTTPException(
                    status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                    detail="Too many login attempts. Please try again later.",
                    headers={"Retry-After": str(retry_after)}
                )

            valid_timestamps.append(now)
            self._requests[client_ip] = valid_timestamps

            # Periodic cleanup if registry grows large
            if len(self._requests) > 1000:
                expired_keys = [k for k, v in self._requests.items() if not v or v[-1] <= cutoff]
                for k in expired_keys:
                    self._requests.pop(k, None)

    def reset(self):
        """Reset the rate limiter state (useful in tests)."""
        with self._lock:
            self._requests.clear()


login_rate_limiter = IPRateLimiter(max_requests=10, window_seconds=60)
