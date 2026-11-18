import unittest
from fastapi.testclient import TestClient
from main import app
from app.core.rate_limit import login_rate_limiter


class AuthRateLimitTests(unittest.TestCase):
    def setUp(self):
        login_rate_limiter.reset()

    def tearDown(self):
        login_rate_limiter.reset()

    def test_login_rate_limit_exceeded(self):
        with TestClient(app) as client:
            payload = {
                "email": "ratelimit_user@example.com",
                "password": "wrongpassword"
            }

            # 10 allowed requests (which may return 401 for wrong credentials)
            for _ in range(10):
                resp = client.post("/api/auth/login", json=payload)
                self.assertEqual(resp.status_code, 401)

            # 11th request must be rate limited (429)
            resp_blocked = client.post("/api/auth/login", json=payload)
            self.assertEqual(resp_blocked.status_code, 429)
            self.assertIn("Too many login attempts", resp_blocked.json()["detail"])
            self.assertIn("retry-after", resp_blocked.headers)


if __name__ == "__main__":
    unittest.main()
