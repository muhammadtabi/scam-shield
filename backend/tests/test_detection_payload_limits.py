import unittest
from fastapi.testclient import TestClient
from main import app
from app.core.security import create_access_token


class DetectionPayloadLimitsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.user_id = "test-limits-user-42"
        cls.token = create_access_token({"sub": cls.user_id, "email": "limits@example.com"})
        cls.headers = {"Authorization": f"Bearer {cls.token}"}

    def test_email_payload_length_limits(self):
        with TestClient(app) as client:
            # Huge body exceeds max_length 200000
            huge_body = "A" * 200001
            resp = client.post(
                "/api/detect/email",
                headers=self.headers,
                json={"subject": "Test", "sender": "test@example.com", "body": huge_body}
            )
            self.assertEqual(resp.status_code, 422)

    def test_sms_payload_length_limits(self):
        with TestClient(app) as client:
            # Huge message exceeds max_length 5000
            huge_msg = "A" * 5001
            resp = client.post(
                "/api/detect/sms",
                headers=self.headers,
                json={"sender_id": "+12345678901", "message": huge_msg}
            )
            self.assertEqual(resp.status_code, 422)

    def test_url_payload_length_limits(self):
        with TestClient(app) as client:
            # Huge URL exceeds max_length 2048
            huge_url = "http://example.com/" + ("a" * 2050)
            resp = client.post(
                "/api/detect/url",
                headers=self.headers,
                json={"url": huge_url}
            )
            self.assertEqual(resp.status_code, 422)

    def test_history_pagination_bounds(self):
        with TestClient(app) as client:
            # limit > 100
            resp_high = client.get("/api/detect/history?limit=101", headers=self.headers)
            self.assertEqual(resp_high.status_code, 422)

            # limit < 1
            resp_low = client.get("/api/detect/history?limit=0", headers=self.headers)
            self.assertEqual(resp_low.status_code, 422)

            # skip < 0
            resp_neg = client.get("/api/detect/history?skip=-1", headers=self.headers)
            self.assertEqual(resp_neg.status_code, 422)

            # valid bounds
            resp_ok = client.get("/api/detect/history?limit=50&skip=10", headers=self.headers)
            self.assertEqual(resp_ok.status_code, 200)


if __name__ == "__main__":
    unittest.main()
