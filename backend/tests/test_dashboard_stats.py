import unittest
from datetime import datetime, timezone, timedelta
from fastapi.testclient import TestClient
from main import app
from app.core.security import create_access_token
from app.db.database import get_db

class DashboardStatsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.client = TestClient(app)
        cls.user_id = "test-dashboard-user-123"
        cls.token = create_access_token({"sub": cls.user_id, "email": "dash_test@example.com"})
        cls.headers = {"Authorization": f"Bearer {cls.token}"}

    def test_dashboard_stats_endpoint_returns_aggregated_metrics(self):
        with TestClient(app) as client:
            resp = client.get("/api/dashboard/stats", headers=self.headers)
            self.assertEqual(resp.status_code, 200)
            data = resp.json()

            # Verify response schema structure
            self.assertIn("total", data)
            self.assertIn("scam_count", data)
            self.assertIn("suspicious_count", data)
            self.assertIn("safe_count", data)
            self.assertIn("by_type", data)
            self.assertIn("trend", data)
            self.assertIn("recent", data)
            self.assertIn("security_score", data)

            # by_type keys
            self.assertIn("email", data["by_type"])
            self.assertIn("sms", data["by_type"])
            self.assertIn("url", data["by_type"])

            # trend structure
            self.assertEqual(len(data["trend"]), 7)
            for day in data["trend"]:
                self.assertIn("date", day)
                self.assertIn("day_name", day)
                self.assertIn("count", day)
                self.assertIn("scams", day)
                self.assertIn("suspicious", day)
                self.assertIn("safe", day)
                self.assertEqual(day["count"], day["scams"] + day["suspicious"] + day["safe"])

            # total matches level sums
            self.assertEqual(data["total"], data["scam_count"] + data["suspicious_count"] + data["safe_count"])

if __name__ == "__main__":
    unittest.main()

