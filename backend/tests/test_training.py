import unittest
from fastapi.testclient import TestClient
from main import app
from app.core.security import create_access_token
from app.db.database import InMemoryMongoClient, connect_db
import app.db.database as db_module
from app.ml.predictor import load_models

class TestTrainingModule(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        load_models()
        cls.token = create_access_token(data={"sub": "training_tester_42"})
        cls.headers = {"Authorization": f"Bearer {cls.token}"}

    def setUp(self):
        self.mock_client = InMemoryMongoClient()
        self.orig_client = db_module.client
        db_module.client = self.mock_client

    def tearDown(self):
        db_module.client = self.orig_client

    def test_list_scenarios_requires_auth_and_returns_public_data(self):
        with TestClient(app) as client:
            # Unauthenticated should fail
            unauth = client.get("/api/training/scenarios")
            self.assertIn(unauth.status_code, (401, 403))

            # Authenticated returns scenario list
            res = client.get("/api/training/scenarios", headers=self.headers)
            self.assertEqual(res.status_code, 200)
            data = res.json()
            self.assertIsInstance(data, list)
            self.assertGreaterEqual(len(data), 6)

            # Verify public sanitization: actual_verdict or key_takeaway should not be leaked in public list
            first = data[0]
            self.assertIn("id", first)
            self.assertIn("type", first)
            self.assertIn("clue_options", first)
            self.assertNotIn("actual_verdict", first)
            self.assertNotIn("key_takeaway", first)

    def test_submit_correct_and_incorrect_evaluation(self):
        with TestClient(app) as client:
            # 1. Submit correct answer for netflix scam
            req_correct = {
                "scenario_id": "scn_email_netflix_scam",
                "user_verdict": "scam",
                "selected_clues": [
                    "Mismatched sender domain (netflx-account-renew.xyz instead of netflix.com)",
                    "Artificial 24-hour urgency deadline"
                ]
            }
            res_c = client.post("/api/training/submit", json=req_correct, headers=self.headers)
            self.assertEqual(res_c.status_code, 200)
            eval_c = res_c.json()
            self.assertTrue(eval_c["is_correct"])
            self.assertEqual(eval_c["actual_verdict"], "scam")
            self.assertGreater(eval_c["total_score"], 100) # Base 100 + clues
            self.assertIn("key_takeaway", eval_c)
            self.assertIn("ml_confidence", eval_c)

            # 2. Submit incorrect answer for chase otp (mark safe as scam)
            req_wrong = {
                "scenario_id": "scn_sms_chase_otp_safe",
                "user_verdict": "scam",
                "selected_clues": []
            }
            res_w = client.post("/api/training/submit", json=req_wrong, headers=self.headers)
            self.assertEqual(res_w.status_code, 200)
            eval_w = res_w.json()
            self.assertFalse(eval_w["is_correct"])
            self.assertEqual(eval_w["actual_verdict"], "safe")

            # 3. Check stats
            stats_res = client.get("/api/training/stats", headers=self.headers)
            self.assertEqual(stats_res.status_code, 200)
            stats = stats_res.json()
            self.assertEqual(stats["total_attempted"], 2)
            self.assertEqual(stats["total_correct"], 1)
            self.assertEqual(stats["accuracy_percent"], 50.0)

            # 4. Reset progress
            reset_res = client.post("/api/training/reset", headers=self.headers)
            self.assertEqual(reset_res.status_code, 200)

            # 5. Check stats after reset
            stats_after = client.get("/api/training/stats", headers=self.headers).json()
            self.assertEqual(stats_after["total_attempted"], 0)
            self.assertEqual(stats_after["accuracy_percent"], 0.0)

    def test_invalid_scenario_id_returns_404(self):
        with TestClient(app) as client:
            res = client.post(
                "/api/training/submit",
                json={"scenario_id": "nonexistent_id", "user_verdict": "safe"},
                headers=self.headers
            )
            self.assertEqual(res.status_code, 404)
