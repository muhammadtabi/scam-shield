import unittest
from unittest.mock import patch
from fastapi.testclient import TestClient
from pymongo.errors import DuplicateKeyError
from main import app


class AuthDuplicateKeyTests(unittest.TestCase):
    def test_duplicate_key_error_returns_400(self):
        with TestClient(app) as client:
            payload = {
                "full_name": "Test User",
                "email": "duplicate_test_unique@example.com",
                "password": "SecurePassword123!"
            }

            # First register or mock DuplicateKeyError on insert_one
            with patch("app.db.database.InMemoryCollection.insert_one", side_effect=DuplicateKeyError("duplicate key")):
                # Also mock on AsyncIOMotorCollection if real Atlas is connected
                with patch("motor.motor_asyncio.AsyncIOMotorCollection.insert_one", side_effect=DuplicateKeyError("duplicate key")):
                    resp = client.post("/api/auth/register", json=payload)
                    self.assertEqual(resp.status_code, 400)
                    self.assertEqual(resp.json()["detail"], "Email already registered")


if __name__ == "__main__":
    unittest.main()
