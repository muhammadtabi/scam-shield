import unittest

from app.core.config import settings
from app.db import database


class DatabaseFallbackTests(unittest.IsolatedAsyncioTestCase):
    async def test_connect_db_falls_back_to_in_memory_when_atlas_is_unreachable(self):
        original_url = settings.MONGODB_URL
        original_db = settings.DATABASE_NAME
        settings.MONGODB_URL = "mongodb+srv://bad-host.invalid/test"
        settings.DATABASE_NAME = "scamshield"

        try:
            await database.connect_db()
            db = database.get_db()
            result = await db.users.insert_one({"email": "demo@example.com", "full_name": "Demo User"})
            saved = await db.users.find_one({"_id": result.inserted_id})
            self.assertIsNotNone(saved)
            self.assertEqual(saved["email"], "demo@example.com")

            # Mutating returned cursor/find documents must not corrupt stored _id in fallback DB.
            saved.pop("_id", None)
            items = [doc async for doc in db.users.find({"email": "demo@example.com"})]
            self.assertEqual(len(items), 1)
            self.assertIn("_id", items[0])
            items[0].pop("_id")
            items_again = [doc async for doc in db.users.find({"email": "demo@example.com"})]
            self.assertIn("_id", items_again[0])
        finally:
            await database.close_db()
            settings.MONGODB_URL = original_url
            settings.DATABASE_NAME = original_db


if __name__ == "__main__":
    unittest.main()
