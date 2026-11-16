import unittest
from types import SimpleNamespace
from unittest.mock import patch

from app.core.security import decrypt_secret
from app.db.database import InMemoryCollection
from app.services import gmail_monitor


class GmailOAuthEncryptionTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.mem_db = SimpleNamespace(
            gmail_connections=InMemoryCollection("gmail_connections"),
            detections=InMemoryCollection("detections"),
        )

    async def test_save_gmail_connection_encrypts_tokens_at_rest(self):
        user_id = "user-oauth-encrypted-1"
        plain_access = "ya29.a0AfH6SMD_very_secret_oauth_access_token_12345"
        plain_refresh = "1//04_very_secret_oauth_refresh_token_67890"

        with patch.object(gmail_monitor, "get_db", return_value=self.mem_db):
            await gmail_monitor.save_gmail_connection(
                user_id=user_id,
                tokens={
                    "access_token": plain_access,
                    "refresh_token": plain_refresh,
                    "expires_in": 3600,
                    "token_type": "Bearer",
                },
                profile={"emailAddress": "security_test@example.com"},
            )

            # 1. Inspect raw document in MongoDB
            stored = await self.mem_db.gmail_connections.find_one({"user_id": user_id})
            self.assertIsNotNone(stored)

            # Tokens must NEVER be stored as raw plaintext in the database
            self.assertNotEqual(stored["access_token"], plain_access)
            self.assertNotEqual(stored["refresh_token"], plain_refresh)

            # Decrypting via secret key restores exact original plaintext
            self.assertEqual(decrypt_secret(stored["access_token"]), plain_access)
            self.assertEqual(decrypt_secret(stored["refresh_token"]), plain_refresh)

            # 2. _ensure_access_token transparently decrypts and returns plaintext access token
            resolved_token = await gmail_monitor._ensure_access_token(stored)
            self.assertEqual(resolved_token, plain_access)

    async def test_ensure_access_token_handles_legacy_unencrypted_tokens(self):
        # Backward compatibility test for existing unencrypted rows
        user_id = "user-legacy-plain"
        legacy_plain_token = "legacy_unencrypted_access_token"

        stored_legacy = {
            "user_id": user_id,
            "access_token": legacy_plain_token,
            "refresh_token": None,
            "expires_at": 9999999999.0,
        }

        resolved = await gmail_monitor._ensure_access_token(stored_legacy)
        self.assertEqual(resolved, legacy_plain_token)


if __name__ == "__main__":
    unittest.main()
