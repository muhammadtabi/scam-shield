import unittest
from unittest.mock import MagicMock, patch

from app.services import gmail_monitor


class FakeCollection:
    async def find_one(self, *args, **kwargs):
        return None


class FakeDB:
    detections = FakeCollection()


class StaleCollection:
    async def find_one(self, *args, **kwargs):
        return {"_id": "old-detection", "scam_level": "scam", "detector_version": 1}


class StaleDB:
    detections = StaleCollection()


class GmailInboxPerformanceTests(unittest.IsolatedAsyncioTestCase):
    @classmethod
    def setUpClass(cls):
        from app.ml import predictor
        predictor.load_models()

    async def test_list_gmail_inbox_uses_lightweight_metadata_without_fetching_full_messages(self):
        fetch_message = MagicMock(side_effect=AssertionError("list endpoint should not fetch full message bodies"))

        with patch.object(gmail_monitor, "get_gmail_connection", return_value={"user_id": "user-1", "enabled": True}), \
             patch.object(gmail_monitor, "get_db", return_value=FakeDB()), \
             patch.object(gmail_monitor, "_ensure_access_token", return_value="token-123"), \
             patch.object(gmail_monitor, "_list_recent_message_ids", return_value=[{"id": "m1", "snippet": "Hello there"}, {"id": "m2", "snippet": "Bank transfer"}]), \
             patch.object(gmail_monitor, "_fetch_message", fetch_message), \
             patch.object(gmail_monitor, "_fetch_message_metadata", side_effect=[
                 {"internalDate": "1710000000000", "payload": {"headers": [{"name": "Subject", "value": "First message"}, {"name": "From", "value": "Alice <alice@example.com>"}, {"name": "Date", "value": "Mon, 01 Jan 2024 10:00:00 +0000"}]}},
                 {"internalDate": "1710001000000", "payload": {"headers": [{"name": "Subject", "value": "Second message"}, {"name": "From", "value": "Bob <bob@example.com>"}, {"name": "Date", "value": "Mon, 01 Jan 2024 10:15:00 +0000"}]}}
             ]) as metadata_fetch:

            results = await gmail_monitor.list_gmail_inbox("user-1", max_results=2)

        self.assertEqual(len(results), 2)
        self.assertEqual(results[0]["id"], "m1")
        self.assertEqual(results[0]["subject"], "First message")
        self.assertEqual(results[0]["sender"], "Alice <alice@example.com>")
        self.assertEqual(results[0]["snippet"], "Hello there")
        self.assertEqual(results[1]["id"], "m2")
        self.assertEqual(results[1]["subject"], "Second message")
        self.assertEqual(results[1]["sender"], "Bob <bob@example.com>")
        self.assertEqual(results[1]["date"], "1710001000000")
        self.assertEqual(metadata_fetch.call_count, 2)
        fetch_message.assert_not_called()

    async def test_old_detection_policy_results_are_hidden_until_reverified(self):
        with patch.object(gmail_monitor, "get_gmail_connection", return_value={"user_id": "user-1", "enabled": True}), \
             patch.object(gmail_monitor, "get_db", return_value=StaleDB()), \
             patch.object(gmail_monitor, "_ensure_access_token", return_value="token-123"), \
             patch.object(gmail_monitor, "_list_recent_message_ids", return_value=[{"id": "m1", "snippet": "Transaction"}]), \
             patch.object(gmail_monitor, "_fetch_message_metadata", return_value={"payload": {"headers": [{"name": "Subject", "value": "Transaction completed"}, {"name": "From", "value": "service@example.com"}]}}):

            results = await gmail_monitor.list_gmail_inbox("user-1", max_results=1)

        self.assertIsNone(results[0]["scan"])

    def test_normalize_message_extracts_html_links_and_auth_metadata(self):
        import base64

        html_doc = '<p>Verify at <a href="http://evil-verify.xyz/login">https://paypal.com</a></p>'
        encoded = base64.urlsafe_b64encode(html_doc.encode()).decode().rstrip("=")
        msg = {
            "snippet": "Verify account",
            "payload": {
                "mimeType": "text/html",
                "headers": [
                    {"name": "Subject", "value": "Security Alert"},
                    {"name": "From", "value": "PayPal <support@evil-verify.xyz>"},
                    {"name": "Reply-To", "value": "scammer99@gmail.com"},
                    {"name": "Authentication-Results", "value": "mx.google.com; spf=fail"},
                ],
                "body": {"data": encoded},
            },
        }
        norm = gmail_monitor._normalize_message(msg)
        self.assertIn("Verify at", norm["body"])
        self.assertEqual(norm["metadata"]["reply_to"], "scammer99@gmail.com")
        self.assertIn("spf=fail", norm["metadata"]["authentication_results"])
        self.assertEqual(norm["metadata"]["html_links"][0][0], "http://evil-verify.xyz/login")

    async def test_sync_gmail_account_upserts_without_duplicates_and_keeps_input_data(self):
        import base64
        from types import SimpleNamespace
        from app.db.database import InMemoryCollection

        mem_db = SimpleNamespace(
            detections=InMemoryCollection("detections"),
            gmail_connections=InMemoryCollection("gmail_connections"),
        )
        await mem_db.gmail_connections.insert_one(
            {
                "user_id": "user-1",
                "enabled": True,
                "access_token": "tok-1",
                "processed_message_ids": [],
            }
        )
        raw_body = base64.urlsafe_b64encode(b"Hello from Jobseeker Team").decode().rstrip("=")
        fake_msg = {
            "id": "m-sync-1",
            "threadId": "th-1",
            "historyId": "h-1",
            "snippet": "Hello",
            "payload": {
                "mimeType": "text/plain",
                "headers": [
                    {"name": "Subject", "value": "Weekly Update"},
                    {"name": "From", "value": "Team <updates@example.com>"},
                ],
                "body": {"data": raw_body},
            },
        }

        with patch.object(gmail_monitor, "get_db", return_value=mem_db), \
             patch.object(gmail_monitor, "_ensure_access_token", return_value="tok-1"), \
             patch.object(gmail_monitor, "_list_recent_message_ids", return_value=[{"id": "m-sync-1"}]), \
             patch.object(gmail_monitor, "_fetch_message", return_value=fake_msg):
            first = await gmail_monitor.sync_gmail_account("user-1", max_messages=5)
            # Simulate reconnect resetting processed_message_ids
            await mem_db.gmail_connections.update_one(
                {"user_id": "user-1"},
                {"$set": {"processed_message_ids": []}},
            )
            second = await gmail_monitor.sync_gmail_account("user-1", max_messages=5)

        self.assertEqual(first["processed"], 1)
        self.assertEqual(second["processed"], 1)
        total_docs = await mem_db.detections.count_documents({"user_id": "user-1", "gmail_message_id": "m-sync-1"})
        self.assertEqual(total_docs, 1)
        stored = await mem_db.detections.find_one({"user_id": "user-1", "gmail_message_id": "m-sync-1"})
        self.assertEqual(stored["input_data"], {"subject": "Weekly Update", "sender": "Team <updates@example.com>"})
        self.assertEqual(stored["detector_version"], gmail_monitor.DETECTION_POLICY_VERSION)

    async def test_list_gmail_inbox_scopes_cached_detection_by_user_id(self):
        from types import SimpleNamespace
        from app.db.database import InMemoryCollection

        mem_db = SimpleNamespace(
            detections=InMemoryCollection("detections"),
            gmail_connections=InMemoryCollection("gmail_connections"),
        )
        await mem_db.detections.insert_one(
            {
                "user_id": "other-user",
                "gmail_message_id": "m-shared-1",
                "detector_version": gmail_monitor.DETECTION_POLICY_VERSION,
                "scam_level": "scam",
            }
        )

        with patch.object(gmail_monitor, "get_gmail_connection", return_value={"user_id": "user-1", "enabled": True}), \
             patch.object(gmail_monitor, "get_db", return_value=mem_db), \
             patch.object(gmail_monitor, "_ensure_access_token", return_value="tok-1"), \
             patch.object(gmail_monitor, "_list_recent_message_ids", return_value=[{"id": "m-shared-1", "snippet": "Hi"}]), \
             patch.object(gmail_monitor, "_fetch_message_metadata", return_value={"payload": {"headers": [{"name": "Subject", "value": "Hi"}, {"name": "From", "value": "Alice <alice@example.com>"}]}}):
            results = await gmail_monitor.list_gmail_inbox("user-1", max_results=1)

        self.assertIsNone(results[0]["scan"])

    async def test_gmail_callback_redirects_gracefully_on_errors_and_success(self):
        from datetime import timedelta
        from app.api.routes import gmail as gmail_routes
        from app.core.security import create_access_token

        denied = await gmail_routes.gmail_callback(code="", state=None, error="access_denied")
        self.assertEqual(denied.status_code, 307)
        self.assertIn("gmail=error", denied.headers["location"])
        self.assertIn("access+was+denied", denied.headers["location"])

        bad_state = await gmail_routes.gmail_callback(code="abc", state="invalid-token", error=None)
        self.assertEqual(bad_state.status_code, 307)
        self.assertIn("gmail=error", bad_state.headers["location"])
        self.assertIn("expired", bad_state.headers["location"])

        valid_state = create_access_token(
            {"sub": "user-1", "purpose": "gmail_connect"},
            expires_delta=timedelta(minutes=5),
        )
        with patch.object(gmail_routes, "_finish_gmail_connection", return_value={"enabled": True}):
            ok_resp = await gmail_routes.gmail_callback(code="auth-code-123", state=valid_state, error=None)
        self.assertEqual(ok_resp.status_code, 307)
        self.assertTrue(ok_resp.headers["location"].endswith("/?gmail=connected"))

    def test_status_from_connection_handles_naive_and_aware_datetimes(self):
        from datetime import datetime, timezone
        from app.api.routes import gmail as gmail_routes

        naive_dt = datetime(2026, 11, 17, 17, 14, 23)
        status_naive = gmail_routes._status_from_connection({
            "enabled": True,
            "gmail_email": "test@example.com",
            "last_checked_at": naive_dt,
        })
        self.assertIsNotNone(status_naive.last_checked_at)
        self.assertEqual(status_naive.last_checked_at.tzinfo, timezone.utc)

        status_none = gmail_routes._status_from_connection(None)
        self.assertFalse(status_none.connected)
        self.assertIsNone(status_none.last_checked_at)


if __name__ == "__main__":
    unittest.main()
