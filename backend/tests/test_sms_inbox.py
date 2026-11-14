import asyncio
import unittest
import unittest.mock
from datetime import datetime

from app.db.database import InMemoryMongoClient, connect_db
import app.db.database as db_module
from app.ml.predictor import load_models
from app.services.sms_service import (
    connect_sms_phone,
    delete_sms_message,
    disconnect_sms_phone,
    get_single_sms,
    get_sms_status,
    ingest_sms_message,
    list_sms_messages,
    resolve_user_by_sync_token,
    simulate_sms_message,
    import_sms_batch,
)


class TestSMSInbox(unittest.IsolatedAsyncioTestCase):
    @classmethod
    def setUpClass(cls):
        load_models()

    async def asyncSetUp(self):
        # Use a fresh in-memory database for isolation
        self.mock_client = InMemoryMongoClient()
        self.patcher = unittest.mock.patch.object(db_module, "client", self.mock_client)
        self.patcher.start()

    async def asyncTearDown(self):
        self.patcher.stop()

    async def test_connect_and_status(self):
        user_id = "user-alice-123"
        status = await get_sms_status(user_id)
        self.assertFalse(status.connected)

        connected = await connect_sms_phone(user_id, "+14155552671")
        self.assertTrue(connected.connected)
        self.assertEqual(connected.phone_number, "+14155552671")
        self.assertTrue(connected.sync_token.startswith("scam_sms_"))

        # Verify resolve by sync token
        resolved_user = await resolve_user_by_sync_token(connected.sync_token)
        self.assertEqual(resolved_user, user_id)

    async def test_ingest_and_scam_detection(self):
        user_id = "user-bob-456"
        await connect_sms_phone(user_id, "+12125559876")

        # Ingest a safe bank OTP message with shortcode 8558
        safe_item = await ingest_sms_message(
            user_id=user_id,
            sender_id="8558",
            message="Your Chase banking security code is 782910. Never share this code with anyone.",
        )
        self.assertEqual(safe_item.scam_level, "safe")
        self.assertLess(safe_item.confidence, 0.40)
        self.assertFalse(safe_item.is_read)

        # Ingest a smishing phishing attack
        scam_item = await ingest_sms_message(
            user_id=user_id,
            sender_id="+14159821102",
            message="USPS: Your parcel has arrived at our warehouse but cannot be shipped due to missing house number. Update immediately: http://usps-parcel-redirection-notice.xyz/update",
        )
        self.assertEqual(scam_item.scam_level, "scam")
        self.assertGreaterEqual(scam_item.confidence, 0.70)
        self.assertTrue(len(scam_item.reasons) > 0)

        # Verify inbox listing and counts
        inbox = await list_sms_messages(user_id=user_id)
        self.assertEqual(inbox.total, 2)
        self.assertEqual(inbox.scam_count, 1)
        self.assertEqual(inbox.safe_count, 1)

    async def test_filter_and_search(self):
        user_id = "user-carol-789"
        await connect_sms_phone(user_id, "+13125551234")

        await ingest_sms_message(
            user_id=user_id,
            sender_id="8558",
            message="Chase security code: 112233",
        )
        await ingest_sms_message(
            user_id=user_id,
            sender_id="+19293021944",
            message="URGENT: Wells Fargo account locked. Verify at http://wellsfargo-secure.xyz",
        )

        # Filter by scam_level
        scam_inbox = await list_sms_messages(user_id=user_id, scam_level="scam")
        self.assertEqual(len(scam_inbox.messages), 1)
        self.assertEqual(scam_inbox.messages[0].sender_id, "+19293021944")

        # Search by keyword
        search_inbox = await list_sms_messages(user_id=user_id, search="Chase")
        self.assertEqual(len(search_inbox.messages), 1)
        self.assertEqual(search_inbox.messages[0].sender_id, "8558")

    async def test_multi_user_isolation(self):
        user_a = "user-a"
        user_b = "user-b"
        await connect_sms_phone(user_a, "+11111111111")
        await connect_sms_phone(user_b, "+22222222222")

        item_a = await ingest_sms_message(
            user_id=user_a,
            sender_id="8558",
            message="User A secret code",
        )
        item_b = await ingest_sms_message(
            user_id=user_b,
            sender_id="3737",
            message="User B secret bill",
        )

        # User A inbox only sees User A's messages
        inbox_a = await list_sms_messages(user_id=user_a)
        self.assertEqual(inbox_a.total, 1)
        self.assertEqual(inbox_a.messages[0].id, item_a.id)

        # User B cannot read or delete User A's message
        self.assertIsNone(await get_single_sms(user_id=user_b, message_id=item_a.id))
        deleted_by_b = await delete_sms_message(user_id=user_b, message_id=item_a.id)
        self.assertFalse(deleted_by_b)

        # User A can delete their own message
        deleted_by_a = await delete_sms_message(user_id=user_a, message_id=item_a.id)
        self.assertTrue(deleted_by_a)
        inbox_a_after = await list_sms_messages(user_id=user_a)
        self.assertEqual(inbox_a_after.total, 0)

    async def test_simulation_presets(self):
        user_id = "user-sim-999"
        await connect_sms_phone(user_id, "+15550001111")

        simulated_scam = await simulate_sms_message(user_id=user_id, preset="package_delivery_scam")
        self.assertEqual(simulated_scam.scam_level, "scam")
        self.assertIn("USPS", simulated_scam.message)

        simulated_safe = await simulate_sms_message(user_id=user_id, preset="bank_otp_safe")
        self.assertEqual(simulated_safe.scam_level, "safe")
        self.assertEqual(simulated_safe.sender_id, "8558")

    async def test_batch_import(self):
        user_id = "user-batch-101"
        await connect_sms_phone(user_id, "+15551112222")

        batch_data = [
            {"sender_id": "8558", "message": "Chase OTP: 991827. Valid for 10 min."},
            {"sender_id": "3737", "message": "Monthly carrier renewal of $45."},
            {"sender_id": "+14159821102", "message": "USPS: Delivery failed due to address error. Update immediately at http://usps-parcel-redirection-notice.xyz/update"},
        ]

        res = await import_sms_batch(user_id=user_id, items=batch_data)
        self.assertEqual(res["imported_count"], 3)
        self.assertEqual(res["scam_count"], 1)
        self.assertEqual(res["safe_count"], 2)

        inbox = await list_sms_messages(user_id=user_id)
        self.assertEqual(inbox.total, 3)

    async def test_disconnect(self):
        user_id = "user-disc-000"
        await connect_sms_phone(user_id, "+14155550000")
        status = await disconnect_sms_phone(user_id)
        self.assertFalse(status.connected)

        token = await resolve_user_by_sync_token("some_token")
        self.assertIsNone(token)


if __name__ == "__main__":
    unittest.main()

