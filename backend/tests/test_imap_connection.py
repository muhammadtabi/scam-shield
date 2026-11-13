import unittest
from types import SimpleNamespace
from unittest.mock import patch

from pydantic import ValidationError

from app.core.security import decrypt_secret, encrypt_secret
from app.db.database import InMemoryCollection
from app.schemas.gmail import GmailImapConnectRequest
from app.services import gmail_monitor, imap_client


class ImapConnectionTests(unittest.IsolatedAsyncioTestCase):
    def test_app_password_encryption_and_schema_validation(self):
        secret = "abcd efgh ijkl mnop"
        req = GmailImapConnectRequest(email="someone@gmail.com", app_password=secret, provider="gmail")
        self.assertEqual(req.app_password, "abcdefghijklmnop")

        cipher = encrypt_secret(req.app_password)
        self.assertNotIn("abcdefghijklmnop", cipher)
        self.assertEqual(decrypt_secret(cipher), "abcdefghijklmnop")

        tampered = cipher[:12] + ("A" if cipher[12] != "A" else "B") + cipher[13:]
        with self.assertRaises(ValueError):
            decrypt_secret(tampered)

        with self.assertRaises(ValidationError):
            GmailImapConnectRequest(email="someone@gmail.com", app_password="short", provider="gmail")

        with self.assertRaises(ValidationError):
            GmailImapConnectRequest(email="someone@gmail.com", app_password=secret, provider="127.0.0.1")

    def test_parse_rfc822_message_extracts_headers_html_links_and_auth(self):
        raw = (
            b"From: PayPal <support@evil-verify.xyz>\r\n"
            b"Reply-To: scammer@gmail.com\r\n"
            b"Subject: Action Required\r\n"
            b"Authentication-Results: mx.google.com; spf=fail\r\n"
            b"MIME-Version: 1.0\r\n"
            b"Content-Type: text/html; charset=utf-8\r\n\r\n"
            b'<p>Verify <a href="http://evil-verify.xyz/login">https://paypal.com</a></p>'
        )
        parsed = imap_client.parse_rfc822_message(raw, "imap:42")
        self.assertEqual(parsed["id"], "imap:42")
        self.assertEqual(parsed["subject"], "Action Required")
        self.assertEqual(parsed["metadata"]["reply_to"], "scammer@gmail.com")
        self.assertIn("spf=fail", parsed["metadata"]["authentication_results"])
        self.assertEqual(parsed["metadata"]["html_links"][0][0], "http://evil-verify.xyz/login")

    async def test_multi_user_imap_save_list_scan_and_disconnect_purge(self):
        mem_db = SimpleNamespace(
            detections=InMemoryCollection("detections"),
            gmail_connections=InMemoryCollection("gmail_connections"),
        )

        sample_headers = [
            {
                "id": "imap:101",
                "subject": "Weekly Newsletter",
                "sender": "Team <news@example.com>",
                "date": "1710000000000",
                "snippet": "",
            }
        ]
        sample_norm = {
            "id": "imap:101",
            "threadId": None,
            "historyId": None,
            "internalDate": "1710000000000",
            "date": "1710000000000",
            "snippet": "Welcome to our weekly engineering digest.",
            "subject": "Weekly Newsletter",
            "sender": "Team <news@example.com>",
            "body": "Welcome to our weekly engineering digest.",
            "metadata": {"reply_to": "", "authentication_results": "dkim=pass spf=pass", "html_links": []},
        }

        with patch.object(gmail_monitor, "get_db", return_value=mem_db), \
             patch.object(gmail_monitor, "imap_verify_connection", return_value=("imap.gmail.com", 993)), \
             patch.object(gmail_monitor, "imap_list_recent_headers", return_value=sample_headers), \
             patch.object(gmail_monitor, "imap_fetch_normalized_message", return_value=sample_norm):
            await gmail_monitor.save_imap_connection("user-a", "Alice@Gmail.com", "aaaa bbbb cccc dddd", "gmail")
            await gmail_monitor.save_imap_connection("user-b", "bob@gmail.com", "eeee ffff gggg hhhh", "gmail")

            conn_a = await gmail_monitor.get_gmail_connection("user-a")
            conn_b = await gmail_monitor.get_gmail_connection("user-b")
            self.assertEqual(conn_a["gmail_email"], "alice@gmail.com")
            self.assertEqual(conn_b["gmail_email"], "bob@gmail.com")
            self.assertEqual(conn_a["auth_type"], "imap")
            self.assertNotIn("aaaabbbbccccdddd", conn_a["imap_secret"])
            self.assertEqual(decrypt_secret(conn_a["imap_secret"]), "aaaabbbbccccdddd")

            inbox_a = await gmail_monitor.list_gmail_inbox("user-a", max_results=5)
            self.assertEqual(len(inbox_a), 1)
            self.assertIsNone(inbox_a[0]["scan"])

            scanned_a = await gmail_monitor.scan_gmail_message("user-a", "imap:101")
            self.assertEqual(scanned_a["scam_level"], "safe")
            self.assertEqual(scanned_a["input_data"]["subject"], "Weekly Newsletter")

            # Disconnect purges stored encrypted secret
            await gmail_monitor.disconnect_gmail("user-a")
            after_disconnect_a = await gmail_monitor.get_gmail_connection("user-a")
            self.assertFalse(after_disconnect_a["enabled"])
            self.assertNotIn("imap_secret", after_disconnect_a)
            # User B remains completely unaffected
            conn_b_after = await gmail_monitor.get_gmail_connection("user-b")
            self.assertTrue(conn_b_after["enabled"])


if __name__ == "__main__":
    unittest.main()
