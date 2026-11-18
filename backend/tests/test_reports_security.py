import unittest
import io
import csv
from datetime import datetime, timezone
from fastapi.testclient import TestClient
from main import app
from app.core.security import create_access_token
from app.db.database import get_db
from app.api.routes.reports import _sanitize_csv_cell


class ReportsSecurityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.user_id = "test-reports-user-sec"
        cls.token = create_access_token({"sub": cls.user_id, "email": "reports_test@example.com"})
        cls.headers = {"Authorization": f"Bearer {cls.token}"}

    def test_sanitize_csv_cell_neutralizes_formulas(self):
        self.assertEqual(_sanitize_csv_cell("=1+1"), "'=1+1")
        self.assertEqual(_sanitize_csv_cell("+cmd|' /C calc'!A0"), "'+cmd|' /C calc'!A0")
        self.assertEqual(_sanitize_csv_cell("-2+3"), "'-2+3")
        self.assertEqual(_sanitize_csv_cell("@SUM(A1:A10)"), "'@SUM(A1:A10)")
        self.assertEqual(_sanitize_csv_cell("\tTAB"), "'\tTAB")
        self.assertEqual(_sanitize_csv_cell("\rRETURN"), "'\rRETURN")
        self.assertEqual(_sanitize_csv_cell("Normal text"), "Normal text")
        self.assertEqual(_sanitize_csv_cell(""), "")
        self.assertEqual(_sanitize_csv_cell(None), "")

    def test_csv_and_pdf_generation_with_malicious_content(self):
        with TestClient(app) as client:
            # Post an SMS detection with leading '+' (formula char) in sender
            detect_sms_resp = client.post(
                "/api/detect/sms",
                headers=self.headers,
                json={
                    "sender_id": "+12345678901",
                    "message": "Urgent alert! Click here to verify account: http://phish-secure.test/login"
                }
            )
            self.assertEqual(detect_sms_resp.status_code, 200)

            # Post an email detection containing XML characters
            detect_email_resp = client.post(
                "/api/detect/email",
                headers=self.headers,
                json={
                    "subject": "Security Notice <admin@fake.test> & alert(1)",
                    "sender": "attacker@evil.com",
                    "body": "Your bank account has been compromised <a href='bad'>click</a>"
                }
            )
            self.assertEqual(detect_email_resp.status_code, 200)

            # Test CSV export
            csv_resp = client.get("/api/reports/csv", headers=self.headers)
            self.assertEqual(csv_resp.status_code, 200)
            self.assertEqual(csv_resp.headers["content-type"], "text/csv; charset=utf-8")
            csv_content = csv_resp.text
            # Verify formula neutralization in CSV (+ was sanitized to '+)
            self.assertIn("'+12345678901", csv_content)

            # Test PDF export
            pdf_resp = client.get("/api/reports/pdf", headers=self.headers)
            self.assertEqual(pdf_resp.status_code, 200)
            self.assertEqual(pdf_resp.headers["content-type"], "application/pdf")
            self.assertTrue(len(pdf_resp.content) > 1000)
            self.assertTrue(pdf_resp.content.startswith(b"%PDF-"))


if __name__ == "__main__":
    unittest.main()
