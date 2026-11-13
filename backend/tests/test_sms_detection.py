import unittest

from pydantic import ValidationError

from app.ml import predictor
from app.schemas.detection import SMSDetectRequest


class SMSDetectionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        predictor.load_models()

    def test_legitimate_otps_deliveries_and_promos_are_safe(self):
        safe_cases = [
            (
                "BANKALERT",
                "Your OTP is 482910 to confirm your transaction of Rs 5,000. Do not share this code with anyone.",
            ),
            (
                "FEDEX",
                "Your package #9918273 is out for delivery today. Track at https://www.fedex.com/track or reply STOP to opt out.",
            ),
            (
                "JAZZ",
                "Enjoy free 5GB mobile internet offer for 3 days! Dial *117*4# to subscribe or reply STOP to opt out.",
            ),
            (
                "CLINIC",
                "Reminder: Your dental appointment is tomorrow at 10am. Please reply YES to confirm or call 051-2345678 to reschedule.",
            ),
            (
                "03315123456",
                "Urgent! Can you call me back asap? My phone battery is at 2% and I need the apartment gate code.",
            ),
        ]
        for sender_id, msg in safe_cases:
            with self.subTest(sender_id=sender_id):
                res = predictor.detect_sms(sender_id, msg)
                self.assertEqual(res["scam_level"], "safe", msg=f"{sender_id}: {res}")
                joined = " ".join(res["reasons"]).lower()
                self.assertNotIn("suspicious number sequence", joined)

    def test_smishing_otp_theft_and_prize_scams_are_flagged(self):
        scam_cases = [
            (
                "03019991122",
                "DHL: Your package is suspended due to unpaid customs fee of Rs 250. Pay immediately: http://dhl-track-fee.xyz/pay",
            ),
            (
                "03156677889",
                "Sorry I accidentally sent my WhatsApp verification code to your number by mistake! Please forward me the 6-digit code urgently.",
            ),
            (
                "03009811223",
                "Hi this is bank helpline officer. An unauthorized transaction happened on your card. Reply immediately with the 6-digit OTP code.",
            ),
            (
                "04477009001",
                "CONGRATULATIONS! You won a $1000 Walmart gift card! Claim your cash prize now at http://walmart-claim.tk/win",
            ),
        ]
        for sender_id, msg in scam_cases:
            with self.subTest(sender_id=sender_id):
                res = predictor.detect_sms(sender_id, msg)
                self.assertIn(res["scam_level"], ("suspicious", "scam"), msg=f"{sender_id}: {res}")

    def test_sms_shortcode_schema_validation_and_classification(self):
        for valid_sender in ("8558", "3737", "8171", "123456", "03315123456", "BANKALERT"):
            req = SMSDetectRequest(sender_id=valid_sender, message="Your OTP is 482910. Do not share this code.")
            self.assertEqual(req.sender_id, valid_sender)

        for invalid_sender in ("123", "1234567", "030012345", "+8558", "12-34"):
            with self.assertRaises(ValidationError, msg=f"Expected rejection for {invalid_sender}"):
                SMSDetectRequest(sender_id=invalid_sender, message="Test message")

        otp_res = predictor.detect_sms(
            "8558",
            "Your HBL OTP is 482910 for Rs 5,000 transaction. Do not share this code with anyone.",
        )
        self.assertEqual(otp_res["scam_level"], "safe", msg=otp_res)
        self.assertIn("carrier/brand shortcode", otp_res["explanation"])

        promo_res = predictor.detect_sms(
            "3737",
            "Enjoy free 5GB mobile internet offer for 3 days! Dial *117*4# to subscribe or reply STOP to opt out.",
        )
        self.assertEqual(promo_res["scam_level"], "safe", msg=promo_res)

        scam_res = predictor.detect_sms(
            "8558",
            "CONGRATULATIONS! You won a Rs 50,000 prize. Send OTP and verify at http://win-cash.xyz/claim",
        )
        self.assertEqual(scam_res["scam_level"], "scam", msg=scam_res)


if __name__ == "__main__":
    unittest.main()

