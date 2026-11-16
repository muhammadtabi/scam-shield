import unittest

from app.ml import predictor


class EmailDetectionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        predictor.load_models()

    def test_legitimate_bank_transaction_header_is_safe(self):
        result = predictor.detect_email(
            "Your transaction is confirmed",
            "Chase Alerts <no-reply@chase.com>",
            "A bank transfer of $250.00 was completed successfully. Your account activity is available in your statement.",
        )

        self.assertEqual(result["scam_level"], "safe")

    def test_completed_transaction_from_less_known_sender_is_safe(self):
        result = predictor.detect_email(
            "Transaction completed successfully",
            "Bank Notifications <alerts@regionalbank.example>",
            "Your payment of $125.00 was processed successfully and posted to your account. This receipt is for your records.",
        )

        self.assertEqual(result["scam_level"], "safe")

    def test_nayapay_transfer_is_safe(self):
        result = predictor.detect_email(
            "You sent Rs. 100 to Zeeshan Ahmed",
            "NayaPay <service@nayapay.com>",
            "You sent Rs. 100 to Zeeshan Ahmed. Your payment was processed successfully.",
        )

        self.assertEqual(result["scam_level"], "safe")

    def test_legitimate_emergent_newsletter_is_safe(self):
        result = predictor.detect_email(
            "MISSING: One big idea",
            "Emergent <team@ship.emergent.sh>",
            "Last seen mid-build. Finder's reward: $1 Standard pass for 7 days. Claim your pass and view the post.",
        )

        self.assertEqual(result["scam_level"], "safe")

    def test_legitimate_skool_newsletter_is_safe(self):
        result = predictor.detect_email(
            "You have a new post in your group",
            'Fit Pro Alpha Tribe <noreply@skool.com>',
            "An admin posted a new educational article about building a $1,000 client offer. View post or turn off group emails.",
        )

        self.assertEqual(result["scam_level"], "safe")

    def test_legitimate_promo_and_saas_otp_are_safe(self):
        promo = predictor.detect_email(
            "50% off annual plan - limited time offer",
            "Figma <news@figma.com>",
            "Upgrade today to save 50% on Figma Professional. Click here to claim your student discount or unsubscribe at https://www.figma.com/email/unsubscribe",
        )
        otp = predictor.detect_email(
            "Your login verification code",
            "Discord Security <security@discord.com>",
            "Enter verification code 849201 to verify your login attempt. If this was not you, update your password immediately.",
        )
        self.assertEqual(promo["scam_level"], "safe", msg=promo)
        self.assertEqual(otp["scam_level"], "safe", msg=otp)

    def test_completed_transfer_evasion_and_html_anchor_spoof_are_caught(self):
        evasion = predictor.detect_email(
            "Bank transfer completed — confirm unauthorized wire",
            "Security Operations <billing@chase-secure-resolution.xyz>",
            "Your bank transfer of $1,850.00 was completed. Click to cancel and enter your card PIN: http://chase-secure-resolution.xyz/refund",
        )
        html_spoof = predictor.detect_email(
            "Verify your PayPal account",
            "PayPal Desk <alerts@unrelated-mailer.com>",
            "Visit <a href='http://paypa1-verify.xyz/login'>https://www.paypal.com/security</a> to restore access.",
            metadata={"authentication_results": "spf=fail dkim=fail"},
        )
        self.assertEqual(evasion["scam_level"], "scam", msg=evasion)
        self.assertEqual(html_spoof["scam_level"], "scam", msg=html_spoof)

    def test_jobseeker_alert_with_tracking_tokens_and_esp_footer_is_safe(self):
        result = predictor.detect_email(
            "New roles since your last visit",
            "Jobseeker <support@jobseeker.com>",
            (
                "Dear Muhammad, 3 new roles have been posted. "
                "See jobs: https://www.jobseeker.com/app/jobs?email=user%40gmail.com&token=0fbc5cbe08d5c9d776a404a401b4edf5fffa3468930b7812275d101da951eca9&utm_source=email "
                "Don't want to receive emails from us? Click here: "
                "https://e.customeriomail.com/e/c/eyJlbWFpbF9pZCI6ImRnVHJBb0xBSW45NXdtSV9lY0pBYUhKTmdTWDUtR2pIN2YxeXlSMkJ3PT0ifQ=="
            ),
        )
        self.assertEqual(result["scam_level"], "safe", msg=result)

    def test_appwrite_action_email_with_terms_privacy_links_is_safe(self):
        result = predictor.detect_email(
            '[Action required] Your project "Appwrite project" is inactive',
            "Appwrite <noreply@appwrite.io>",
            (
                "Hello, your Appwrite Cloud project has been inactive for 30 days. "
                "Review our terms (https://appwrite.io/terms) and privacy policy (https://appwrite.io/privacy)."
            ),
        )
        self.assertEqual(result["scam_level"], "safe", msg=result)

    def test_spf_auth_failure_alone_is_at_least_suspicious(self):
        result = predictor.detect_email(
            "Confirm Your Subscription",
            "Mad Personal Care <sender@example.com>",
            "Please confirm your newsletter subscription preferences at your convenience.",
            metadata={"authentication_results": "spf=fail"},
        )
        self.assertIn(result["scam_level"], ("suspicious", "scam"), msg=result)

    def test_authenticated_hubspot_newsletter_with_tracking_links_is_safe(self):
        result = predictor.detect_email(
            "Meet Agent Loop: voice agents that get better with every call",
            "Team Vapi <team@mail.vapi.ai>",
            (
                "Early access is open. Join the waitlist today. "
                "Read more: https://dxLN-b04.na2.hubspotlinks.com/Ctc/2R+113/dxLN-b04/VVyl9z87373SW3PfNyh7mr1d7W44_bnN5Xf2mLN2lhp1d3m2nnW6N1vHY6lZ3nh "
                "Unsubscribe or manage preferences: https://hs-244349038.s.hubspotemail-na2.net/hs/preferences-center/en/direct?data=W2nWGVW47zk4tW1Xh6mh1ZwXKnW1S13m2"
            ),
            metadata={"authentication_results": "dkim=pass spf=pass dmarc=pass"},
        )
        self.assertEqual(result["scam_level"], "safe", msg=result)

    def test_legitimate_linkedin_notification_with_mobile_app_link_is_safe(self):
        result = predictor.detect_email(
            "You appeared in 1 search",
            "LinkedIn <notifications-noreply@linkedin.com>",
            (
                "Muhammad, this is what you’ve missed on LinkedIn\n"
                "You were found by people from these companies\n"
                "See all searches: https://www.linkedin.com/comm/me/search-appearances/?lipi=urn%3Ali\n"
                "Download for free: https://www.linkedinmobileapp.com/comm/feed/?appType=FLAGSHIP\n"
                "Learn why we included this: https://www.linkedin.com/help/linkedin/answer/4788\n"
                "Unsubscribe: https://www.linkedin.com/comm/mypreferences/u/emailunsub?action=update\n"
                "© 2026 LinkedIn Corporation"
            ),
        )
        self.assertEqual(result["scam_level"], "safe", msg=result)
        self.assertLess(result["confidence"], 10.0, msg=result)


if __name__ == "__main__":
    unittest.main()