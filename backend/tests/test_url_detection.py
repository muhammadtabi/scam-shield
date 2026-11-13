import unittest

from app.ml import predictor
from app.ml.url_features import extract_url_features, parse_canonical_url


class URLDetectionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        predictor.load_models()

    def test_scheme_normalization_produces_identical_features(self):
        bare = "example.org/docs/getting-started"
        http_u = "http://example.org/docs/getting-started"
        https_u = "https://www.example.org/docs/getting-started/"
        self.assertEqual(extract_url_features(bare), extract_url_features(http_u))
        self.assertEqual(extract_url_features(http_u), extract_url_features(https_u))

    def test_at_symbol_distinguishes_userinfo_spoof_from_path_handle(self):
        handle_info = parse_canonical_url("https://medium.com/@security-team/phishing-post")
        spoof_info = parse_canonical_url("https://www.paypal.com@evil-login.example/auth")
        self.assertFalse(handle_info.has_userinfo_at)
        self.assertTrue(spoof_info.has_userinfo_at)
        self.assertEqual(spoof_info.registrable_domain, "evil-login.example")

    def test_legitimate_auth_docs_and_brand_article_urls_are_safe(self):
        safe_urls = [
            "https://login.salesforce.com/",
            "https://support.mozilla.org/en-US/kb/reset-your-primary-password",
            "https://docs.stripe.com/invoicing/overview",
            "https://blog.cloudflare.com/securing-paypal-and-apple-payments",
            "http://cs.stanford.edu/people/",
            "https://www.jobseeker.com/app/jobs?email=user@gmail.com&token=0fbc5cbe08d5c9d776a404a401b4edf5fffa3468930b7812275d101da951eca9",
            "https://e.customeriomail.com/e/c/eyJlbWFpbF9pZCI6ImRnVHJBb0xBSW45NXdtSV9lY0pBYUhKTmdTWDUtR2pIN2YxeXlSMkJ3PT0ifQ==",
            "https://appwrite.io/terms",
            "https://appwrite.io/privacy",
            "https://vercel.app/docs",
            "https://dxLN-b04.na2.hubspotlinks.com/Ctc/2R+113/dxLN-b04/VVyl9z87373SW3PfNyh7mr1d7W44_bnN5Xf2mLN2lhp1d3m2nn",
        ]
        for url in safe_urls:
            with self.subTest(url=url):
                res = predictor.detect_url(url)
                self.assertEqual(res["scam_level"], "safe", msg=f"{url} returned {res}")

    def test_phishing_spoof_typosquat_and_raw_ip_are_flagged(self):
        bad_urls = [
            "http://paypal-secure-verify.xyz/login/confirm",
            "https://www.paypa1.com/signin/verify",
            "https://login.microsoftonline.com.verify-user.tk/auth/session",
            "http://192.168.1.1/admin/steal-data",
            "https://www.paypal.com@evil-phish-portal.com/signin",
            "http://paypal-login-check.app/signin",
            "https://apple-verify-session.io/login",
        ]
        for url in bad_urls:
            with self.subTest(url=url):
                res = predictor.detect_url(url)
                self.assertIn(res["scam_level"], ("suspicious", "scam"), msg=f"{url} returned {res}")

    def test_clean_work_tld_tracking_url_is_cautious_not_high_confidence_scam(self):
        res = predictor.detect_url("https://app.inmind.work/front-pages/order-tracking?trackingNumber=26532280260890")
        self.assertEqual(res["scam_level"], "suspicious", msg=res)

    def test_api_route_allows_anonymous_url_detection(self):
        from fastapi.testclient import TestClient
        from main import app
        with TestClient(app) as client:
            resp = client.post("/api/detect/url", json={"url": "https://paypal-secure-verify.xyz/login/confirm"})
            self.assertEqual(resp.status_code, 200)
            data = resp.json()
            self.assertIn("scam_level", data)
            self.assertIn(data["scam_level"], ("suspicious", "scam"))
            self.assertNotIn("id", data)

    def test_api_route_persists_when_authenticated(self):
        from fastapi.testclient import TestClient
        from main import app
        from app.core.security import create_access_token
        token = create_access_token(data={"sub": "test-user-ext-123"})
        with TestClient(app) as client:
            resp = client.post(
                "/api/detect/url",
                json={"url": "https://paypal-secure-verify.xyz/login/confirm"},
                headers={"Authorization": f"Bearer {token}"}
            )
            self.assertEqual(resp.status_code, 200)
            data = resp.json()
            self.assertIn("scam_level", data)
            self.assertIn("id", data)
            self.assertTrue(bool(data["id"]))


if __name__ == "__main__":
    unittest.main()

