import unittest
from app.core.security import hash_password, verify_password, pwd_context

class PasswordSecurityTests(unittest.TestCase):
    def test_pre_hashed_password_verification(self):
        pwd = "MySuperSecretPassword123!@#"
        hashed = hash_password(pwd)
        self.assertTrue(verify_password(pwd, hashed))
        self.assertFalse(verify_password("WrongPassword", hashed))

    def test_long_and_unicode_password_handles_gracefully(self):
        # 150-character unicode password that would break standard bcrypt 72-byte limit
        long_unicode_pwd = "🔐" * 60 + "SecurePasswordWithManyCharactersOverTheLimit1234567890!"
        hashed = hash_password(long_unicode_pwd)
        self.assertTrue(verify_password(long_unicode_pwd, hashed))
        self.assertFalse(verify_password(long_unicode_pwd + "extra", hashed))

    def test_backward_compatibility_with_legacy_bcrypt_hashes(self):
        legacy_pwd = "LegacyOldUserPassword123"
        # Directly hash with legacy truncation plain[:72]
        legacy_hash = pwd_context.hash(legacy_pwd[:72])

        # verify_password must successfully authenticate legacy hashes
        self.assertTrue(verify_password(legacy_pwd, legacy_hash))
        self.assertFalse(verify_password("WrongLegacyPassword", legacy_hash))

if __name__ == "__main__":
    unittest.main()
