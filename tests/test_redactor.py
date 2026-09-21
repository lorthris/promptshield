"""Unit tests for the redactor engine and rehydration."""

import shutil
import tempfile
import unittest
from pathlib import Path

from promptshield.detector import Detector
from promptshield.redactor import Redactor


class TestRedactor(unittest.TestCase):
    def setUp(self):
        self.temp_dir = Path(tempfile.mkdtemp())
        self.redactor = Redactor(session_dir=self.temp_dir)

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_deterministic_pseudonym_consistency(self):
        key = "sk-proj-abc123def456ghi789jkl012mno345pqr678stu901vwx"
        text = f"First call: {key}. Second call: {key}."
        result = self.redactor.redact(text)

        # Both occurrences should have identical pseudonym [OPENAI_KEY_1]
        self.assertEqual(result.sanitised_text.count("[OPENAI_KEY_1]"), 2)
        self.assertNotIn(key, result.sanitised_text)

    def test_multiple_distinct_secrets(self):
        key1 = "sk-proj-abc123def456ghi789jkl012mno345pqr678stu901vwx"
        key2 = "sk-proj-zzz999yyy888xxx777www666vvv555uuu444ttt333sss"
        text = f"Primary: {key1}\nBackup: {key2}"
        result = self.redactor.redact(text)

        self.assertIn("[OPENAI_KEY_1]", result.sanitised_text)
        self.assertIn("[OPENAI_KEY_2]", result.sanitised_text)

    def test_round_trip_rehydration(self):
        key = "sk-ant-api03-abcdef1234567890123456789012345678901234"
        email = "developer@company.internal"
        text = f"Config for {email}: api_key = '{key}'"

        result = self.redactor.redact(text, session_id="test_session")
        self.assertNotIn(key, result.sanitised_text)
        self.assertNotIn(email, result.sanitised_text)

        # Rehydrate using session
        restored = self.redactor.restore(result.sanitised_text, session_id="test_session")
        self.assertEqual(restored, text)

    def test_redaction_styles(self):
        key = "AIzaSyA1B2C3D4E5F6G7H8I9J0K1L2M3N4O5P6Q"

        # Style: redacted
        r_redacted = Redactor(style="redacted", session_dir=self.temp_dir)
        res1 = r_redacted.redact(key)
        self.assertEqual(res1.sanitised_text, "[REDACTED:GOOGLE_GEMINI_API_KEY]")

        # Style: hash
        r_hash = Redactor(style="hash", session_dir=self.temp_dir)
        res2 = r_hash.redact(key)
        self.assertTrue(res2.sanitised_text.startswith("[SECRET_HASH_"))


if __name__ == "__main__":
    unittest.main()
