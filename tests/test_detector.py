"""Unit tests for the detector engine."""

import unittest

from promptshield.detector import (
    Detector,
    calculate_shannon_entropy,
    luhn_checksum_valid,
    australian_tfn_valid,
)


class TestDetector(unittest.TestCase):
    def setUp(self):
        self.detector = Detector()

    def test_detect_openai_api_key(self):
        text = "export OPENAI_API_KEY=sk-proj-abc123def456ghi789jkl012mno345pqr678stu901vwx"
        findings = self.detector.scan(text)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].rule_name, "openai_api_key")
        self.assertEqual(findings[0].category, "CREDENTIAL")

    def test_detect_anthropic_api_key(self):
        text = "client = Anthropic(api_key='sk-ant-api03-abcdef1234567890123456789012345678901234')"
        findings = self.detector.scan(text)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].rule_name, "anthropic_api_key")

    def test_detect_google_gemini_key(self):
        text = "GEMINI_KEY = 'AIzaSyA1B2C3D4E5F6G7H8I9J0K1L2M3N4O5P6Q'"
        findings = self.detector.scan(text)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].rule_name, "google_gemini_api_key")

    def test_detect_aws_access_key(self):
        text = "aws_access_key_id = AKIAIOSFODNN7EXAMPLE"
        findings = self.detector.scan(text)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].rule_name, "aws_access_key_id")

    def test_detect_github_token(self):
        text = "git clone https://ghp_0123456789abcdefghijklmnopqrstuvwxyz@github.com/repo"
        findings = self.detector.scan(text)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].rule_name, "github_token")

    def test_detect_stripe_key(self):
        text = "stripe.api_key = 'sk_test_51ABC123DEF456GHI789JKL012MNO345PQR678'"
        findings = self.detector.scan(text)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].rule_name, "stripe_api_key")

    def test_detect_database_uri(self):
        text = "DATABASE_URL=postgres://dbuser:s3cr3t_p@ssw0rd@db.example.internal:5432/production"
        findings = self.detector.scan(text)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].rule_name, "database_connection_uri")

    def test_detect_email_and_mobile(self):
        text = "Contact James at james@example.com or mobile 0412 345 678 for details."
        findings = self.detector.scan(text)
        rule_names = {f.rule_name for f in findings}
        self.assertIn("email_address", rule_names)
        self.assertIn("australian_mobile", rule_names)

    def test_luhn_credit_card(self):
        valid_card = "4532 0151 1283 0366"
        self.assertTrue(luhn_checksum_valid(valid_card))
        invalid_card = "4532 0151 1283 0367"
        self.assertFalse(luhn_checksum_valid(invalid_card))

        findings = self.detector.scan(f"Payment card: {valid_card}")
        self.assertTrue(any(f.rule_name == "credit_card_number" for f in findings))

    def test_australian_tfn_validation(self):
        valid_tfn = "123 456 782"
        self.assertTrue(australian_tfn_valid(valid_tfn))
        invalid_tfn = "123 456 789"
        self.assertFalse(australian_tfn_valid(invalid_tfn))

        findings = self.detector.scan(f"Tax file number: {valid_tfn}")
        self.assertTrue(any(f.rule_name == "australian_tfn" for f in findings))

    def test_shannon_entropy(self):
        low_entropy = "AAAAAAAAAAAAAAAAAAAAAAAA"
        high_entropy = "u8X$9vL#2pQ@1zW&7mK!5yT*"
        self.assertLess(calculate_shannon_entropy(low_entropy), 1.0)
        self.assertGreater(calculate_shannon_entropy(high_entropy), 4.2)


if __name__ == "__main__":
    unittest.main()
