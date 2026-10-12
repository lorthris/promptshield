"""Unit tests for the clipboard sanitiser."""

import io
import unittest
from unittest.mock import patch

from promptshield.cli import main
from promptshield.clipboard import sanitise_clipboard


class TestClipboard(unittest.TestCase):
    @patch("promptshield.clipboard.get_clipboard_text", return_value=None)
    def test_sanitise_clipboard_empty(self, mock_get):
        stderr = io.StringIO()
        with patch("sys.stderr", stderr):
            count = sanitise_clipboard()
        self.assertEqual(count, 0)
        self.assertIn("Clipboard is empty", stderr.getvalue())

    @patch(
        "promptshield.clipboard.get_clipboard_text", return_value="Just a normal public message."
    )
    def test_sanitise_clipboard_clean(self, mock_get):
        stderr = io.StringIO()
        with patch("sys.stderr", stderr):
            count = sanitise_clipboard()
        self.assertEqual(count, 0)
        self.assertIn("Clipboard clean", stderr.getvalue())

    @patch("promptshield.clipboard.set_clipboard_text", return_value=True)
    @patch(
        "promptshield.clipboard.get_clipboard_text",
        return_value="Secret key: sk-ant-api03-abcdef1234567890123456789012345678901234",
    )
    def test_sanitise_clipboard_dirty(self, mock_get, mock_set):
        stderr = io.StringIO()
        with patch("sys.stderr", stderr):
            count = sanitise_clipboard()
        self.assertEqual(count, 1)
        mock_set.assert_called_once()
        sanitised_arg = mock_set.call_args[0][0]
        self.assertNotIn("sk-ant-api03-", sanitised_arg)
        self.assertIn("[ANTHROPIC_KEY_1]", sanitised_arg)
        self.assertIn("Sanitised 1 sensitive token(s)", stderr.getvalue())

    @patch("promptshield.clipboard.set_clipboard_text", return_value=False)
    @patch(
        "promptshield.clipboard.get_clipboard_text",
        return_value="Secret key: sk-ant-api03-abcdef1234567890123456789012345678901234",
    )
    def test_sanitise_clipboard_set_failure(self, mock_get, mock_set):
        stderr = io.StringIO()
        with patch("sys.stderr", stderr):
            count = sanitise_clipboard()
        self.assertEqual(count, 0)
        self.assertIn("Failed to update clipboard", stderr.getvalue())

    @patch("promptshield.clipboard.sanitise_clipboard", return_value=1)
    def test_cli_clip_dispatch(self, mock_sanitise):
        code = main(["clip", "--session", "test_clip_session"])
        self.assertEqual(code, 0)
        mock_sanitise.assert_called_once_with(session_id="test_clip_session")


if __name__ == "__main__":
    unittest.main()
