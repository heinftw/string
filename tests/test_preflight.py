"""Unit tests for the pure startup-preflight decision logic (any platform)."""

from __future__ import annotations

import unittest

from core.preflight import classify_versions


class ClassifyVersionsTests(unittest.TestCase):
    def test_healthy_windows_11(self):
        self.assertIsNone(classify_versions((10, 0), 26100))

    def test_healthy_windows_10(self):
        self.assertIsNone(classify_versions((10, 0), 19045))

    def test_reported_none_build_modern(self):
        self.assertIsNone(classify_versions(None, 22000))

    def test_no_data_at_all(self):
        self.assertIsNone(classify_versions(None, None))

    def test_lie_reports_vista_on_windows_11(self):
        result = classify_versions((6, 0), 26100)
        self.assertIsNotNone(result)
        message, allow_continue = result
        self.assertTrue(allow_continue)
        self.assertIn("compatibility", message.casefold())
        self.assertIn("Windows 7 is the minimum supported platform", message)
        self.assertIn("where python", message)
        self.assertIn("Windows Vista", message)

    def test_lie_reports_xp_on_windows_10(self):
        result = classify_versions((5, 1), 19045)
        self.assertIsNotNone(result)
        message, allow_continue = result
        self.assertTrue(allow_continue)
        self.assertIn("Windows XP", message)

    def test_lie_reports_windows_7_on_windows_11(self):
        # A Win7 compat shim is still a lie: Qt 6 checks for Windows 10.
        result = classify_versions((6, 1), 26100)
        self.assertIsNotNone(result)
        _, allow_continue = result
        self.assertTrue(allow_continue)

    def test_unverifiable_suspicious_report(self):
        result = classify_versions((6, 0), None)
        self.assertIsNotNone(result)
        message, allow_continue = result
        self.assertTrue(allow_continue)
        self.assertIn("Fatal Error", message)

    def test_unverifiable_normal_report(self):
        self.assertIsNone(classify_versions((10, 0), None))

    def test_genuine_windows_7(self):
        result = classify_versions((6, 1), 7601)
        self.assertIsNotNone(result)
        message, allow_continue = result
        self.assertFalse(allow_continue)
        self.assertIn("Windows 10 or later", message)

    def test_genuine_windows_8_1(self):
        result = classify_versions((6, 3), 9600)
        self.assertIsNotNone(result)
        _, allow_continue = result
        self.assertFalse(allow_continue)


if __name__ == "__main__":
    unittest.main()
