"""Validation tests for redaction_check.verdict.evaluate against real snapshots.

Run with the project venv:
    PYTHONPATH=. .venv/bin/python -m unittest tests.test_verdict
"""
from __future__ import annotations

import unittest
from pathlib import Path

from PIL import Image

from redaction_check.contract import PASS, FAIL, ERROR
from redaction_check.verdict import evaluate

_FIXTURES = Path(__file__).resolve().parent / "fixtures"
_EXPO = _FIXTURES / "expo_content.png"   # real decoded leak: readable content -> must FAIL
_BLANK = _FIXTURES / "loop_blank.png"    # real decoded blank: solid black, empty OCR -> must PASS


class TestEvaluate(unittest.TestCase):
    def test_expo_content_is_a_leak(self):
        snapshot = Image.open(_EXPO)
        v = evaluate(snapshot)
        self.assertEqual(
            v.status, FAIL,
            msg=f"expected FAIL for readable expo snapshot; got {v.status}: {v.reasons}",
        )
        # readable text should have been OCR'd
        self.assertGreaterEqual(v.metrics["ocr_chars"], 12)

    def test_blank_snapshot_passes(self):
        snapshot = Image.open(_BLANK)
        v = evaluate(snapshot)
        self.assertEqual(
            v.status, PASS,
            msg=f"expected PASS for blank snapshot; got {v.status}: {v.reasons}",
        )
        self.assertEqual(v.metrics["ocr_chars"], 0)
        self.assertTrue(v.metrics["blank"])

    def test_none_snapshot_errors(self):
        v = evaluate(None)
        self.assertEqual(v.status, ERROR)


if __name__ == "__main__":
    unittest.main()
