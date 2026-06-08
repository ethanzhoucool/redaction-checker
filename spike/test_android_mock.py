"""Mock-mode test for redaction_check.android_runner.

Exercises run_android with NO device and NO Android SDK by feeding it
mock_screenshots. Tolerant of redaction_check.verdict being absent: if the
shared verdict engine isn't built yet, the dispatch path still runs and every
ScreenResult comes back ERROR ("verdict engine unavailable") — which we accept
as a SKIP rather than a failure.

Run from repo root:
    PYTHONPATH=. .venv/bin/python spike/test_android_mock.py
"""
from __future__ import annotations

import sys
from pathlib import Path

from redaction_check.android_runner import run_android
from redaction_check.contract import ERROR, FAIL, PASS

REPO_ROOT = Path(__file__).resolve().parent.parent

# (mock image, screen name, expected verdict once verdict.py exists)
CASES = [
    ("spike/expo_content.png", "payment-form", FAIL),  # readable content -> leak
    ("spike/loop_blank.png", "ssn-entry", PASS),       # black (FLAG_SECURE) -> protected
]


def _verdict_engine_available() -> bool:
    try:
        import redaction_check.verdict  # noqa: F401
        return True
    except ImportError:
        return False


def main() -> int:
    config = {
        "android": {
            # backend intentionally unset -> mock_screenshots takes priority
            "screens": [
                {"name": name, "sensitive": True} for _, name, _ in CASES
            ],
            "mock_screenshots": [img for img, _, _ in CASES],
        },
        "secrets": None,  # use DEFAULT_SECRET_PATTERNS via the engine
    }
    out_dir = str(REPO_ROOT / "spike" / "_out_android_mock")

    results = run_android(config, out_dir)

    # --- Structural checks that hold regardless of the engine. ---
    assert isinstance(results, list), "run_android must return a list"
    assert len(results) == len(CASES), f"expected {len(CASES)} results, got {len(results)}"
    for r, (img, name, _) in zip(results, CASES):
        assert r.platform == "android", f"platform should be android, got {r.platform!r}"
        assert r.name == name, f"name mismatch: {r.name!r} != {name!r}"
        assert r.snapshot_image == img, f"snapshot_image mismatch: {r.snapshot_image!r}"
        assert r.sensitive is True
    print("[ok] mock dispatch produced one android ScreenResult per screen")

    engine = _verdict_engine_available()
    if not engine:
        statuses = {r.verdict.status for r in results}
        assert statuses == {ERROR}, (
            "without verdict.py every result should be ERROR; got "
            f"{[(r.name, r.verdict.status) for r in results]}"
        )
        # Confirm the ERROR message actually names the missing engine.
        msg = " ".join(results[0].verdict.reasons).lower()
        assert "verdict" in msg, f"ERROR reason should mention the verdict engine: {msg!r}"
        print("[SKIP] redaction_check.verdict not built yet — verdict assertions skipped.")
        print("       Mock dispatch + ERROR-handling path verified instead:")
        for r in results:
            print(f"         {r.name:14s} -> {r.verdict.status}  ({'; '.join(r.verdict.reasons)[:80]})")
        return 0

    # --- Full verdict checks, once the engine exists. ---
    ok = True
    for r, (img, name, expected) in zip(results, CASES):
        got = r.verdict.status
        mark = "ok" if got == expected else "FAIL"
        if got != expected:
            ok = False
        print(f"[{mark}] {name:14s} expected {expected:4s} got {got:4s}  ({img})")
        if r.verdict.leaked_text:
            print(f"        leaked_text sample: {r.verdict.leaked_text[:3]}")
    if not ok:
        print("\nVERDICT MISMATCH — see lines above.")
        return 1
    print("\n[ok] all verdict expectations met (FAIL on content, PASS on black).")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except AssertionError as exc:
        print(f"[FAIL] {exc}")
        sys.exit(1)
