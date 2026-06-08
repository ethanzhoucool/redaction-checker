"""redaction-checker CLI.

    python -m redaction_check --config sensitive-screens.yml --platform both --out report

Drives the configured app to each sensitive screen, recovers the app-switcher /
recents snapshot, and writes a PASS/FAIL report with side-by-side evidence.
Exit code is non-zero if any sensitive screen FAILS (so it can gate CI).
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

import yaml

from .contract import FAIL, ERROR
from . import report as report_mod


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="redaction-check",
                                 description="Confirm sensitive screens are obscured in the app switcher / recents.")
    ap.add_argument("--config", default="sensitive-screens.yml", help="path to the screens config")
    ap.add_argument("--platform", choices=["ios", "android", "both"], default="both")
    ap.add_argument("--out", default="report", help="output directory for the report + evidence")
    args = ap.parse_args(argv)

    cfg_path = Path(args.config)
    if not cfg_path.exists():
        print(f"config not found: {cfg_path}", file=sys.stderr)
        return 2
    config = yaml.safe_load(cfg_path.read_text()) or {}

    results = []
    if args.platform in ("ios", "both") and config.get("ios"):
        from .ios_runner import run_ios
        print("→ iOS: driving simulator and harvesting app-switcher snapshots…")
        results += run_ios(config, args.out)
    if args.platform in ("android", "both") and config.get("android"):
        from .android_runner import run_android
        print("→ Android: driving device and capturing recents…")
        results += run_android(config, args.out)

    if not results:
        print("no screens checked — nothing in config for the selected platform(s).", file=sys.stderr)
        return 2

    report_mod.write_report(results, args.out)   # also renders per-screen evidence PNGs

    # summary
    print("\n" + "=" * 56)
    failed = 0
    for r in results:
        mark = {"PASS": "✓", "FAIL": "✗", "ERROR": "!"}.get(r.verdict.status, "?")
        print(f"  {mark} [{r.platform}] {r.name}: {r.verdict.status}"
              + (f" — {r.verdict.reasons[0]}" if r.verdict.reasons else ""))
        if r.verdict.leaked_text:
            print(f"      leaked: {', '.join(r.verdict.leaked_text[:4])}")
        if r.verdict.status == FAIL:
            failed += 1
    print("=" * 56)
    print(f"report: {Path(args.out) / 'report.md'}")
    print(f"{failed} FAIL / {len(results)} screens")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
