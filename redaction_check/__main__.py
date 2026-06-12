"""redaction-checker CLI.

    python -m redaction_check --config sensitive-screens.yml --platform both --out report

Drives the configured app to each sensitive screen, recovers the app-switcher /
recents snapshot, and writes a PASS/FAIL report with side-by-side evidence.
Exit code is non-zero if any sensitive screen FAILS (so it can gate CI).
"""
from __future__ import annotations

import argparse
import os
import subprocess
import sys
from pathlib import Path

import yaml

from .contract import FAIL, ERROR
from . import report as report_mod


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="redaction-check",
                                 description="Confirm sensitive screens are obscured in the app switcher / recents.")
    ap.add_argument("config", nargs="?", default=None,
                    help="path to the screens config (default: sensitive-screens.yml)")
    ap.add_argument("--config", dest="config_flag", default=None,
                    help="alternative to the positional config path")
    ap.add_argument("--platform", choices=["ios", "android", "both"], default="both")
    ap.add_argument("--out", default="report", help="output directory for the report + evidence")
    ap.add_argument("--open", dest="open_report", action="store_true", default=None,
                    help="open the HTML report when the run finishes (default: on when interactive)")
    ap.add_argument("--no-open", dest="open_report", action="store_false",
                    help="do not open the report (default in CI / non-interactive)")
    args = ap.parse_args(argv)

    cfg_path = Path(args.config or args.config_flag or "sensitive-screens.yml")
    if not cfg_path.exists():
        print(f"config not found: {cfg_path}", file=sys.stderr)
        return 2
    config = yaml.safe_load(cfg_path.read_text()) or {}

    results = []
    if args.platform in ("ios", "both") and config.get("ios"):
        ios_backend = (config["ios"].get("backend") or "simctl").lower()
        if ios_backend == "revyl":
            from .revyl_ios_runner import run_ios_revyl
            print("→ iOS: driving Revyl cloud device (Control Center backgrounding)…")
            results += run_ios_revyl(config, args.out)
        else:
            from .ios_runner import run_ios
            print("→ iOS: driving local simulator and harvesting app-switcher snapshots…")
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
    failed = errored = 0
    for r in results:
        mark = {"PASS": "✓", "FAIL": "✗", "ERROR": "!"}.get(r.verdict.status, "?")
        print(f"  {mark} [{r.platform}] {r.name}: {r.verdict.status}"
              + (f" — {r.verdict.reasons[0]}" if r.verdict.reasons else ""))
        if r.verdict.leaked_text:
            print(f"      leaked: {', '.join(r.verdict.leaked_text[:4])}")
        if r.verdict.status == FAIL:
            failed += 1
        elif r.verdict.status == ERROR:
            errored += 1
    print("=" * 56)
    print(f"report: {Path(args.out) / 'report.md'}")
    print(f"{failed} FAIL / {errored} ERROR / {len(results)} screens")

    # Open the report when asked, or by default when run interactively. Skipped in
    # CI / piped runs so it never tries to pop a browser on a build agent.
    should_open = args.open_report if args.open_report is not None else sys.stdout.isatty()
    if should_open:
        _open_report(args.out)

    # Non-zero on FAIL (compliance) and on ERROR (the check didn't complete) so a
    # broken run never reads as a green CI pass.
    if failed:
        return 1
    return 2 if errored else 0


def _open_report(out_dir) -> None:
    """Open the generated report in the default viewer. Best-effort: a failure to
    open never changes the run's exit code."""
    out = Path(out_dir)
    target = out / "report.html"
    if not target.exists():
        target = out / "report.md"
    if not target.exists():
        return
    try:
        if sys.platform == "darwin":
            subprocess.run(["open", str(target)], check=False)
        elif sys.platform.startswith("linux"):
            subprocess.run(["xdg-open", str(target)], check=False)
        elif os.name == "nt":
            os.startfile(str(target))  # type: ignore[attr-defined]
    except Exception:
        pass


if __name__ == "__main__":
    raise SystemExit(main())
