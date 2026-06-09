"""Android runner for redaction-checker.

Drives an Android device/emulator to each sensitive screen, captures what the
OS recents (app-switcher) view shows for it, and asks the shared verdict engine
whether sensitive content leaked.

Signal (Android-specific): a screen marked ``FLAG_SECURE`` makes the OS blank
its thumbnail in the recents view. So, for the RECENTS capture:

    screenshot is (near-)black  =>  PASS  (content was protected)
    readable sensitive content  =>  FAIL  (leak)

WHY recents and not the live screen: on Revyl cloud devices,
``revyl device screenshot`` of a LIVE ``FLAG_SECURE`` screen reads straight past
the protection and captures the content (verified live 2026-06). Evaluating the
live capture would falsely FAIL a correctly-secured screen, so it is kept as
evidence only (``live_image``) and NEVER judged — the recents thumbnail, which
the OS itself blanks, is the artifact that carries the verdict.

Three backends, dispatched on ``config["android"]["backend"]``:

  * ``"revyl"``   (PRIMARY) — drive an already-active Revyl cloud session with the
    ``revyl`` CLI. Per screen: ``device instruction`` to the screen, screenshot
    the live screen (evidence only), ``device instruction`` into the recents
    overview, screenshot THAT (the evaluated image), then best-effort reopen the
    app for the next screen. The Billing Test org has device concurrency = 1, so
    we assume exactly ONE active session and never ``device start`` a second one.
  * ``"emulator"`` (fallback) — local ``adb`` against an emulator/USB device.
  * mock          — if ``config["android"]["mock_screenshots"]`` is a list of image
    paths, ALL device I/O is skipped and ``evaluate()`` is run on those images
    (paired to screens by index). Lets the whole pipeline be tested with no
    device and no Android SDK.

Every subprocess call is wrapped defensively: a missing/erroring ``revyl`` or
``adb`` yields a ``ScreenResult`` with ``Verdict(status=ERROR, ...)`` — a single
bad screen never crashes the whole run.

This module imports the shared verdict engine LAZILY (``redaction_check.verdict``)
so it can be developed before that module lands.
"""
from __future__ import annotations

import os
import re
import shutil
import subprocess
import time
from pathlib import Path

from .contract import ERROR, ScreenResult, Verdict

# Revyl's screenshot shutter is ~2.3s; give it margin before/after capture.
_SHUTTER_WAIT_S = 3.0
_SUBPROCESS_TIMEOUT_S = 120


# --------------------------------------------------------------------------- #
# Lazy import of the shared verdict engine.
# --------------------------------------------------------------------------- #
def _load_evaluate():
    """Import redaction_check.verdict.evaluate lazily.

    Returns the callable, or raises ImportError with a clear message if the
    verdict module hasn't been built yet.
    """
    try:
        from .verdict import evaluate  # noqa: WPS433 (intentionally local)
    except ImportError as exc:  # verdict.py not written yet
        raise ImportError(
            "redaction_check.verdict.evaluate is unavailable — the shared "
            "verdict engine (redaction_check/verdict.py) has not been built "
            f"yet. Original error: {exc}"
        ) from exc
    return evaluate


# --------------------------------------------------------------------------- #
# Public entry point.
# --------------------------------------------------------------------------- #
def run_android(config: dict, out_dir: str) -> list[ScreenResult]:
    """Run the Android redaction check for every configured screen.

    Args:
        config: parsed config. Relevant keys:
            config["android"]["backend"]            -> "revyl" | "emulator"
            config["android"]["screens"]            -> [{"name","instruction","sensitive"?}, ...]
            config["android"]["mock_screenshots"]   -> optional [path, ...] (mock mode)
            config["secrets"]                       -> optional [regex, ...]
        out_dir: directory to write captured PNGs into (created if missing).

    Returns:
        One ScreenResult per screen. Errors are reported per-screen as
        Verdict(status=ERROR, ...); this function does not raise for device or
        CLI failures.
    """
    android = (config or {}).get("android") or {}
    secret_patterns = (config or {}).get("secrets")
    os.makedirs(out_dir, exist_ok=True)

    mock = android.get("mock_screenshots")
    if isinstance(mock, list):
        return _run_mock(android, mock, secret_patterns, out_dir)

    backend = (android.get("backend") or "").lower()
    if backend == "revyl":
        return _run_revyl(android, secret_patterns, out_dir)
    if backend == "emulator":
        return _run_emulator(android, secret_patterns, out_dir)

    # Unknown / unset backend and no mock screenshots: emit a single ERROR
    # ScreenResult rather than crashing the orchestrator.
    return [
        _error_result(
            name="<config>",
            sensitive=False,
            reasons=[
                "android.backend must be 'revyl' or 'emulator' (or supply "
                f"android.mock_screenshots for mock mode); got {backend!r}",
            ],
        )
    ]


# --------------------------------------------------------------------------- #
# Mock mode — no device, no SDK.
# --------------------------------------------------------------------------- #
def _run_mock(android, mock_paths, secret_patterns, out_dir) -> list[ScreenResult]:
    """Run evaluate() over a list of on-disk PNGs, paired to screens by index."""
    from PIL import Image  # local import: keeps module importable without PIL paths

    screens = android.get("screens") or []
    results: list[ScreenResult] = []

    for idx, img_path in enumerate(mock_paths):
        screen = screens[idx] if idx < len(screens) else {}
        name = screen.get("name") or f"mock[{idx}]"
        sensitive = bool(screen.get("sensitive", True))

        try:
            img = Image.open(img_path)
            img.load()
        except Exception as exc:  # noqa: BLE001 — never crash the run
            results.append(
                _error_result(
                    name=name,
                    sensitive=sensitive,
                    reasons=[f"failed to open mock screenshot {img_path!r}: {exc}"],
                    snapshot_image=str(img_path),
                )
            )
            continue

        verdict = _evaluate_or_error(img, secret_patterns)
        results.append(
            ScreenResult(
                name=name,
                platform="android",
                sensitive=sensitive,
                verdict=verdict,
                live_image=None,
                snapshot_image=str(img_path),
            )
        )

    return results


# --------------------------------------------------------------------------- #
# Revyl backend (PRIMARY).
# --------------------------------------------------------------------------- #
def _run_revyl(android, secret_patterns, out_dir) -> list[ScreenResult]:
    """Drive a single already-active Revyl session screen-by-screen.

    Concurrency = 1 in the Billing Test org, so we never start a session here;
    we assume one is live and steer it with `revyl device instruction`.

    Per screen: drive -> live capture (evidence only) -> open recents ->
    recents capture (the ONLY image evaluated) -> best-effort reopen the app.
    The live screen is never judged: Revyl's screenshot bypasses FLAG_SECURE
    (see module docstring), so only the recents thumbnail is trustworthy.
    """
    from PIL import Image

    if shutil.which("revyl") is None:
        return [
            _error_result(
                name=(s.get("name") or f"screen[{i}]"),
                sensitive=bool(s.get("sensitive", True)),
                reasons=["`revyl` CLI not found on PATH"],
            )
            for i, s in enumerate(android.get("screens") or [{}])
        ]

    screens = android.get("screens") or []
    results: list[ScreenResult] = []

    for idx, screen in enumerate(screens):
        name = screen.get("name") or f"screen[{idx}]"
        sensitive = bool(screen.get("sensitive", True))
        instruction = screen.get("instruction")

        # 1) Drive the active session to this screen.
        if instruction:
            drive = _run_cli(["revyl", "device", "instruction", str(instruction)])
            if not drive.ok:
                results.append(
                    _error_result(
                        name=name,
                        sensitive=sensitive,
                        reasons=[f"`revyl device instruction` failed: {drive.detail}"],
                    )
                )
                continue

        # 2) Let the UI settle past the shutter latency, then capture the LIVE
        #    screen. Evidence only — Revyl's screenshot bypasses FLAG_SECURE, so
        #    this image is never evaluated and a failure here is non-fatal.
        time.sleep(_SHUTTER_WAIT_S)
        live_path: Path | None = None
        live_shot = _run_cli(["revyl", "device", "screenshot"])
        if live_shot.ok:
            live_path = _resolve_revyl_screenshot(
                live_shot.stdout + "\n" + live_shot.stderr, out_dir, name, suffix="live"
            )
        live_image = str(live_path) if live_path is not None else None

        # 3) Open the recents overview — the OS blanks the thumbnail there,
        #    which is the artifact that matters. If we can't get there, we must
        #    NOT fall back to judging the live capture (false FAILs/PASSes).
        recents = _open_recents_revyl()
        if not recents.ok:
            results.append(
                _error_result(
                    name=name,
                    sensitive=sensitive,
                    reasons=[f"could not open the recents overview: {recents.detail}"],
                    live_image=live_image,
                )
            )
            _restore_app_revyl()  # best-effort; we may or may not be in recents
            continue

        # 4) Let the overview settle, then capture the recents thumbnail —
        #    the ONLY image that gets evaluated.
        time.sleep(_SHUTTER_WAIT_S)
        shot = _run_cli(["revyl", "device", "screenshot"])
        if not shot.ok:
            results.append(
                _error_result(
                    name=name,
                    sensitive=sensitive,
                    reasons=[f"`revyl device screenshot` (recents) failed: {shot.detail}"],
                    live_image=live_image,
                )
            )
            _restore_app_revyl()
            continue

        png_path = _resolve_revyl_screenshot(
            shot.stdout + "\n" + shot.stderr, out_dir, name, suffix="recents"
        )
        if png_path is None:
            results.append(
                _error_result(
                    name=name,
                    sensitive=sensitive,
                    reasons=[
                        "could not locate the PNG path in `revyl device screenshot` "
                        f"output: {(shot.stdout or shot.stderr or '').strip()[:300]!r}"
                    ],
                    live_image=live_image,
                )
            )
            _restore_app_revyl()
            continue

        # 5) Bring the app back so the next screen's instruction starts from
        #    the app, not the overview. Best-effort: failure is ignored.
        _restore_app_revyl()

        # 6) Load + evaluate the recents capture.
        try:
            img = Image.open(png_path)
            img.load()
        except Exception as exc:  # noqa: BLE001
            results.append(
                _error_result(
                    name=name,
                    sensitive=sensitive,
                    reasons=[f"failed to open captured PNG {png_path!r}: {exc}"],
                    snapshot_image=str(png_path),
                    live_image=live_image,
                )
            )
            continue

        verdict = _evaluate_or_error(img, secret_patterns)
        results.append(
            ScreenResult(
                name=name,
                platform="android",
                sensitive=sensitive,
                verdict=verdict,
                live_image=live_image,
                snapshot_image=str(png_path),
            )
        )

    if not screens:
        results.append(
            _error_result(
                name="<config>",
                sensitive=False,
                reasons=["android.screens is empty — nothing to check"],
            )
        )
    return results


def _open_recents_revyl() -> _CliResult:
    """Open the Android recents (app-switcher) overview on the active session.

    Kept as its own helper so the mechanism is easy to swap once it has been
    validated live — natural-language grounding of "recents" may need tuning,
    and there is no dedicated recents key in the Revyl CLI today.
    """
    return _run_cli(
        ["revyl", "device", "instruction", "open the recent apps overview screen"]
    )


def _restore_app_revyl() -> _CliResult:
    """Best-effort: bring the app back to the foreground from the recents view.

    The Revyl CLI has no guaranteed recents-exit primitive (no home keyevent),
    so we ask for the app's card by instruction. Callers ignore failures — the
    next screen's own instruction can usually recover from the overview.
    """
    return _run_cli(["revyl", "device", "instruction", "reopen the app from recents"])


def _resolve_revyl_screenshot(
    cli_output: str, out_dir: str, name: str, suffix: str = ""
) -> Path | None:
    """Find the PNG the `revyl device screenshot` CLI wrote, and stage it in out_dir.

    The CLI prints the saved path somewhere in its output; formats vary, so we
    parse robustly: pull the last token that looks like a .png path, verify it
    exists, then copy it into out_dir under a stable per-screen filename.
    ``suffix`` distinguishes multiple captures of the same screen (e.g. "live"
    vs "recents") so they don't overwrite each other.
    """
    text = cli_output or ""
    candidates: list[str] = []

    # Quoted path: "... saved to '/tmp/shot.png'" or "...\"shot.png\""
    candidates += re.findall(r"""['"]([^'"]+\.png)['"]""", text, flags=re.IGNORECASE)
    # Bare path token ending in .png (absolute or relative).
    candidates += re.findall(r"(\S+\.png)\b", text, flags=re.IGNORECASE)
    # Keyword-anchored path that may contain spaces (e.g. "saved to /My Shots/a.png").
    candidates += re.findall(
        r"(?:saved(?:\s+to)?|wrote|written\s+to|output|->|:)\s+(.+?\.png)\b",
        text, flags=re.IGNORECASE)

    seen: set[str] = set()
    ordered: list[str] = []
    for c in candidates:
        cc = c.strip().strip("'\"")
        if cc and cc not in seen:
            seen.add(cc)
            ordered.append(cc)

    safe = re.sub(r"[^A-Za-z0-9._-]+", "_", name).strip("_") or "screen"
    stem = f"android_{safe}_{suffix}" if suffix else f"android_{safe}"
    dest = Path(out_dir) / f"{stem}.png"

    # Prefer the last existing candidate (CLIs usually print the final path last).
    for cand in reversed(ordered):
        src = Path(cand)
        if src.is_file():
            try:
                if src.resolve() != dest.resolve():
                    shutil.copyfile(src, dest)
                return dest if dest.is_file() else src
            except Exception:  # noqa: BLE001 — fall back to the source path
                return src
    return None


# --------------------------------------------------------------------------- #
# Emulator / adb backend (fallback).
# --------------------------------------------------------------------------- #
def _run_emulator(android, secret_patterns, out_dir) -> list[ScreenResult]:
    """Local adb path. Degrades gracefully if the Android SDK / adb is absent.

    For each screen we capture the LIVE screen, then push to the recents
    (app-switcher) view and capture again — the recents thumbnail is where the
    FLAG_SECURE black-out matters most. We evaluate the recents capture.
    """
    from PIL import Image

    if shutil.which("adb") is None:
        return [
            _error_result(
                name=(s.get("name") or f"screen[{i}]"),
                sensitive=bool(s.get("sensitive", True)),
                reasons=["`adb` not found on PATH (Android SDK platform-tools missing)"],
            )
            for i, s in enumerate(android.get("screens") or [{}])
        ]

    screens = android.get("screens") or []
    results: list[ScreenResult] = []

    for idx, screen in enumerate(screens):
        name = screen.get("name") or f"screen[{idx}]"
        sensitive = bool(screen.get("sensitive", True))
        safe = re.sub(r"[^A-Za-z0-9._-]+", "_", name).strip("_") or "screen"

        # Optional: drive to the screen with an adb instruction string, if given.
        instruction = screen.get("instruction")
        if instruction:
            drive = _run_cli(["adb", "shell", str(instruction)])
            if not drive.ok:
                results.append(
                    _error_result(
                        name=name,
                        sensitive=sensitive,
                        reasons=[f"adb instruction failed: {drive.detail}"],
                    )
                )
                continue
            time.sleep(1.0)

        live_path = Path(out_dir) / f"android_{safe}_live.png"
        live_cap = _adb_screencap(live_path)
        if not live_cap.ok:
            results.append(
                _error_result(
                    name=name,
                    sensitive=sensitive,
                    reasons=[f"adb screencap (live) failed: {live_cap.detail}"],
                )
            )
            continue

        # Push to recents (app-switcher) and capture the thumbnail view.
        _run_cli(["adb", "shell", "input", "keyevent", "KEYCODE_APP_SWITCH"])
        time.sleep(1.0)
        recents_path = Path(out_dir) / f"android_{safe}_recents.png"
        recents_cap = _adb_screencap(recents_path)
        # Restore foreground regardless of capture outcome.
        _run_cli(["adb", "shell", "input", "keyevent", "KEYCODE_APP_SWITCH"])

        capture_path = recents_path if recents_cap.ok else live_path

        try:
            img = Image.open(capture_path)
            img.load()
        except Exception as exc:  # noqa: BLE001
            results.append(
                _error_result(
                    name=name,
                    sensitive=sensitive,
                    reasons=[f"failed to open captured PNG {capture_path!r}: {exc}"],
                    snapshot_image=str(capture_path),
                )
            )
            continue

        verdict = _evaluate_or_error(img, secret_patterns)
        results.append(
            ScreenResult(
                name=name,
                platform="android",
                sensitive=sensitive,
                verdict=verdict,
                live_image=str(live_path) if live_cap.ok else None,
                snapshot_image=str(capture_path),
            )
        )

    if not screens:
        results.append(
            _error_result(
                name="<config>",
                sensitive=False,
                reasons=["android.screens is empty — nothing to check"],
            )
        )
    return results


def _adb_screencap(dest: Path) -> "_CliResult":
    """`adb exec-out screencap -p` -> dest PNG, captured to a file."""
    try:
        proc = subprocess.run(
            ["adb", "exec-out", "screencap", "-p"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=_SUBPROCESS_TIMEOUT_S,
        )
    except FileNotFoundError:
        return _CliResult(False, "", "adb not found", "adb not found")
    except subprocess.TimeoutExpired:
        return _CliResult(False, "", "timeout", "adb screencap timed out")
    except Exception as exc:  # noqa: BLE001
        return _CliResult(False, "", str(exc), str(exc))

    if proc.returncode != 0 or not proc.stdout:
        detail = (proc.stderr or b"").decode("utf-8", "replace").strip() or "no image bytes"
        return _CliResult(False, "", detail, detail)
    try:
        Path(dest).write_bytes(proc.stdout)
    except Exception as exc:  # noqa: BLE001
        return _CliResult(False, "", str(exc), f"could not write {dest}: {exc}")
    return _CliResult(True, str(dest), "", "")


# --------------------------------------------------------------------------- #
# Shared helpers.
# --------------------------------------------------------------------------- #
class _CliResult:
    """Tiny result wrapper for a subprocess call."""

    __slots__ = ("ok", "stdout", "stderr", "detail")

    def __init__(self, ok: bool, stdout: str, stderr: str, detail: str):
        self.ok = ok
        self.stdout = stdout
        self.stderr = stderr
        self.detail = detail


def _run_cli(cmd: list[str]) -> _CliResult:
    """Run a CLI command defensively; never raises."""
    try:
        proc = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=_SUBPROCESS_TIMEOUT_S,
            text=True,
        )
    except FileNotFoundError:
        return _CliResult(False, "", "", f"{cmd[0]!r} not found on PATH")
    except subprocess.TimeoutExpired:
        return _CliResult(False, "", "", f"{' '.join(cmd)} timed out")
    except Exception as exc:  # noqa: BLE001
        return _CliResult(False, "", "", str(exc))

    stdout = proc.stdout or ""
    stderr = proc.stderr or ""
    if proc.returncode != 0:
        detail = (stderr or stdout).strip() or f"exit code {proc.returncode}"
        return _CliResult(False, stdout, stderr, detail)
    return _CliResult(True, stdout, stderr, "")


def _evaluate_or_error(img, secret_patterns) -> Verdict:
    """Call the shared verdict engine, mapping a missing engine to a clear ERROR."""
    try:
        evaluate = _load_evaluate()
    except ImportError as exc:
        return Verdict(status=ERROR, reasons=[str(exc)])
    try:
        return evaluate(snapshot=img, live=None, secret_patterns=secret_patterns)
    except Exception as exc:  # noqa: BLE001 — verdict bug must not crash the run
        return Verdict(status=ERROR, reasons=[f"evaluate() raised: {exc!r}"])


def _error_result(
    name: str,
    sensitive: bool,
    reasons: list[str],
    snapshot_image: str | None = None,
    live_image: str | None = None,
) -> ScreenResult:
    return ScreenResult(
        name=name,
        platform="android",
        sensitive=sensitive,
        verdict=Verdict(status=ERROR, reasons=reasons),
        live_image=live_image,
        snapshot_image=snapshot_image,
    )
