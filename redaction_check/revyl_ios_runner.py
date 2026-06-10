"""Revyl-native iOS runner — the Control Center backgrounding method.

Revyl's iOS cloud is a *simulator-only* device reachable only through the
``revyl`` CLI. Two facts make the local ``ios_runner`` (decode the SplashBoard
snapshot off disk) impossible here, and make the app switcher itself unreachable:

  * There is no container-file access — ``revyl device state`` can read an app's
    UserDefaults/SQLite, but not the ``Library/SplashBoard/Snapshots`` card, and
    ``code-execution`` runs in a separate Linux sandbox with no Simulator access.
  * The iOS app-switcher gesture is a swipe-up-*and-hold*. The CLI's ``swipe``
    controls a start point + duration but not the end point (distance is fixed,
    so it overshoots to Home); ``drag`` is point-to-point with no hold. Verified
    live 2026-06: neither opens the switcher, and there is no switcher primitive.

THE METHOD (verified live 2026-06 on the 1320x2868 Revyl iOS sim):

Pulling **Control Center** makes the foreground app resign-active — the *same*
``scenePhase != .active`` transition the OS uses when it writes the app-switcher
snapshot. A correctly-built app draws its privacy cover on that transition; a
leaky one keeps rendering its content. Both are observable with a plain
``revyl device screenshot`` (unlike ``hierarchy``, whose WDA backend drops while
Control Center is foreground). So per screen we:

  1. navigate to the screen and screenshot it ACTIVE (the content baseline)
  2. pull Control Center (a partial pull leaves the app's inactive rendering
     visible below the status sliver), screenshot it INACTIVE
  3. dismiss Control Center to restore the app for the next screen

THE VERDICT (differential, blur-invariant):

Control Center dims (~60%) and blurs whatever is behind it — uniformly, to both
the cover and the leak — so absolute brightness / OCR / ``verdict.diff_ratio``
(absolute pixel diff) all mis-fire. What survives the blur is *layout structure*.
So we compare the active and inactive frames with a zero-mean normalised
cross-correlation (ZNCC), which is invariant to global dimming and blur:

    corr(active, inactive) high  =>  the inactive frame is just a dimmed/blurred
                                     copy of the live screen — content was NOT
                                     obscured  =>  FAIL (leak)
    corr low                     =>  the content was replaced by an unrelated
                                     cover  =>  PASS

Measured on the fixture: leaky corr ~0.88, redacted corr ~0.05 (cover is the
black PrivacyCover). OCR secret-matching still runs on the inactive frame as a
*corroborating* signal — if a secret survives the blur it is a definitive FAIL
with quotable ``leaked_text`` — but the ZNCC test is the primary decision.

Every subprocess call is wrapped defensively: a missing/erroring ``revyl`` yields
a per-screen ``Verdict(status=ERROR, ...)`` — a single bad screen never crashes
the whole run.
"""
from __future__ import annotations

import os
import shutil
import subprocess
import sys
import time
from pathlib import Path

import numpy as np

from .contract import ERROR, FAIL, PASS, ScreenResult, Verdict, compile_secret_patterns

# Revyl's screenshot shutter is ~2.3s; give the UI margin to settle before capture.
_SHUTTER_WAIT_S = 3.0
_SUBPROCESS_TIMEOUT_S = 120

# Verdict thresholds on the active<->inactive ZNCC. Measured gap is wide
# (leak ~0.88 vs cover ~0.05); we leave a deliberate ERROR band between them so a
# mid-range correlation is flagged for review rather than guessed either way.
_FAIL_CORR = 0.50        # >= this: inactive still tracks the live screen -> not obscured -> FAIL
_PASS_CORR = 0.25        # <  this: structurally unrelated -> candidate cover (band between -> review)
# A real privacy cover (or a dimmed/blurred app) is flat; a structurally-rich
# *unrelated* frame at low corr is more likely Control Center chrome or the wrong
# screen, so we refuse to call that a PASS.
_COVER_FLAT_STD = 15.0
# An active baseline flatter than this carries no layout to correlate against —
# navigation probably never reached a real screen, so ERROR rather than guess.
_MIN_BASELINE_STDDEV = 3.0
# Control Center dims the backdrop ~60%. If the inactive frame is NOT dimmer than
# this ratio of the active frame AND still correlates above _CC_SAME_CORR, the app
# never went inactive (Control Center didn't engage) — we tested nothing.
_CC_DIM_MAX_RATIO = 0.85
_CC_SAME_CORR = 0.90

# Small canvas both frames are squished to for the structural comparison.
_DOWNSCALE = (48, 96)
# Structural compare: crop the Control Center status sliver (top) + home indicator (bottom).
_CROP_TOP = 0.13
_CROP_BOTTOM = 0.93
# OCR backstop: a lighter top crop so a top-of-screen secret isn't clipped away.
_OCR_CROP_TOP = 0.06
# Screenshot pixel size the default gestures + crop fractions are tuned for.
_CALIBRATED_SIZE = (1320, 2868)

# Default Control Center gestures, verified on the 1320x2868 Revyl iOS sim. The
# swipe coordinate space is ~half the screenshot pixel space. Override per-config
# under ios.gestures.{cc_open,cc_close} for a differently-sized device.
_CC_OPEN = {"direction": "down", "x": 600, "y": 2, "duration": 1200}
_CC_CLOSE = {"direction": "up", "x": 330, "y": 1430, "duration": 400}


# --------------------------------------------------------------------------- #
# Public entry point.
# --------------------------------------------------------------------------- #
def run_ios_revyl(config: dict, out_dir: str) -> list[ScreenResult]:
    """Run the Revyl-native iOS redaction check for every configured screen.

    Assumes an active Revyl iOS session (Billing Test org concurrency = 1, so we
    never start a session here; drive whatever is live). Errors are reported
    per-screen as ``Verdict(status=ERROR, ...)``; this never raises for device or
    CLI failures.
    """
    ios = (config or {}).get("ios") or {}
    bundle_id = ios.get("bundle_id")
    secret_patterns = (config or {}).get("secrets")
    os.makedirs(out_dir, exist_ok=True)

    screens = ios.get("screens") or []

    if shutil.which("revyl") is None:
        return [
            _error_result(
                name=(s.get("name") or f"screen[{i}]"),
                sensitive=bool(s.get("sensitive", True)),
                reasons=["`revyl` CLI not found on PATH"],
            )
            for i, s in enumerate(screens or [{}])
        ]

    gestures = ios.get("gestures") or {}
    cc_open = {**_CC_OPEN, **(gestures.get("cc_open") or {})}
    cc_close = {**_CC_CLOSE, **(gestures.get("cc_close") or {})}

    results: list[ScreenResult] = []
    size_warned = bool(gestures)  # skip the size warning if the device's gestures are overridden
    for idx, screen in enumerate(screens):
        name = screen.get("name") or f"screen[{idx}]"
        sensitive = bool(screen.get("sensitive", True))
        # A malformed nav step or any unexpected error must fail just THIS screen,
        # never the whole run (matches the per-screen-isolation guarantee).
        try:
            expect = screen.get("expect")

            # 1) Navigate to the screen.
            nav = _navigate(screen, bundle_id)
            if not nav.ok:
                results.append(_error_result(name, sensitive, [f"navigation failed: {nav.detail}"]))
                continue
            time.sleep(_SHUTTER_WAIT_S)

            # 2) Active baseline capture.
            active_path = _screenshot(out_dir, name, "active")
            if active_path is None:
                results.append(_error_result(name, sensitive, ["`revyl device screenshot` (active) failed"]))
                continue
            if not size_warned:
                size_warned = _warn_if_unexpected_size(active_path)

            # 3) Pull Control Center -> app resigns active -> capture the inactive frame.
            _cc_open(cc_open)
            time.sleep(_SHUTTER_WAIT_S)
            inactive_path = _screenshot(out_dir, name, "inactive")
            # Always dismiss Control Center so the next screen starts from the app.
            _cc_close(cc_close)
            time.sleep(1.0)

            if inactive_path is None:
                results.append(
                    _error_result(name, sensitive,
                                  ["`revyl device screenshot` (inactive/Control Center) failed"],
                                  live_image=str(active_path))
                )
                continue

            # 4) Decide.
            verdict = _evaluate_cc(active_path, inactive_path, secret_patterns,
                                   sensitive=sensitive, expect=expect)
            results.append(
                ScreenResult(
                    name=name,
                    platform="ios",
                    sensitive=sensitive,
                    verdict=verdict,
                    live_image=str(active_path),
                    snapshot_image=str(inactive_path),
                )
            )
        except Exception as exc:  # noqa: BLE001 — one bad screen must not kill the run
            results.append(_error_result(name, sensitive, [f"runner error: {exc!r}"]))

    if not screens:
        results.append(
            _error_result("<config>", False, ["ios.screens is empty — nothing to check"])
        )
    return results


# --------------------------------------------------------------------------- #
# Navigation — a small step vocabulary so the fixture (coordinate taps) and real
# apps (NL instructions / deep links) are both reachable.
# --------------------------------------------------------------------------- #
def _navigate(screen: dict, bundle_id: str | None) -> "_CliResult":
    """Drive to the screen. Uses screen['nav'] (a list of steps) if present, else
    falls back to a single 'instruction' (cold-launch then ground it) or a
    'deeplink'. A step is one of:

        {"kill": true}                 -> revyl device kill-app
        {"launch": "<bundle>"|true}    -> revyl device launch <bundle|ios.bundle_id>
        {"tap": [x, y]}                -> revyl device tap --x --y  (raw coords)
        {"instruction": "..."}         -> revyl device instruction <text>
        {"deeplink": "..."}            -> revyl device navigate <url>
        {"wait": <seconds>}            -> sleep
    """
    steps = screen.get("nav")
    if not steps:
        if screen.get("instruction"):
            steps = [
                {"kill": True}, {"launch": True}, {"wait": 2},
                {"instruction": screen["instruction"]},
            ]
        elif screen.get("deeplink"):
            steps = [{"deeplink": screen["deeplink"]}]
        else:
            return _CliResult(False, "", "",
                              "iOS screen has no `nav`, `instruction`, or `deeplink`")

    for step in steps:
        if "wait" in step:
            time.sleep(float(step["wait"]))
            continue
        if "kill" in step and step["kill"]:
            _run_cli(["revyl", "device", "kill-app"])  # best-effort; app may not be running
            continue
        if "launch" in step:
            target = step["launch"]
            target = bundle_id if target is True else str(target)
            if not target:
                return _CliResult(False, "", "", "launch step needs a bundle id (set ios.bundle_id)")
            r = _run_cli(["revyl", "device", "launch", target])
            if not r.ok:
                return r
            continue
        if "tap" in step:
            x, y = step["tap"]
            r = _run_cli(["revyl", "device", "tap", "--x", str(int(x)), "--y", str(int(y))])
            if not r.ok:
                return r
            continue
        if "instruction" in step:
            r = _run_cli(["revyl", "device", "instruction", str(step["instruction"])])
            if not r.ok:
                return r
            continue
        if "deeplink" in step:
            r = _run_cli(["revyl", "device", "navigate", str(step["deeplink"])])
            if not r.ok:
                return r
            continue
        return _CliResult(False, "", "", f"unknown nav step: {step!r}")
    return _CliResult(True, "", "", "")


# --------------------------------------------------------------------------- #
# Control Center gestures + capture.
# --------------------------------------------------------------------------- #
def _cc_open(g: dict) -> None:
    _run_cli(["revyl", "device", "swipe", "--direction", g["direction"],
              "--x", str(int(g["x"])), "--y", str(int(g["y"])),
              "--duration", str(int(g["duration"]))])


def _cc_close(g: dict) -> None:
    _run_cli(["revyl", "device", "swipe", "--direction", g["direction"],
              "--x", str(int(g["x"])), "--y", str(int(g["y"])),
              "--duration", str(int(g["duration"]))])


def _screenshot(out_dir: str, name: str, suffix: str) -> Path | None:
    """`revyl device screenshot --out <path>` -> staged PNG, or None on failure.

    The CLI writes directly to --out, so we just confirm the file exists.
    """
    import re
    safe = re.sub(r"[^A-Za-z0-9._-]+", "_", name).strip("_") or "screen"
    dest = Path(out_dir) / f"ios_{safe}_{suffix}.png"
    r = _run_cli(["revyl", "device", "screenshot", "--out", str(dest)])
    if r.ok and dest.is_file():
        return dest
    return None


# --------------------------------------------------------------------------- #
# Differential verdict.
# --------------------------------------------------------------------------- #
def _prep(img) -> np.ndarray:
    """Grayscale, crop away Control Center chrome + home indicator, downscale."""
    g = img.convert("L")
    w, h = g.size
    g = g.crop((0, int(h * _CROP_TOP), w, int(h * _CROP_BOTTOM))).resize(_DOWNSCALE)
    return np.asarray(g, dtype=np.float32)


def _zncc(a: np.ndarray, b: np.ndarray) -> float:
    """Zero-mean normalised cross-correlation: invariant to global brightness and
    contrast (so Control Center's uniform dim/blur cancels out). Returns 0.0 when
    either frame is ~uniform (a cover has no structure to match)."""
    a = a - a.mean()
    b = b - b.mean()
    da, db = float(np.sqrt((a * a).sum())), float(np.sqrt((b * b).sum()))
    if da < 1e-3 or db < 1e-3:
        return 0.0
    return float((a * b).sum() / (da * db))


def _ocr_secrets(inactive_img, secret_patterns) -> list[str]:
    """Corroborating signal: OCR the (cropped) inactive frame and match secret
    patterns. Usually defeated by Control Center's blur, but a survivor is a
    definitive leak. Never raises."""
    try:
        import pytesseract  # local import: keep the module importable without tesseract
    except Exception:  # noqa: BLE001
        return []
    g = inactive_img.convert("L")
    w, h = g.size
    g = g.crop((0, int(h * _OCR_CROP_TOP), w, int(h * _CROP_BOTTOM)))
    try:
        text = pytesseract.image_to_string(g)
    except Exception:  # noqa: BLE001 — tesseract misconfig must not crash the run
        return []
    leaked: list[str] = []
    for pat in compile_secret_patterns(secret_patterns):
        for m in pat.findall(text):
            hit = (m if isinstance(m, str) else "".join(m)).strip()
            if hit and hit not in leaked:
                leaked.append(hit)
    return leaked


def _evaluate_cc(active_path: Path, inactive_path: Path, secret_patterns,
                 sensitive: bool = True, expect: str | None = None) -> Verdict:
    """Compare the active and inactive (Control Center) frames and decide.

    Conservative for a security tool: a PASS is only issued with positive evidence
    that (a) we reached the intended screen, (b) Control Center actually
    backgrounded the app, and (c) the content was replaced by a cover. Anything
    ambiguous is ERROR, never a silent PASS.
    """
    from PIL import Image

    metrics: dict = {}
    try:
        active_img = Image.open(active_path); active_img.load()
        inactive_img = Image.open(inactive_path); inactive_img.load()
    except Exception as exc:  # noqa: BLE001
        return Verdict(status=ERROR, reasons=[f"failed to open captures: {exc}"], metrics=metrics)

    A, I = _prep(active_img), _prep(inactive_img)
    active_mean, inactive_mean = float(A.mean()), float(I.mean())
    active_std, inactive_std = float(A.std()), float(I.std())
    metrics.update(active_mean=round(active_mean, 1), inactive_mean=round(inactive_mean, 1),
                   inactive_std=round(inactive_std, 1))

    # 0) Baseline sanity: a near-uniform active frame means we never landed on a
    #    real screen, so there is no content to compare against.
    if active_std < _MIN_BASELINE_STDDEV:
        return Verdict(status=ERROR, metrics=metrics, reasons=[
            "Active screen is near-uniform; navigation may not have reached a real screen."])

    # 1) Confirm we reached the INTENDED screen. A tap on empty space or a
    #    mis-grounded instruction still exits 0, so without this a PASS could be
    #    certified against a screen we never tested. Skip only if OCR is
    #    unavailable (then we can't verify, and say so) — never silently.
    if expect:
        active_text = _ocr_text(active_img)
        if active_text and _norm(expect) not in _norm(active_text):
            return Verdict(status=ERROR, metrics=metrics, reasons=[
                f"Expected landmark {expect!r} not visible on the active screen; "
                f"navigation did not reach it (no verdict)."])
        if not active_text:
            metrics["landmark_check"] = "skipped (no OCR available)"

    corr = _zncc(A, I)
    metrics["active_inactive_corr"] = round(corr, 3)

    # 2) Confirm Control Center actually backgrounded the app BEFORE trusting the
    #    inactive frame. If it's neither dimmer nor structurally changed, CC never
    #    engaged — the "inactive" capture is really the live screen, so its content
    #    is meaningless and judging it would falsely FAIL a secured screen. ERROR.
    if (inactive_mean / max(active_mean, 1.0)) > _CC_DIM_MAX_RATIO and corr > _CC_SAME_CORR:
        return Verdict(status=ERROR, metrics=metrics, reasons=[
            "Backgrounded capture matches the live screen in brightness and layout; "
            "Control Center did not engage (the app never went inactive). Re-run."])

    # 3) Corroboration: a secret that survives the blur in a genuine backgrounded
    #    frame is a definitive leak, sensitive or not.
    leaked = _ocr_secrets(inactive_img, secret_patterns)
    if leaked:
        return Verdict(status=FAIL, leaked_text=leaked, metrics=metrics, reasons=[
            f"Secret pattern(s) recovered from the backgrounded capture: {', '.join(leaked)}."])

    # 4) Non-sensitive screens: content visible when inactive is expected and fine;
    #    only a recovered secret (handled above) is a violation.
    if not sensitive:
        return Verdict(status=PASS, metrics=metrics, reasons=[
            "Non-sensitive screen; no secret recovered from the backgrounded capture."])

    # 5) Decide on structure, with a deliberate ERROR band in the middle.
    if corr >= _FAIL_CORR:
        return Verdict(status=FAIL, metrics=metrics, reasons=[
            f"Backgrounded capture still tracks the live screen (corr={corr:.2f} >= {_FAIL_CORR}): "
            f"the app did not obscure its content when inactive."])
    if corr < _PASS_CORR:
        # Low correlation alone isn't proof of a cover — it could be Control Center
        # chrome or the wrong screen. A genuine cover (or a dimmed/blurred app) is
        # flat; require that before calling it a PASS.
        if inactive_std <= _COVER_FLAT_STD:
            return Verdict(status=PASS, metrics=metrics, reasons=[
                f"Backgrounded capture is unrelated to the live screen (corr={corr:.2f} < {_PASS_CORR}) "
                f"and flat (std={inactive_std:.1f}): a privacy cover obscured the content."])
        return Verdict(status=ERROR, metrics=metrics, reasons=[
            f"Backgrounded capture is unrelated to the live screen (corr={corr:.2f}) but not flat "
            f"(std={inactive_std:.1f}): likely Control Center chrome or the wrong screen, not a cover. Re-run."])
    return Verdict(status=ERROR, metrics=metrics, reasons=[
        f"Inconclusive correlation (corr={corr:.2f}, between {_PASS_CORR} and {_FAIL_CORR}); "
        f"cannot confirm whether the content was obscured. Re-run."])


def _norm(s: str) -> str:
    """Lowercase, alphanumerics only — tolerant landmark matching against OCR."""
    return "".join(c for c in s.lower() if c.isalnum())


def _ocr_text(img) -> str:
    """OCR a frame (light top crop) for landmark confirmation. "" if unavailable."""
    try:
        import pytesseract
    except Exception:  # noqa: BLE001
        return ""
    g = img.convert("L")
    w, h = g.size
    g = g.crop((0, int(h * _OCR_CROP_TOP), w, int(h * _CROP_BOTTOM)))
    try:
        return pytesseract.image_to_string(g)
    except Exception:  # noqa: BLE001
        return ""


def _warn_if_unexpected_size(path: Path) -> bool:
    """Warn once if the screenshot isn't the size the default gestures are tuned
    for — the Control Center pull + crops would then be misaligned. Returns True
    so the caller stops re-checking."""
    try:
        from PIL import Image
        size = Image.open(path).size
    except Exception:  # noqa: BLE001
        return True
    if size != _CALIBRATED_SIZE:
        print(f"  warning: screenshot is {size[0]}x{size[1]}, but the default Control Center "
              f"gestures + crops are tuned for {_CALIBRATED_SIZE[0]}x{_CALIBRATED_SIZE[1]}. "
              f"If iOS verdicts look off, set ios.gestures.cc_open/cc_close for this device.",
              file=sys.stderr)
    return True


# --------------------------------------------------------------------------- #
# Shared helpers (mirrors android_runner's defensive subprocess style).
# --------------------------------------------------------------------------- #
class _CliResult:
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


def _error_result(name: str, sensitive: bool, reasons: list[str],
                  live_image: str | None = None) -> ScreenResult:
    return ScreenResult(
        name=name,
        platform="ios",
        sensitive=sensitive,
        verdict=Verdict(status=ERROR, reasons=reasons),
        live_image=live_image,
        snapshot_image=None,
    )
