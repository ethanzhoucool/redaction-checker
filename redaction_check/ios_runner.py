"""iOS runner: drive a local Simulator to each sensitive screen, force the
app-switcher snapshot, harvest it from disk, and evaluate it.

Mechanics (all via `xcrun simctl`, no third-party device tooling):
  1. boot the sim + install the .app
  2. per screen: cold-launch at the target route (terminate -> launch with args),
     or open a deep link
  3. screenshot the live (foregrounded) screen as ground truth
  4. background the app (launch a neutral system app) so SpringBoard writes the
     SplashBoard snapshot
  5. wait for a snapshot newer than the trigger, decode it, and evaluate it
"""
from __future__ import annotations

import shutil
import subprocess
import time
from pathlib import Path

from . import ios_snapshot
from .contract import Verdict, ScreenResult, ERROR

# System apps used only to push our app to the background (first that launches wins).
_BACKGROUND_APPS = ["com.apple.mobilesafari", "com.apple.Preferences", "com.apple.MobileSMS"]


def _sim(*args, check=False, timeout=60) -> subprocess.CompletedProcess:
    return subprocess.run(["xcrun", "simctl", *args],
                          capture_output=True, text=True, check=check, timeout=timeout)


def _resolve_udid(udid: str | None) -> str:
    if udid and udid != "booted":
        return udid
    out = _sim("list", "devices", "booted").stdout
    for line in out.splitlines():
        if "(Booted)" in line and "(" in line:
            # ... DeviceName (UDID) (Booted)
            return line.split("(")[-2].strip().rstrip(")").strip() or _first_available()
    return _first_available()


def _first_available() -> str:
    out = _sim("list", "devices", "available").stdout
    for line in out.splitlines():
        if "iPhone" in line and "(" in line and "unavailable" not in line.lower():
            parts = line.split("(")
            if len(parts) >= 2:
                return parts[-2].strip().rstrip(")").strip()
    raise RuntimeError("no available iPhone simulator found")


def _boot(udid: str) -> None:
    _sim("boot", udid)            # no-op if already booted
    _sim("bootstatus", udid, timeout=120)


def _background(device: str) -> bool:
    for app in _BACKGROUND_APPS:
        if _sim("launch", device, app).returncode == 0:
            return True
    return False


def _newest_mtime(bundle_id: str, udid: str) -> float:
    snaps = ios_snapshot.find_snapshots(bundle_id, udid=udid)
    return snaps[0].path.stat().st_mtime if snaps else 0.0


def run_ios(config: dict, out_dir: str) -> list[ScreenResult]:
    ios = config.get("ios", {})
    bundle_id = ios["bundle_id"]
    sel = ios.get("udid") or "booted"
    udid = _resolve_udid(sel)                          # real UDID — used to locate snapshots on disk
    device = "booted" if sel == "booted" else udid     # selector for simctl commands
    out = Path(out_dir).resolve()   # simctl io screenshot needs an absolute path
    out.mkdir(parents=True, exist_ok=True)
    secrets = config.get("secrets")

    _boot(udid)
    app_path = ios.get("app_path")
    if app_path and Path(app_path).exists():
        _sim("install", device, app_path)

    results: list[ScreenResult] = []
    for i, screen in enumerate(ios.get("screens", [])):
        name = screen.get("name", f"screen-{i}")
        try:
            results.append(_check_screen(device, udid, bundle_id, screen, name, out, secrets, i))
        except Exception as e:  # never let one screen kill the run
            results.append(ScreenResult(
                name=name, platform="ios", sensitive=screen.get("sensitive", True),
                verdict=Verdict(status=ERROR, reasons=[f"runner error: {e}"]),
            ))
    return results


def _check_screen(device, udid, bundle_id, screen, name, out: Path, secrets, idx) -> ScreenResult:
    from .verdict import evaluate  # lazy: tolerate verdict.py landing later

    # 1. navigate to the screen
    if screen.get("deeplink"):
        _sim("openurl", device, screen["deeplink"])
    else:
        _sim("terminate", device, bundle_id)
        args = screen.get("launch_args") or []
        if isinstance(args, str):
            args = args.split()
        _sim("launch", device, bundle_id, *args)
    time.sleep(2.2)

    # 2. live ground-truth screenshot
    live_path = out / f"{idx:02d}_{_slug(name)}_live.png"
    _sim("io", device, "screenshot", str(live_path))

    # 3. background -> force the OS to write the app-switcher snapshot
    trigger = _newest_mtime(bundle_id, udid)
    if not _background(device):
        return ScreenResult(name=name, platform="ios", sensitive=screen.get("sensitive", True),
                            live_image=str(live_path),
                            verdict=Verdict(status=ERROR, reasons=["could not background the app"]))

    # 4. wait for a snapshot newer than the trigger
    snap = None
    deadline = time.time() + 8
    while time.time() < deadline:
        snaps = ios_snapshot.find_snapshots(bundle_id, udid=udid)
        if snaps and snaps[0].path.stat().st_mtime > trigger + 0.01:
            snap = snaps[0]
            break
        time.sleep(0.4)

    from PIL import Image
    live_img = Image.open(live_path) if live_path.exists() else None
    if snap is None:
        return ScreenResult(name=name, platform="ios", sensitive=screen.get("sensitive", True),
                            live_image=str(live_path),
                            verdict=Verdict(status=ERROR, reasons=["no app-switcher snapshot was written"]))

    snap_img = ios_snapshot.decode(snap.path)
    snap_path = out / f"{idx:02d}_{_slug(name)}_snapshot.png"
    snap_img.save(snap_path)

    verdict = evaluate(snap_img, live=live_img, compressed_bytes=snap.compressed_payload,
                       secret_patterns=secrets)
    verdict.metrics.setdefault("snapshot_file_bytes", snap.file_size)
    verdict.metrics.setdefault("snapshot_dims", f"{snap.width}x{snap.height}")
    return ScreenResult(
        name=name, platform="ios", sensitive=screen.get("sensitive", True),
        verdict=verdict, live_image=str(live_path), snapshot_image=str(snap_path),
    )


def _slug(s: str) -> str:
    return "".join(c if c.isalnum() else "-" for c in s.lower()).strip("-")[:40]
