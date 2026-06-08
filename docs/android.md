# Android runner — runbook

The Android runner (`redaction_check/android_runner.py`) checks whether sensitive
screens (payment, SSN, etc.) are obscured the way an attacker or the OS recents
view would see them.

**The signal.** A screen marked `FLAG_SECURE` makes Android render a **BLACK**
frame for screen capture *and* the recents thumbnail. So:

| What the capture looks like | Verdict |
| --- | --- |
| (near-)black frame | **PASS** — content was protected |
| readable sensitive content | **FAIL** — leak |
| device/CLI error | **ERROR** — couldn't determine (run not aborted) |

The actual black-vs-readable judgement is made by the shared verdict engine
(`redaction_check.verdict.evaluate`), not here.

## Backends

`config["android"]["backend"]` selects the device path:

- **`revyl`** (primary) — drives an already-active Revyl cloud session via the
  `revyl` CLI.
- **`emulator`** (fallback) — local `adb` against an emulator or USB device.
- **mock** — set `config["android"]["mock_screenshots"]` to a list of PNG paths;
  all device I/O is skipped and the engine runs on those images (paired to
  `screens` by index). For pipeline testing with no device and no SDK.

Every device/CLI failure is captured as a per-screen `ERROR` result — one bad
screen never aborts the whole run.

## Prerequisites

### Revyl backend
- A Revyl **Android** app uploaded (`revyl build upload --app <app>` — note it's
  `--app`, *not* `--app-id`).
- **Exactly one active device session.** The Billing Test org has device
  concurrency = 1, so the runner does **not** start a session — it assumes one is
  live and steers it with `revyl device instruction`. Start a session yourself
  first (e.g. `revyl device start --app-id <id>` — note this installs the
  **latest** build, not necessarily your current one).
- `revyl` on `PATH`, authenticated.

### Emulator backend
- Android SDK platform-tools (`adb`) on `PATH`.
- A running emulator/device (`adb devices` shows one).

## Config shape

```jsonc
{
  "android": {
    "backend": "revyl",              // "revyl" | "emulator" | (omit for mock)
    "screens": [
      { "name": "payment-form", "instruction": "open the payment screen", "sensitive": true },
      { "name": "ssn-entry",    "instruction": "tap Profile, then SSN",     "sensitive": true }
    ],
    // mock mode — overrides backend, no device needed:
    "mock_screenshots": ["spike/expo_content.png", "spike/loop_blank.png"]
  },
  "secrets": ["\\bSSN\\b", "\\b\\d{3}-\\d{2}-\\d{4}\\b"]   // optional; defaults from contract.py
}
```

## How to run

```python
from redaction_check.android_runner import run_android
results = run_android(config, out_dir="out/android")   # -> list[ScreenResult]
```

Captured PNGs are written into `out_dir` (e.g. `out/android/android_<screen>.png`).

### Per-screen flow
- **Revyl:** `revyl device instruction "<screen.instruction>"` → wait ~3s (the
  Revyl screenshot shutter is ~2.3s) → `revyl device screenshot` → parse the PNG
  path the CLI prints, copy it into `out_dir`, load it, `evaluate()`.
- **Emulator:** drive (optional) → `adb exec-out screencap -p` (live) →
  `KEYCODE_APP_SWITCH` to recents → `screencap` again → restore foreground →
  `evaluate()` the **recents** thumbnail (that's where the FLAG_SECURE black-out
  matters most), falling back to the live frame if recents capture fails.

### Mock test

```sh
PYTHONPATH=. .venv/bin/python spike/test_android_mock.py
```

Expectation: `spike/expo_content.png` → **FAIL** (readable), `spike/loop_blank.png`
→ **PASS** (black). The test is tolerant of `redaction_check/verdict.py` being
absent — if the engine isn't built yet it still verifies mock dispatch and the
`ERROR` path, and skips the verdict assertions with a clear message.

## ⚠️ ONE assumption to verify on a real Revyl Android device

**Does `revyl device screenshot` of a `FLAG_SECURE` screen actually come back
BLACK on Revyl's cloud Android device?**

The entire PASS signal depends on this. It is **true on stock/production Android**,
but **some cloud emulators and rooted/eng-build system images do NOT honor
`FLAG_SECURE` for `screencap`** — they happily capture the real pixels. If that's
the case on Revyl's fleet, a protected screen will read as content and the runner
will report a false **FAIL**.

**How to verify:** put a real app screen behind `FLAG_SECURE`
(`getWindow().setFlags(FLAG_SECURE, FLAG_SECURE)`), drive to it on a live Revyl
Android session, run `revyl device screenshot`, and confirm the PNG is black.

**If it is NOT black, fall back to one of:**
1. **Recents thumbnail** instead of the live screencap — Android blanks the
   recents card from `FLAG_SECURE` windows even on some images where `screencap`
   leaks (the emulator path already evaluates the recents frame for this reason).
2. **In-app `FLAG_SECURE` reflection check** — have the app expose, via a
   test-only hook/deep link, whether the current window actually has `FLAG_SECURE`
   set, and assert on that instead of (or alongside) the pixel signal.
