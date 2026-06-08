# redaction-checker

**Catch sensitive screens that leak into the iOS app switcher and Android recents — before an auditor (or attacker) does.**

When your app goes to the background, the OS takes a snapshot of the current screen to render the app-switcher card (iOS) or recents thumbnail (Android). If the screen on top is a payment form, an SSN entry, or anything else sensitive, that snapshot **persists to disk in plaintext** and shows up the next time someone double-taps the home button. `redaction-checker` drives your app to its sensitive screens, backgrounds it, recovers the snapshot the OS actually wrote, and tells you `PASS` or `FAIL` with the recovered text as evidence.

---

## Why most apps fail

This maps to a real compliance control:

> **OWASP MASVS MSTG-STORAGE-9 / PCI-MSTG** — *Sensitive data must be removed from views when the app is moved to the background.*

It's one of the most commonly-failed items in a mobile pentest, because nothing in the normal dev loop surfaces it. The app looks fine. The screen renders correctly. The leak only exists in a file the OS writes on your behalf when the app resigns active — a file you never see unless you go looking for it. So the bug ships, and the first time anyone notices is during an audit or a breach writeup.

The two classic root-cause bugs this tool catches:

- **Android — `FLAG_SECURE` set too late.** Devs set it in `onPause()`. By then the recents snapshot has already been taken. The screen leaks anyway.
- **iOS — no privacy overlay on resign.** Devs forget to cover the window when the scene goes `.inactive` (`scenePhase`) / on `applicationWillResignActive`. The live payment form gets captured verbatim.

Both render identically in normal use. Only the snapshot tells the truth.

---

## How it works

A redacted screen produces a **blank/obscured** snapshot. A leaky screen produces a **readable** one. The whole tool is built around making that difference machine-checkable.

### iOS — recover the snapshot the OS actually wrote

iOS doesn't hand you a screenshot; it persists the app-switcher card to disk as an Apple **`AAPL`** container with a misleading `.ktx` extension. We reverse that format end-to-end, with **no external binaries**:

```
SplashBoard/Snapshots/<scene-with-bundle-id>/*.ktx
        │
        │  AAPL header                  (find_snapshots → read_header)
        ▼
   LZFSE-compressed payload             (libcompression via ctypes)
        │
        ▼
   raw ASTC 4x4 texture                 (texture2ddecoder)
        │
        ▼
        PNG  ──►  OCR  ──►  verdict      (Tesseract + secret regex)
```

The compressed size alone is most of the signal: a blank/redacted snapshot LZFSE-crushes to **~2 KB**; a real leak is **50 KB+** and the text comes back OCR-readable. We decode it the rest of the way to produce side-by-side evidence images.

### Android — let `FLAG_SECURE` blacken the frame

Android is simpler: a window with `FLAG_SECURE` (or, on API 33+, `setRecentsScreenshotEnabled(false)`) makes screen capture and the recents thumbnail come back **black**. So we don't reverse a file — we just capture the screen and check whether it went dark.

```
revyl device screenshot   (cloud device — primary)
        │   └─ adb fallback for a local emulator
        ▼
   captured frame
        │
        ▼
  black? ──► PASS        readable? ──► OCR ──► secret regex ──► FAIL
```

Primary capture backend is **Revyl** (`revyl device screenshot`); a local-emulator `adb` path is the fallback.

### Shared verdict engine

Both platforms feed one engine: OCR + secret-regex (SSN / PAN / CVV) + blank/blur/compressed-size heuristics → `PASS` / `FAIL`, with side-by-side evidence images and a markdown/HTML report.

| Stage | iOS | Android |
|---|---|---|
| Drive to screen | deeplink | `revyl device instruction` (natural language) |
| Background it | launch another app | press Home |
| Capture | decode AAPL snapshot from disk | `revyl device screenshot` |
| Decide | OCR + regex + compressed-size | OCR + regex + blackness |

---

## Install

```bash
# from the repo root
python3 -m venv .venv
source .venv/bin/activate
pip install pillow numpy pytesseract texture2ddecoder pyyaml

# OCR engine (macOS)
brew install tesseract

# Revyl CLI (Android capture backend)
# https://github.com/RevylAI/revyl-cli
```

The iOS path is macOS-only — it reads from `~/Library/Developer/CoreSimulator/Devices` and decodes LZFSE via the system `libcompression.dylib`. No Xcode command-line decoder needed.

---

## Usage

Point the tool at a target by describing its sensitive screens in `sensitive-screens.yml`, then run the checker:

```bash
source .venv/bin/activate
python -m redaction_check sensitive-screens.yml
```

For each sensitive screen the tool will: drive the app to it, background it, recover the snapshot, run the verdict engine, and write `report.md` + evidence PNGs. A single `FAIL` exits non-zero — drop it straight into CI (template under `.github/workflows/`).

A minimal config:

```yaml
ios:
  bundle_id: com.revyl.redactiondemo
  udid: "booted"
  screens:
    - { name: "Add Card", deeplink: "redactiondemo://payment/leaky", sensitive: true }

android:
  backend: "revyl"
  revyl_app_id: "<your-revyl-app-id>"
  package: com.revyl.redactiondemo
  screens:
    - { name: "SSN entry", instruction: "open the SSN entry screen", sensitive: true }
```

See `sensitive-screens.yml` for the full shape (custom `secrets` regexes, `background_via`, etc.) and `CLAUDE.md` for how to point Claude Code at a new app.

---

## Sample report

```
redaction-checker — MSTG-STORAGE-9 / PCI-MSTG
target: com.revyl.redactiondemo

[PASS] iOS · Add Card (redacted)
       snapshot 1.9 KB · ocr_chars 0 · stddev 0.4
       → app-switcher card is blank; no sensitive text recovered

[FAIL] iOS · Add Card (leaky)
       snapshot 71.3 KB · ocr_chars 218 · stddev 64.1
       → recovered from app-switcher snapshot:
           "Card number  4242 4242 4242 4242"
           "Exp 04/29     CVV 311"
       → fix: add a privacy overlay when scenePhase becomes .inactive

[FAIL] Android · SSN entry (leaky)
       recents thumbnail not black · ocr_chars 96
       → recovered from recents thumbnail:
           "Social Security Number  517-04-8829"
       → fix: setRecentsScreenshotEnabled(false) / FLAG_SECURE in onWindowFocusChanged(false)

2 FAIL · 1 PASS  ›  evidence in ./report/
```

The recovered card number and SSN come straight out of the snapshot the OS wrote — that's the whole point. If the tool can read them off disk, so can anyone with the device or a backup.

---

## How to fix it

### iOS — cover the window before it's captured

Add a privacy overlay (a blur or your launch screen) when the scene resigns active. The snapshot is taken on the transition to `.inactive`, so you have to be covered *by then*, not after:

```swift
// SwiftUI
@Environment(\.scenePhase) private var scenePhase

.onChange(of: scenePhase) { phase in
    privacyOverlayVisible = (phase != .active)   // covers on .inactive AND .background
}
```

```swift
// UIKit
func applicationWillResignActive(_ application: UIApplication) {
    window?.addSubview(privacyOverlay)
}
```

### Android — set `FLAG_SECURE` early, not in `onPause()`

`onPause()` runs *after* the recents snapshot is captured, so the fix that "looks right" still leaks. Set the flag when the window loses focus, or disable the recents screenshot outright:

```kotlin
// API 33+ — cleanest
override fun onCreate(savedInstanceState: Bundle?) {
    super.onCreate(savedInstanceState)
    setRecentsScreenshotEnabled(false)
}

// or, works everywhere — set it before focus is lost
override fun onWindowFocusChanged(hasFocus: Boolean) {
    super.onWindowFocusChanged(hasFocus)
    if (!hasFocus) {
        window.setFlags(WindowManager.LayoutParams.FLAG_SECURE,
                        WindowManager.LayoutParams.FLAG_SECURE)
    }
}
```

Re-run `redaction-checker` after the fix — a passing screen produces a blank/black snapshot and an empty OCR result.

---

## Built With

- **[Revyl CLI](https://github.com/RevylAI/revyl-cli)** — Cloud device provisioning and AI-grounded mobile app interaction
- **[Claude Code](https://claude.ai/code)** — AI agent for code analysis and orchestration
- **[Claude Code Action](https://github.com/anthropics/claude-code-action)** — Run Claude in GitHub Actions
