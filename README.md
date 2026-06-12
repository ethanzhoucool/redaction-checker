# redaction-checker

Catch sensitive screens that leak into the iOS app switcher and Android recents before an auditor or attacker does.

When your app goes to the background, the OS takes a snapshot of the current screen to render the app-switcher card (iOS) or recents thumbnail (Android). If the screen on top is a payment form, an SSN entry, or anything else sensitive, that snapshot gets written to disk in plaintext and shows up the next time someone opens the multitasking view. redaction-checker drives your app to its sensitive screens, backgrounds it, recovers the snapshot the OS actually wrote, and reports PASS or FAIL with the recovered text as evidence.

> Runs locally, no account needed. Revyl's cloud devices are an optional tier: opt-in for iOS so you can check without a Mac, and the primary path for Android. The iOS checks never require Revyl.

---

## Why most apps fail

This maps to a real compliance control:

> OWASP MASVS MSTG-STORAGE-9 / PCI-MSTG: sensitive data must be removed from views when the app is moved to the background.

It is one of the most commonly failed items in a mobile pentest, because nothing in the normal dev loop surfaces it. The app looks fine. The screen renders correctly. The leak only exists in a file the OS writes on your behalf when the app resigns active, a file you never see unless you go looking for it. So the bug ships, and the first time anyone notices is during an audit or a breach writeup.

The two classic root-cause bugs this tool catches:

- Android: `FLAG_SECURE` set too late. Devs set it in `onPause()`. By then the recents snapshot has already been taken, so the screen leaks anyway.
- iOS: no privacy overlay on resign. Devs forget to cover the window when the scene goes `.inactive` (`scenePhase`) or on `applicationWillResignActive`. The live payment form gets captured verbatim.

Both render identically in normal use. Only the snapshot tells the truth.

---

## How it works

A redacted screen produces a blank or obscured snapshot. A leaky screen produces a readable one. The whole tool is built around making that difference machine-checkable.

The core tool runs locally with no Revyl account. Revyl's cloud devices are an optional tier you turn on per platform: opt-in for iOS, so you can run without a Mac, and the primary path for Android, where there is no practical local option. You never need a Revyl account to check iOS.

### iOS: local simulator first (primary), Revyl cloud optional

Local simulator (macOS), `backend: simctl`. This is the default and the recommended path. It needs a Mac with Xcode and a simulator build of the app, but no account, and it recovers the leaked text crisply so you can quote the exact card number. iOS persists the app-switcher card as an Apple `AAPL` container with a misleading `.ktx` extension. We reverse it end to end, with no external binaries:

```
SplashBoard/Snapshots/<scene-with-bundle-id>/*.ktx
        |
        |  AAPL header                  (find_snapshots -> read_header)
        v
   LZFSE-compressed payload             (libcompression via ctypes)
        |
        v
   raw ASTC 4x4 texture                 (texture2ddecoder)
        |
        v
        PNG  -->  OCR  -->  verdict      (Tesseract + secret regex)
```

The compressed size alone is most of the signal: a blank or redacted snapshot LZFSE-crushes to about 2 KB, while a real leak is 50 KB or more and the text comes back OCR-readable.

Revyl cloud device (optional tier), `backend: revyl`. Turn this on when you do not have a Mac. It runs on a cloud device, so it needs a Revyl account but no Xcode. The iOS app switcher cannot be opened through the CLI's synthetic touches: the gesture is a swipe-up-and-hold, which `swipe`/`drag` cannot express, and it is a SpringBoard-level system gesture that WebDriverAgent does not reach. So instead of opening the switcher, we trigger the same OS event another way: pulling Control Center makes the app resign active (`scenePhase != .active`), the exact transition the OS uses when it writes the app-switcher snapshot. A correctly built app draws its privacy cover on that transition; a leaky one keeps rendering its content. We screenshot the screen active, pull Control Center, screenshot it inactive, and compare.

Control Center dims and blurs the backdrop uniformly, which defeats brightness, OCR, and absolute pixel-diff. So the verdict uses a zero-mean normalized cross-correlation (ZNCC) between the active and inactive frames. ZNCC is invariant to global dim/blur and keys only on layout:

```
active frame  x  inactive frame  -->  corr
   corr high  ->  inactive still looks like the live screen  ->  not obscured  ->  FAIL
   corr low   ->  content was replaced by a cover            ->  PASS
```

Measured on the fixture: leaky around 0.88, redacted around 0.05. The tradeoff is that Control Center's blur means this tier gives a reliable PASS/FAIL but cannot quote the exact leaked digits. The local backend above does.

### Android: Revyl cloud device (primary)

For Android the Revyl cloud device is the primary path, with a local-emulator `adb` route as the fallback. A window with `FLAG_SECURE` (or, on API 33+, `setRecentsScreenshotEnabled(false)`) makes the recents thumbnail come back black. One nuance learned on the cloud devices: a `revyl device screenshot` of the live secured screen reads straight past `FLAG_SECURE` and captures the content. So the live screen is kept as evidence only and never judged. The verdict is taken from the recents thumbnail, which the OS itself blanks. We drive to the screen, open the recents overview, and check whether that thumbnail went dark.

```
drive to screen --> live screenshot (evidence only)
        |
        v
open recents --> recents thumbnail   (Revyl cloud device primary; adb fallback for a local emulator)
        |
        v
  black? --> PASS        readable? --> OCR --> secret regex --> FAIL
```

### Shared verdict engine

Both platforms feed one engine: OCR, secret-regex (SSN / PAN / CVV), and blank/blur/compressed-size heuristics, producing PASS or FAIL with side-by-side evidence images and a markdown/HTML report.

| Stage | iOS (local simctl, default) | Android (Revyl cloud, primary) |
|---|---|---|
| Drive to screen | `deeplink` / `launch_args` | `revyl device instruction` (natural language) |
| Make it inactive | launch another app | open the recents overview |
| Capture | decode the on-disk AAPL snapshot | recents thumbnail |
| Decide | OCR + regex + compressed size | OCR + regex + blackness |

The optional iOS Revyl tier (`backend: revyl`) instead reaches screens via `nav` steps or an `instruction`, backgrounds by pulling Control Center, and decides on the active-vs-inactive correlation (ZNCC), so it needs no Mac.

---

## Install

```bash
# from the repo root
python3 -m venv .venv
source .venv/bin/activate
pip install pillow numpy pytesseract texture2ddecoder pyyaml

# OCR engine (macOS)
brew install tesseract

# Optional, only for the Revyl cloud tier (iOS without a Mac, and Android):
# Revyl CLI, https://github.com/RevylAI/revyl-cli
```

The default iOS backend (`simctl`) is macOS only: it reads from `~/Library/Developer/CoreSimulator/Devices` and decodes LZFSE via the system `libcompression.dylib` (no Xcode command-line decoder needed). The optional iOS Revyl tier and the Android path use the Revyl CLI instead and run anywhere it does, with no Mac required.

---

## Usage

Point the tool at a target by describing its sensitive screens in `sensitive-screens.yml`, then run the checker:

```bash
source .venv/bin/activate
python -m redaction_check sensitive-screens.yml
```

For each sensitive screen the tool will drive the app to it, background it, recover the snapshot, run the verdict engine, and write `report.md` plus evidence PNGs. When run interactively it also opens the HTML report at the end (pass `--no-open` to skip, or `--open` to force it). A single FAIL exits non-zero, so it drops straight into CI (template under `.github/workflows/`).

A minimal config:

```yaml
ios:
  backend: "simctl"           # "simctl" (local macOS sim, default) or "revyl" (cloud tier, no Mac)
  bundle_id: com.revyl.redactiondemo
  app_path: build/Cashly.app  # the simulator build to install and check
  screens:
    # simctl backend reaches the screen via `deeplink` or `launch_args`:
    - { name: "Add Card", launch_args: "leaky", sensitive: true }
    # the optional revyl tier instead uses `nav` steps (or an `instruction`) plus an `expect`.

android:
  backend: "revyl"            # Revyl cloud device is the primary path for Android
  revyl_app_id: "<your-revyl-app-id>"
  package: com.revyl.redactiondemo
  screens:
    - { name: "SSN entry", instruction: "open the SSN entry screen", sensitive: true }
```

See `sensitive-screens.yml` for the full shape (custom `secrets` regexes, `background_via`, and so on) and `CLAUDE.md` for how to point Claude Code at a new app.

---

## Sample report

```
redaction-checker, MSTG-STORAGE-9 / PCI-MSTG
target: com.revyl.redactiondemo

[PASS] iOS, Add Card (redacted)
       snapshot 1.9 KB, ocr_chars 0, stddev 0.4
       app-switcher card is blank; no sensitive text recovered

[FAIL] iOS, Add Card (leaky)
       snapshot 71.3 KB, ocr_chars 218, stddev 64.1
       recovered from app-switcher snapshot:
           "Card number  4242 4242 4242 4242"
           "Exp 04/29     CVV 311"
       fix: add a privacy overlay when scenePhase becomes .inactive

[FAIL] Android, SSN entry (leaky)
       recents thumbnail not black, ocr_chars 96
       recovered from recents thumbnail:
           "Social Security Number  517-04-8829"
       fix: setRecentsScreenshotEnabled(false) / FLAG_SECURE in onWindowFocusChanged(false)

2 FAIL, 1 PASS, evidence in ./report/
```

The recovered card number and SSN come straight out of the snapshot the OS wrote. That is the whole point. If the tool can read them off disk, so can anyone with the device or a backup.

---

## How to fix it

### iOS: cover the window before it is captured

Add a privacy overlay (a blur or your launch screen) when the scene resigns active. The snapshot is taken on the transition to `.inactive`, so you have to be covered by then, not after:

```swift
// SwiftUI
@Environment(\.scenePhase) private var scenePhase

.onChange(of: scenePhase) { phase in
    privacyOverlayVisible = (phase != .active)   // covers on .inactive and .background
}
```

```swift
// UIKit
func applicationWillResignActive(_ application: UIApplication) {
    window?.addSubview(privacyOverlay)
}
```

### Android: set `FLAG_SECURE` early, not in `onPause()`

`onPause()` runs after the recents snapshot is captured, so the fix that "looks right" still leaks. Set the flag when the window loses focus, or disable the recents screenshot outright:

```kotlin
// API 33+, cleanest
override fun onCreate(savedInstanceState: Bundle?) {
    super.onCreate(savedInstanceState)
    setRecentsScreenshotEnabled(false)
}

// or, works everywhere, set it before focus is lost
override fun onWindowFocusChanged(hasFocus: Boolean) {
    super.onWindowFocusChanged(hasFocus)
    if (!hasFocus) {
        window.setFlags(WindowManager.LayoutParams.FLAG_SECURE,
                        WindowManager.LayoutParams.FLAG_SECURE)
    }
}
```

Re-run redaction-checker after the fix. A passing screen produces a blank or black snapshot and an empty OCR result.

---

## Built With

- [Revyl CLI](https://github.com/RevylAI/revyl-cli): cloud device provisioning and AI-grounded mobile app interaction
- [Claude Code](https://claude.ai/code): AI agent for code analysis and orchestration
- [Claude Code Action](https://github.com/anthropics/claude-code-action): run Claude in GitHub Actions
