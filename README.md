# redaction-checker

Catch sensitive screens that leak into the iOS app switcher and Android recents before an auditor or attacker does.

When your app goes to the background, the OS takes a snapshot of the current screen to render the app-switcher card (iOS) or recents thumbnail (Android). If the screen on top is a payment form, an SSN entry, or anything else sensitive, that snapshot gets written to disk in plaintext and shows up the next time someone opens the multitasking view. redaction-checker drives your app to its sensitive screens, backgrounds it, recovers the snapshot the OS actually wrote, and reports PASS or FAIL with the recovered text as evidence.

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

### iOS: two backends

Revyl cloud device (default, no Xcode or Mac needed), `backend: revyl`.
The iOS app switcher cannot be opened through the CLI's synthetic touches. The gesture is a swipe-up-and-hold, which `swipe`/`drag` cannot express, and it is a SpringBoard-level system gesture that WebDriverAgent does not reach. So instead of opening the switcher, we trigger the same OS event another way: pulling Control Center makes the app resign active (`scenePhase != .active`), the exact transition the OS uses when it writes the app-switcher snapshot. A correctly built app draws its privacy cover on that transition; a leaky one keeps rendering its content. We screenshot the screen active, pull Control Center, screenshot it inactive, and compare.

Control Center dims and blurs the backdrop uniformly, which defeats brightness, OCR, and absolute pixel-diff. So the verdict uses a zero-mean normalized cross-correlation (ZNCC) between the active and inactive frames. ZNCC is invariant to global dim/blur and keys only on layout:

```
active frame  x  inactive frame  -->  corr
   corr high  ->  inactive still looks like the live screen  ->  not obscured  ->  FAIL
   corr low   ->  content was replaced by a cover            ->  PASS
```

Measured on the fixture: leaky around 0.88, redacted around 0.05. The blur means this backend gives a reliable PASS/FAIL but cannot quote the exact leaked digits. Use the local backend below for that.

Local simulator (macOS), `backend: simctl`.
For a crisp, unblurred recovery, so you can quote the leaked card number verbatim, decode the snapshot the OS wrote to disk. iOS persists the app-switcher card as an Apple `AAPL` container with a misleading `.ktx` extension. We reverse it end to end, with no external binaries:

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

### Android: read the recents thumbnail, which the OS blanks

A window with `FLAG_SECURE` (or, on API 33+, `setRecentsScreenshotEnabled(false)`) makes the recents thumbnail come back black. One nuance learned on Revyl's cloud devices: a `revyl device screenshot` of the live secured screen reads straight past `FLAG_SECURE` and captures the content. So the live screen is kept as evidence only and never judged. The verdict is taken from the recents thumbnail, which the OS itself blanks. We drive to the screen, open the recents overview, and check whether that thumbnail went dark.

```
drive to screen --> live screenshot (evidence only)
        |
        v
open recents --> recents thumbnail   (cloud device primary; adb fallback for a local emulator)
        |
        v
  black? --> PASS        readable? --> OCR --> secret regex --> FAIL
```

Primary capture backend is Revyl (`revyl device`). A local-emulator `adb` path is the fallback.

### Shared verdict engine

Both platforms feed one engine: OCR, secret-regex (SSN / PAN / CVV), and blank/blur/compressed-size heuristics, producing PASS or FAIL with side-by-side evidence images and a markdown/HTML report.

| Stage | iOS (Revyl, default) | Android (Revyl) |
|---|---|---|
| Drive to screen | `nav` steps / `instruction` | `revyl device instruction` (natural language) |
| Make it inactive | pull Control Center | open the recents overview |
| Capture | screenshot active + inactive | recents thumbnail |
| Decide | active vs inactive correlation (ZNCC) | OCR + regex + blackness |

The local iOS backend (`simctl`) instead reaches screens via `deeplink`/`launch_args`, backgrounds by launching another app, decodes the AAPL snapshot from disk, and decides on OCR + regex + compressed size.

---

## Install

```bash
# from the repo root
python3 -m venv .venv
source .venv/bin/activate
pip install pillow numpy pytesseract texture2ddecoder pyyaml

# OCR engine (macOS)
brew install tesseract

# Revyl CLI (cloud capture backend)
# https://github.com/RevylAI/revyl-cli
```

The default iOS backend (`revyl`) runs anywhere the Revyl CLI does, with no Mac or Xcode required. The local iOS backend (`simctl`) is macOS only: it reads from `~/Library/Developer/CoreSimulator/Devices` and decodes LZFSE via the system `libcompression.dylib` (no Xcode command-line decoder needed).

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
  backend: "revyl"            # "revyl" (cloud device, default) or "simctl" (local macOS sim)
  bundle_id: com.revyl.redactiondemo
  revyl_app_id: "<your-revyl-app-id>"
  screens:
    # revyl backend reaches the screen via `nav` (or a single `instruction`):
    - name: "Add Card"
      nav: [ { launch: true }, { wait: 2 }, { instruction: "open the add-card screen" } ]
      expect: "Card number"   # text that must be on the active screen, confirms nav actually got there
      sensitive: true
    # simctl backend instead uses `deeplink` or `launch_args`.

android:
  backend: "revyl"
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
