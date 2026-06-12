---
name: redaction-checker
description: >
  Check that sensitive mobile screens (payment forms, SSN, banking, health data) are
  obscured in the iOS app switcher and Android recents thumbnail, so backgrounding the
  app does not leak them to a snapshot on disk. Use this skill when reviewing an iOS or
  Android app for the OWASP MASVS MSTG-STORAGE-9 / PCI control, when asked whether a
  screen leaks into the app switcher or recents, when preparing for a mobile pentest or
  compliance audit, or when fixing a "screen not obscured in the background" finding.
  Works on Swift, SwiftUI, UIKit, Kotlin, Java, React Native, and Expo apps.
---

# redaction-checker: app-switcher and recents leak scanner

You verify one compliance control: sensitive screens must be obscured when the app goes
to the background, so the snapshot the OS writes for the app switcher (iOS) or the recents
thumbnail (Android) does not contain readable secrets. Your job is to find the sensitive
screens, describe how to reach each one, run the checker, read the report, fix every FAIL,
and re-run until the app passes with no FAIL and no ERROR.

Background, so you know why this matters: when an app is backgrounded the OS screenshots
the current screen to render its multitasking preview, and writes that image to disk. If a
payment or identity screen is on top, the secrets land in a file that survives backgrounding.
Nothing in normal use shows this bug. The app looks fine. The leak only exists in that file.

## Step 0: Set up (only if the command is missing)

The tool runs as `python -m redaction_check`. Try it first. If the module is not found,
set it up once:

```bash
git clone https://github.com/ethanzhoucool/redaction-checker.git
cd redaction-checker
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
brew install tesseract            # OCR engine (macOS)
```

The default iOS path is the local simulator (`simctl`), which needs a Mac with Xcode and a
booted simulator but no account. The optional iOS Revyl tier and the Android path use the
Revyl cloud device, so they need the Revyl CLI and a logged-in account:
https://github.com/RevylAI/revyl-cli. Always run from the repo root with the venv active.

## Step 1: Find the sensitive screens

A screen is sensitive if the snapshot the OS persists would leak data that must not survive
backgrounding. Flag any screen that shows or accepts:

- Payment data: card number (PAN), expiry, CVV, cardholder name.
- Government or identity numbers: SSN, passport, driver's license, national ID.
- Banking: account number, routing number, full balance.
- Health (PHI), full date of birth, security answers, recovery codes, OTP seeds.

When in doubt, mark it sensitive. A PASS on a non-sensitive screen costs nothing. A missed
sensitive screen is the whole failure mode.

## Step 2: Describe how to reach each screen in `sensitive-screens.yml`

The tool runs locally with no Revyl account. Revyl's cloud devices are an optional tier:
opt-in for iOS (run without a Mac), and the primary path for Android.

iOS, primary, `backend: simctl` (local macOS sim). This is the default. Reach screens with a
`deeplink` or `launch_args`, set `app_path` to a simulator `.app`, and the tool backgrounds by
launching another app, then decodes the on-disk snapshot for crisp, quotable text.

```yaml
ios:
  backend: "simctl"
  bundle_id: com.example.app
  app_path: build/MyApp.app
  screens:
    - { name: "Add Card", launch_args: "leaky", sensitive: true }
```

iOS, optional cloud tier, `backend: revyl` (no Mac needed). Reach the screen with `nav` steps
(`kill`, `launch`, `tap [x,y]`, `instruction`, `deeplink`, `wait`) or a single
natural-language `instruction`. Always set `expect` to a short string visible on the active
screen. The runner OCRs the active frame and returns ERROR rather than a bogus verdict if
`expect` is missing, which is how it knows navigation actually landed where you intended. This
tier backgrounds by pulling Control Center and decides on an active-vs-inactive correlation,
so it gives a reliable PASS/FAIL but cannot quote the exact digits.

```yaml
ios:
  backend: "revyl"
  bundle_id: com.example.app
  revyl_app_id: "<your-revyl-app-id>"
  screens:
    - name: "Add Card"
      nav: [ { launch: true }, { wait: 2 }, { instruction: "open the add-card screen" } ]
      expect: "Card number"
      sensitive: true
```

Android, primary, `backend: revyl` (Revyl cloud device). Reach screens with a natural-language
`instruction` describing the destination, not the taps. The tool opens the recents overview
and judges that thumbnail (a live screenshot can read past `FLAG_SECURE`, so it is kept as
evidence only). A local-emulator `adb` route is the fallback.

```yaml
android:
  backend: "revyl"
  revyl_app_id: "<your-revyl-app-id>"
  package: com.example.app
  screens:
    - { name: "SSN entry", instruction: "open the SSN entry screen", sensitive: true }
```

## Step 3: Run the checker

```bash
python -m redaction_check sensitive-screens.yml
```

It drives the app to each screen, backgrounds it, recovers the snapshot, decides PASS/FAIL,
and writes `report.md`, `report.html`, and side-by-side evidence PNGs. When run interactively
it opens the HTML report at the end (`--no-open` to skip, `--open` to force). Use
`--platform ios` or `--platform android` to run just one side. A single FAIL exits non-zero,
so it gates CI.

## Step 4: Read the report and fix every FAIL

Each screen returns PASS, FAIL, or ERROR:

- PASS: the snapshot is blank or covered and no secrets were recovered. Correctly obscured.
- FAIL: a secret was recovered, or the backgrounded frame still tracks the live screen. Fix it.
- ERROR: the check could not complete (could not reach the screen, Control Center did not
  engage, no snapshot found, decode failed). Not a verdict. Fix the config or environment and
  re-run. Never report an ERROR as a PASS.

Fixes by platform:

- iOS: draw a privacy cover when the scene resigns active. The snapshot is taken on the
  transition to `.inactive`, so you must be covered by then, not after. In SwiftUI, watch
  `scenePhase` and show an overlay when `phase != .active`. In UIKit, add the overlay in
  `applicationWillResignActive`.
- Android: set `FLAG_SECURE` in `onWindowFocusChanged(false)`, or call
  `setRecentsScreenshotEnabled(false)` (API 33+). Do not set it in `onPause()`, which runs
  after the recents snapshot is already taken.

Fix the actual behavior, not just the presence of a cover. A FAIL means the leak is real.

## Step 5: Re-run until clean

Re-run after each fix and keep going until the report shows no FAIL and no ERROR. A clean run
is a blank or covered snapshot, an empty OCR result, and exit code 0.

## About

redaction-checker maps to OWASP MASVS MSTG-STORAGE-9 / PCI-MSTG. Built with the
[Revyl CLI](https://revyl.com) for cloud device control. Catch the leak before an auditor
or an attacker does.
