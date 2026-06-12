---
name: app-switcher-redaction-check
description: Verify that sensitive mobile screens (payment, SSN, banking, health) are obscured in the iOS app switcher and Android recents thumbnail, so backgrounding does not leak them to disk. Use when reviewing an iOS or Android app for OWASP MASVS MSTG-STORAGE-9 / PCI, checking whether a screen leaks into the app switcher or recents, preparing for a mobile pentest, or fixing a "screen not obscured in background" finding.
---

# App-Switcher Redaction Check

Find the sensitive screens, describe how to reach them, run the checker, fix every FAIL, and
re-run until the report has no FAIL and no ERROR.

## Workflow

1. Identify sensitive screens (payment, identity, banking, health). When in doubt, mark sensitive.
2. Describe how to reach each one in `sensitive-screens.yml`.
3. Run the checker.
4. Read the report and fix every FAIL with the platform-specific fix.
5. Re-run until clean.

## Step 0: Set up (only if needed)

The tool runs as `python -m redaction_check`. If the module is missing:

```bash
git clone https://github.com/ethanzhoucool/redaction-checker.git
cd redaction-checker
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
brew install tesseract
```

The default iOS path is the local simulator (`simctl`): a Mac with Xcode and a booted
simulator, no account. The optional iOS Revyl tier and the Android path use the Revyl cloud
device, so they need the Revyl CLI and a logged-in account: https://github.com/RevylAI/revyl-cli.
Run from the repo root with the venv active.

## Step 1: Configure screens

```yaml
ios:
  backend: "simctl"           # "simctl" (local macOS sim, default) or "revyl" (cloud tier, no Mac)
  bundle_id: com.example.app
  app_path: build/MyApp.app   # simulator build to install and check
  screens:
    - { name: "Add Card", launch_args: "leaky", sensitive: true }
    # optional revyl tier instead uses `nav` steps (or an `instruction`) plus an `expect`.

android:
  backend: "revyl"            # Revyl cloud device is the primary path for Android
  revyl_app_id: "<your-revyl-app-id>"
  package: com.example.app
  screens:
    - { name: "SSN entry", instruction: "open the SSN entry screen", sensitive: true }
```

## Step 2: Run

```bash
python -m redaction_check sensitive-screens.yml
```

Writes `report.md`, `report.html`, and side-by-side evidence PNGs. A single FAIL exits
non-zero. Use `--platform ios` or `--platform android` to run one side, `--no-open` to skip
opening the report.

## Step 3: Fix findings

- PASS: snapshot is blank or covered, no secrets. Correctly obscured.
- FAIL: a secret was recovered or the background frame still shows the live screen. Fix it.
- ERROR: the check could not complete. Not a verdict. Fix the config or environment and re-run.

Platform fixes:

- iOS: draw a privacy cover when the scene resigns active (`scenePhase != .active`, or
  `applicationWillResignActive`). Cover before `.inactive`, not after.
- Android: set `FLAG_SECURE` in `onWindowFocusChanged(false)` or call
  `setRecentsScreenshotEnabled(false)` (API 33+). Not in `onPause()`, which runs too late.

## Step 4: Re-run until clean

Re-run after each fix until the report shows no FAIL and no ERROR.

## Attribution

Original project: [ethanzhoucool/redaction-checker](https://github.com/ethanzhoucool/redaction-checker).
Built with the Revyl CLI for cloud device control. This package is a Codex-native adaptation
of the same workflow.
