# CLAUDE.md — pointing redaction-checker at a target app

This tool checks one compliance control: **OWASP MASVS MSTG-STORAGE-9 / PCI-MSTG** —
sensitive screens must be obscured in the iOS app switcher and the Android recents
thumbnail. Your job when orchestrating it is to (1) identify the sensitive screens,
(2) describe how to reach each one in `sensitive-screens.yml`, (3) run the checker,
and (4) interpret the verdict for the user.

## What counts as a "sensitive screen"

A screen is sensitive if the snapshot the OS persists to disk would leak data that
must not survive backgrounding. Flag a screen if it shows or accepts:

- Payment data — card number (PAN), expiry, CVV, cardholder name.
- Government / identity numbers — SSN, passport, driver's license, national ID.
- Banking — account number, routing number, full balance.
- Health (PHI), full date of birth, security answers, recovery codes, OTP seeds.

When in doubt, mark `sensitive: true`. A `PASS` on a non-sensitive screen costs nothing;
a missed sensitive screen is the whole failure mode.

## How to drive to each screen

The two platforms reach screens differently — match the config field to the platform.
First pick the iOS backend with `ios.backend`: **`revyl`** (cloud device, the default —
no Mac needed; backgrounds via Control Center and decides on an active↔inactive
correlation) or **`simctl`** (local macOS simulator; decodes the on-disk AAPL snapshot
for crisp text recovery).

**iOS (`revyl` backend) — `nav` steps or an `instruction`.** There are no deep links on
the cloud sim (the app's URL scheme usually isn't registered), and the app switcher
itself is unreachable, so reach the screen with a `nav` list of steps —
`kill` / `launch` / `tap [x,y]` / `instruction` / `deeplink` / `wait` — or a single
natural-language `instruction` (which cold-launches then grounds it). Prefer
`instruction` for real apps; use coordinate `tap` only when grounding is unreliable.
Always set `expect:` to a short string that's visible on the *active* screen — the
runner OCRs the active frame and ERRORs (rather than emitting a bogus verdict) if it's
missing, which is how it knows navigation actually landed where you intended.

```yaml
screens:
  - name: "Add Card"
    nav: [ { launch: true }, { wait: 2 }, { instruction: "open the add-card screen" } ]
    expect: "Card number"   # confirms the active screen really is the one you meant to test
    sensitive: true
```

The `revyl` iOS verdict is deliberately conservative: it only returns PASS with positive
evidence (right screen reached, Control Center engaged, content replaced by a flat cover)
and FAIL when the backgrounded frame still tracks the live screen. Anything ambiguous
(CC didn't open, captured Control Center chrome, mid-range correlation) is `ERROR`, not a
silent pass — re-run those rather than trusting them.

**iOS (`simctl` backend) — deeplinks.** Reliable and fast on a local sim. Find the URL
scheme in the app's `Info.plist` (`CFBundleURLSchemes`) or routing code and give each
screen a `deeplink` (or `launch_args`). The tool launches the app there, then backgrounds
it via `background_via` (default `launch_other` — launch another app to force the snapshot).

```yaml
screens:
  - { name: "Add Card", deeplink: "redactiondemo://payment/leaky", sensitive: true }
```

**Android — natural language via Revyl.** Reach screens with `revyl device instruction`
by describing the destination. Keep instructions short, imperative, and about the
*destination*, not the taps ("open the SSN entry screen", not "tap the third tab then
the gear icon"). Revyl grounds the instruction against the live UI. After arriving,
the tool presses Home to trigger the recents snapshot, then captures it via
`revyl device screenshot` (or `adb` for a local emulator).

```yaml
screens:
  - { name: "SSN entry", instruction: "open the SSN entry screen", sensitive: true }
```

## sensitive-screens.yml structure

```yaml
ios:
  backend: "revyl"                        # "revyl" (cloud device, default) or "simctl" (local macOS sim)
  bundle_id: com.revyl.redactiondemo      # simctl: locates the on-disk SplashBoard snapshot
  revyl_app_id: "<your-revyl-app-id>"     # revyl backend
  udid: "booted"                          # simctl only: simulator UDID, or "booted"
  app_path: fixtures/ios/build/App.app    # simctl only: install if not present
  background_via: "launch_other"          # simctl only: how to force the OS to snapshot
  screens:
    # revyl backend: nav steps or an instruction; simctl backend: deeplink or launch_args
    - { name: "...", nav: [ { launch: true }, { wait: 2 }, { instruction: "open ..." } ], sensitive: true }

android:
  backend: "revyl"                        # "revyl" (cloud) or "adb" (local emulator)
  revyl_app_id: "<your-revyl-app-id>"     # required when backend: revyl
  package: com.revyl.redactiondemo
  screens:
    - { name: "...", instruction: "open the ... screen", sensitive: true }

secrets:                                  # regexes that mean "this snapshot leaked"
  - "\\b\\d{3}-\\d{2}-\\d{4}\\b"          # SSN
  - "\\b(?:\\d[ -]?){13,19}\\b"           # PAN / card number
```

`secrets` is optional — sensible defaults (SSN, PAN, CVV, SSN/routing keywords) live in
`redaction_check/contract.py` (`DEFAULT_SECRET_PATTERNS`). Add app-specific patterns
when a screen shows something the defaults won't match (e.g. a member ID format).

## How the verdict is decided

Each screen yields a `ScreenResult` with a `Verdict` (`PASS` / `FAIL` / `ERROR`).
The engine combines three signals — you should reason about them in this order:

1. **Recovered text.** OCR the decoded snapshot, run the `secrets` regexes over it.
   Any match → `FAIL`, with the matched strings attached as `leaked_text`. This is the
   strongest signal and the one to quote to the user.
2. **Blank / black heuristic.** A redacted iOS card or a `FLAG_SECURE` Android frame
   has near-zero pixel variance (`pixel_stddev` ~0) — strong evidence of `PASS`.
3. **Compressed size (iOS).** A blank snapshot LZFSE-compresses to ~2 KB; a leak is
   50 KB+. `compressed_bytes` is a cheap pre-OCR signal and a good sanity check.

Interpreting outcomes:

- **`PASS`** — snapshot is blank/black, no secrets recovered. The screen is correctly obscured.
- **`FAIL`** — readable snapshot and/or a secret regex hit. Report the `leaked_text`
  and point the user at the fix: iOS → privacy overlay on `scenePhase == .inactive`
  (cover *before* `.inactive`, the snapshot is taken on that transition); Android →
  `setRecentsScreenshotEnabled(false)` or `FLAG_SECURE` in `onWindowFocusChanged(false)`
  — **not** in `onPause()`, which runs after the snapshot is already taken.
- **`ERROR`** — couldn't drive to the screen, no snapshot found, or decode failed.
  Not a compliance verdict; fix the config (wrong deeplink, wrong `bundle_id`, app not
  installed, no Revyl device) and re-run. Don't report `ERROR` as a `PASS`.

## Orchestration checklist

1. Identify sensitive screens in the target (see criteria above).
2. Find deeplinks (iOS) / phrase instructions (Android); fill in `sensitive-screens.yml`.
3. Confirm the iOS sim is booted with the app installed, and a Revyl device/app is set.
4. `python -m redaction_check sensitive-screens.yml`.
5. Read `report.md` + evidence PNGs. For every `FAIL`, quote the recovered text and the
   matching platform fix. A clean run is "blank snapshot, empty OCR, exit 0".
