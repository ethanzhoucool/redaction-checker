# Cashly — iOS redaction-checker fixture

Cashly (bundle id `com.revyl.redactiondemo`) is a single-file SwiftUI mock payments app used as a
test fixture for the redaction-checker tool. It has two payment screens showing fake sensitive data
(card number, CVV, SSN, date of birth): a **leaky** screen that does NOT obscure itself when the app
is backgrounded — so its app-switcher snapshot leaks the data (the tool should report a **FAIL**) —
and a **redacted** screen that paints an opaque `PrivacyCover` whenever the scene is not active —
so its snapshot is blank (the tool should report a **PASS**). The screen is selected at launch via a
`simctl` launch argument (`leaky` / `redacted`) or a deep link containing those words.

## Build (simulator .app)

```sh
export DEVELOPER_DIR="/Volumes/Xcode/Xcode-26.4.1.app/Contents/Developer"
cd fixtures/ios
xcodebuild -project Cashly.xcodeproj -scheme Cashly -configuration Debug \
  -sdk iphonesimulator -derivedDataPath build CODE_SIGNING_ALLOWED=NO build
# Product: build/Build/Products/Debug-iphonesimulator/Cashly.app
```

## Run / route

```sh
xcrun simctl boot "iPhone 17 Pro"
xcrun simctl install booted build/Build/Products/Debug-iphonesimulator/Cashly.app
xcrun simctl launch booted com.revyl.redactiondemo leaky      # leaky payment screen
xcrun simctl launch booted com.revyl.redactiondemo redacted   # redacted payment screen
# (no arg) -> home screen with buttons to either route
```
