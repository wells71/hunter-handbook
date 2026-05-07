---
icon: lucide/smartphone
tags:
  - mobile
  - android
  - ios
  - apk
  - frida
  - bug-bounty
description: Mobile app testing is backend testing with a decompilation step — the app exposes endpoints, secrets, and auth flows that never surface through the web interface.
---

# Mobile Application Programs

Mobile programs are some of the highest-signal targets in bug bounty. The app itself is rarely the vulnerability — it's the map to an API surface that's underdocumented, under-tested, and often running with fewer restrictions than the web equivalent. Decompile the app, extract the endpoints and secrets, then apply the same techniques from Parts 2–7 against a backend that wasn't designed to be found this way.

<div class="grid cards" markdown>

-   :simple-android:{ .lg .middle } __Android__

    ---

    APK acquisition, decompilation with JADX, manifest analysis, Frida-based SSL bypass, and local storage inspection.

    [:octicons-arrow-right-24: Android testing](#android)

-   :simple-apple:{ .lg .middle } __iOS__

    ---

    IPA extraction, binary analysis, Objection-based dynamic analysis, keychain dumping, and URL scheme testing.

    [:octicons-arrow-right-24: iOS testing](#ios)

-   :material-api:{ .lg .middle } __Common Findings__

    ---

    OWASP Mobile Top 10 field reference, mobile API backend testing, and Firebase key abuse.

    [:octicons-arrow-right-24: Common findings](#common-mobile-findings)

</div>

## Decision Flow

```
Have the APK/IPA and haven't started?
→ Run MobSF first for a full automated report, then do targeted manual analysis.
→ Decompile with JADX (Android) or extract strings/headers (iOS) and hunt secrets before touching traffic.

Need to intercept traffic but SSL pinning is blocking Burp?
→ Android: try apk-mitm first (no root needed), then Frida + Objection if pinning survives patching.
→ iOS: Objection patchipa (no jailbreak), or SSL Kill Switch 2 on a jailbroken device.

Found API endpoints in intercepted traffic?
→ Map them all — mobile apps routinely expose endpoints absent from web documentation.
→ Test every endpoint with IDOR, mass assignment, and auth bypass techniques from Parts 2–7.

Found hardcoded keys or google-services.json?
→ Test Firebase api_key for open registration, Firestore access, and Auth email enumeration.
→ Test any AWS key with sts get-caller-identity (read-only only — see Part 9).

AndroidManifest shows exported components?
→ Launch exported activities directly via adb to test for authentication bypass.
→ Query exported content providers and test deep link parameter injection.

App accesses local storage (SharedPrefs, Keychain, SQLite)?
→ Use Objection to dump storage contents without modifying the app.
→ Tokens or credentials in plaintext storage = M9 finding, often High severity.
```

---

## Android

### APK Acquisition

**When to use:** Before any other step — you need the APK before static or dynamic analysis.

```bash title="apk_acquisition.sh"
# Method 1: APKPure or APKMirror (no device needed)
# https://apkpure.com/search?q=target-app
# https://apkmirror.com/

# Method 2: From a connected Android device
adb shell pm list packages | grep -i target   # find package name
adb shell pm path com.target.app              # get APK path
adb pull /data/app/com.target.app-1.apk ./target.apk

# Method 3: Google Play via apkeep
apkeep -a com.target.app ./

# Method 4: From a running emulator
# Install from Play Store, then use adb pull (same as Method 2)
```

---

### Static Analysis

**When to use:** Immediately after acquiring the APK, before setting up a proxy.

Decompilation reveals hardcoded secrets, internal API endpoints, and auth logic that never appears in traffic. Start here — JADX output feeds every subsequent test.

```bash title="apk_decompile.sh"
# APKTool: decodes resources, manifest, and smali
apktool d target.apk -o target_decoded/

# JADX: decompiles to readable Java (preferred for code review)
jadx target.apk -d target_jadx/
jadx-gui target.apk    # GUI for visual browsing
```

```bash title="apk_secret_hunt.sh"
# Hardcoded secrets in Java source:
grep -rE "(api_key|apikey|secret|password|token|key)" \
  target_jadx/sources/ | grep -v "//.*" | head -50

# AWS keys:
grep -rE "AKIA[0-9A-Z]{16}" target_jadx/sources/

# Internal URLs and endpoints:
grep -rE "https?://[a-zA-Z0-9._/-]+" target_jadx/sources/ | \
  grep -v "//.*" | sort -u

# Firebase config:
grep -rE "(firebaseio\.com|firebase\.google\.com|google-services)" \
  target_jadx/sources/

# Certificate pinning implementation:
grep -rE "(CertificatePinner|TrustManager|X509|checkServerTrusted|pin)" \
  target_jadx/sources/

# Resources and assets:
grep -rE "(api_key|secret|token|password|key|url)" \
  target_decoded/res/values/
find target_decoded/assets/ -type f | xargs grep -lE "(key|secret|password)"
cat target_decoded/assets/config.json

# Native libraries:
strings target_decoded/lib/arm64-v8a/libnative.so | \
  grep -iE "(key|secret|token|password|http)"

# trufflehog across all decompiled output:
trufflehog filesystem target_jadx/ --json > mobile_secrets.json
```

```bash title="mobsf_scan.sh"
# MobSF automated static analysis:
docker run -it --rm -p 8000:8000 \
  opensecurity/mobile-security-framework-mobsf
# Upload APK at http://localhost:8000
# Review: hardcoded secrets, exported components, dangerous permissions,
#         certificate pinning presence, Firebase/API keys
```

---

### AndroidManifest Analysis

**When to use:** Immediately after APKTool decode — the manifest defines the app's entire security posture.

```bash title="manifest_exported_components.sh"
# List all exported activities (launchable by any app or intent):
adb shell dumpsys package com.target.app | grep -i "activity" | grep "exported=true"

# Launch exported activity directly — tests for auth bypass:
adb shell am start \
  -n com.target.app/.AdminActivity \
  -e "user_id" "1" \
  --ez "bypass_auth" true

# Query exported content provider:
adb shell content query \
  --uri content://com.target.app.provider/users

# Trigger exported broadcast receiver:
adb shell am broadcast \
  -a com.target.app.ACTION_LOGIN \
  -n com.target.app/.LoginReceiver

# Dump app backup (if allowBackup="true"):
adb backup -noapk com.target.app
# Extracts: databases, shared preferences, files — no root required
```

| Flag | Risk |
|---|---|
| `android:exported="true"` (no permission) | Any app can launch the component |
| `android:debuggable="true"` | Attach debugger without root |
| `android:allowBackup="true"` | Full data backup via adb |
| Custom URL scheme without validation | Deep link injection |
| Exported `ContentProvider` | Unauthenticated data access |

!!! tip
    Check for exported `ContentProvider` components specifically — they're often overlooked and can expose the full user database via a single `adb shell content query` command.

---

### SSL Pinning Bypass

**When to use:** Burp traffic interception fails or returns SSL errors — the app is rejecting your CA certificate.

=== "apk-mitm (no root)"

    ```bash title="apkmitm_bypass.sh"
    # Install:
    npm install -g apk-mitm

    # Patch APK (disables pinning + trusts user certs):
    apk-mitm target.apk
    # Output: target-patched.apk

    adb install target-patched.apk
    # All traffic now visible in Burp
    ```

=== "Frida + Objection (rooted)"

    ```bash title="frida_ssl_bypass.sh"
    # Push Frida server to device:
    adb push frida-server /data/local/tmp/
    adb shell chmod 755 /data/local/tmp/frida-server
    adb shell /data/local/tmp/frida-server &

    # Universal SSL bypass via codeshare:
    frida -U -f com.target.app \
      --codeshare pcipolloni/universal-android-ssl-pinning-bypass-with-frida

    # Or via Objection shell:
    objection -g com.target.app explore
    # Inside shell:
    android sslpinning disable
    android root disable
    ```

!!! info
    `apk-mitm` covers most cases without requiring root. If pinning survives patching — the app is likely using certificate transparency or a custom `TrustManager` — move to Frida.

---

### Dynamic Analysis with Objection

**When to use:** After SSL bypass is confirmed and traffic is flowing through Burp — use Objection to explore runtime state.

```bash title="objection_exploration.sh"
objection -g com.target.app explore

# Inside Objection shell:
android hooking list classes
android hooking list class_methods com.target.security.PinningManager
android hooking watch class_method com.target.auth.TokenManager.getToken \
  --dump-return
env    # shows all app data directories
android filesystem ls /data/data/com.target.app/
android filesystem download \
  /data/data/com.target.app/shared_prefs/user.xml
```

---

### Exported Components and Deep Link Abuse

**When to use:** Manifest reveals custom URL schemes or exported components that accept external parameters.

```bash title="deeplink_testing.sh"
# Find all URL schemes and paths from manifest:
grep -r "android:scheme" target_decoded/AndroidManifest.xml
grep -rA5 "intent-filter" target_decoded/AndroidManifest.xml | \
  grep -E "scheme|host|path"

# Test deep link parameter injection:
adb shell am start -a android.intent.action.VIEW \
  -d "targetapp://login?token=test&redirect=https://evil.com"
adb shell am start -d "targetapp://reset?token=../../admin"
adb shell am start -d "targetapp://open?url=javascript:alert(1)"
adb shell am start -d "targetapp://auth?redirect=https://evil.com"

# Check for WebView JavaScript interface (native bridge):
grep -rn "addJavascriptInterface" target_jadx/sources/
# If found: JS injected via deep link or URL param can call native Android methods
```

---

### Insecure Local Storage

**When to use:** After gaining adb access to a debug build, emulator, or rooted device.

```bash title="local_storage_inspection.sh"
# SharedPreferences (auth tokens, session data):
adb shell run-as com.target.app cat \
  /data/data/com.target.app/shared_prefs/user_prefs.xml

# SQLite databases:
adb shell run-as com.target.app ls \
  /data/data/com.target.app/databases/
adb shell run-as com.target.app \
  sqlite3 /data/data/com.target.app/databases/app.db \
  "SELECT * FROM users LIMIT 5;"

# Files and cache:
adb shell run-as com.target.app ls -la \
  /data/data/com.target.app/files/
adb pull /data/data/com.target.app/files/tokens.json

# External storage (no root needed):
adb pull /sdcard/Android/data/com.target.app/files/
```

---

## iOS

### IPA Acquisition

**When to use:** Before any iOS analysis — encrypted App Store binaries must be decrypted from a running device.

```bash title="ipa_acquisition.sh"
# Method 1: frida-ios-dump (jailbroken device — decrypts at runtime)
python3 dump.py com.target.app

# Method 2: ipatool (Apple ID required)
ipatool download -b com.target.app --purchase

# Extract IPA contents (it's a ZIP):
unzip target.ipa -d target_ipa/
# Main binary: Payload/Target.app/Target
```

---

### Static Analysis

**When to use:** Immediately after extraction — before setting up a proxy.

```bash title="ios_static_analysis.sh"
# Binary info:
file target_ipa/Payload/Target.app/Target

# String extraction:
strings target_ipa/Payload/Target.app/Target | \
  grep -iE "(key|secret|token|password|api|https://)"

# Objective-C class interfaces:
class-dump -H target_ipa/Payload/Target.app/Target -o headers/
# Review headers/ for: API endpoints, auth logic, storage method names

# App configuration:
cat target_ipa/Payload/Target.app/Info.plist
# URL schemes (deep links), permissions, ATS config

# Embedded secrets across all plists and JSON:
find target_ipa/ -name "*.plist" | \
  xargs grep -liE "(key|secret|token|password|api)"
find target_ipa/ -name "*.json" | \
  xargs grep -liE "(key|secret|token|password|api)"
```

| Info.plist field | Security implication |
|---|---|
| `NSAllowsArbitraryLoads: true` | HTTP allowed — traffic easier to intercept |
| `CFBundleURLTypes` | Custom URL schemes registered — test deep link injection |
| `NSLocationAlwaysUsageDescription` | Background location access |

---

### SSL Pinning Bypass and Proxy Setup

**When to use:** Burp CA is installed but traffic still shows SSL errors.

=== "Objection (no jailbreak)"

    ```bash title="ios_objection_patch.sh"
    # Patch IPA to inject Frida gadget:
    objection patchipa --source target.ipa

    # Re-sign and install:
    codesign -f -s "iPhone Developer" target-patched.ipa

    # Connect and disable pinning:
    objection -g com.target.app explore
    ios sslpinning disable
    ```

=== "SSL Kill Switch 2 (jailbroken)"

    ```
    # Install via Cydia on jailbroken device
    # Provides blanket SSL pinning bypass system-wide
    # No per-app configuration needed
    ```

---

### Keychain and Insecure Storage

**When to use:** After SSL bypass and traffic mapping — check what the app stores locally.

```bash title="ios_storage_inspection.sh"
# Inside Objection shell:
ios keychain dump
# All keychain items stored by the app
# Look for: tokens or passwords without kSecAttrAccessible restrictions

ios nsuserdefaults get all
# Often contains: session tokens, user IDs, feature flags

ios filesystem ls
# Locate .sqlite files in Documents/Library folders
ios sqlite connect <path-to-sqlite>
ios sqlite execute query "SELECT * FROM users"

ios pasteboard monitor
# Some apps copy sensitive data to clipboard — accessible to any other app

# Download plist files for local review:
ios filesystem download \
  <path>/Library/Preferences/com.target.app.plist
plutil -convert xml1 com.target.app.plist
```

!!! info
    iOS takes a screenshot when the app backgrounds. If that screenshot captures a password field, token, or sensitive screen, it's a valid finding. Path: `/var/mobile/Containers/Data/Application/<UUID>/Library/Caches/Snapshots/`

---

### Deep Link and URL Scheme Abuse

**When to use:** `Info.plist` reveals custom URL schemes or Universal Links are in scope.

```bash title="ios_deeplink_testing.sh"
# Find URL schemes:
grep -A5 "CFBundleURLTypes" \
  target_ipa/Payload/Target.app/Info.plist

# Universal Links — check app-site-association:
curl -s "https://target.com/.well-known/apple-app-site-association"
# Shows which HTTPS paths open in-app vs browser

# Test deep links on simulator:
xcrun simctl openurl booted "targetapp://reset?token=test"
xcrun simctl openurl booted "targetapp://payment?amount=0.01&currency=USD"
xcrun simctl openurl booted "targetapp://auth?redirect=https://evil.com"
```

---

## Common Mobile Findings

### OWASP Mobile Top 10 Field Reference

| Risk | What It Means | Where to Look |
|---|---|---|
| M1: Improper Credential Usage | Hardcoded keys, secrets in source | Java/Swift source, `strings.xml`, `.plist`, assets |
| M2: Inadequate Supply Chain | Malicious third-party SDKs | `build.gradle`, `Podfile`, dependency audit |
| M3: Insecure Auth | Weak tokens, no expiry | Intercepted traffic, token storage locations |
| M4: Insufficient Input Validation | Injection via deep links, WebViews | Deep link params, WebView URL handling |
| M5: Insecure Communication | No cert pinning, HTTP allowed | Intercepted traffic, ATS config |
| M6: Inadequate Privacy Controls | PII in logs, local storage | `adb logcat`, storage inspection |
| M7: Insufficient Binary Protections | Debuggable flag, no obfuscation | Manifest, ease of JADX decompilation |
| M8: Security Misconfiguration | Debug mode, excessive permissions | Manifest analysis, exported components |
| M9: Insecure Data Storage | Tokens in SharedPrefs, unencrypted DB | Local storage inspection |
| M10: Insufficient Cryptography | Weak algorithms, hardcoded IV/key | Source code analysis |

---

### Mobile API Backend Testing

**When to use:** After SSL bypass — every intercepted request is a potential test case.

The mobile client frequently talks to a different API version, or a version of the same API with fewer restrictions. These endpoints are the primary bug surface in mobile programs.

```bash title="mobile_api_recon.sh"
# In Burp: map all endpoints the app calls during normal use
# Look specifically for:
# - Different base URL: /api/mobile/v1/ vs /api/v2/
# - Mobile-specific routes: /api/push-token, /api/device-register
# - Debug endpoints active in production: /api/debug, /api/test
# - Endpoints returning more fields than web counterpart

# Once mapped: apply full API test suite from Part 7
# IDOR, mass assignment, auth bypass, privilege escalation
# Mobile APIs often lack the rate limiting and WAF rules of the web API
```

!!! tip
    Use Burp's "Compare site maps" feature to diff the mobile API surface against the web app. Anything present in mobile but absent from web is high priority.

---

### Firebase and Analytics Key Leakage

**When to use:** `google-services.json` found in the APK, or `GoogleService-Info.plist` found in the IPA.

```bash title="firebase_key_testing.sh"
# Locate in APK:
find target_decoded/ -name "google-services.json"

# Test api_key for open user registration:
curl -s \
  "https://identitytoolkit.googleapis.com/v1/accounts:signUp?key=<api_key>" \
  -H "Content-Type: application/json" \
  -d '{"email":"test@test.com","password":"password123","returnSecureToken":true}'
# idToken returned = open registration with this key

# Test api_key for Firestore document access:
curl -s \
  "https://firestore.googleapis.com/v1/projects/<project_id>/databases/(default)/documents/users?key=<api_key>"
# Documents returned = Firestore misconfiguration

# Firebase Auth email enumeration:
curl -s \
  "https://identitytoolkit.googleapis.com/v1/accounts:createAuthUri?key=<api_key>" \
  -d '{"identifier":"victim@gmail.com","continueUri":"https://target.com"}'
# "signinMethods": ["password"] = email is registered
# "signinMethods": [] = email not registered → user enumeration confirmed
```

---

??? note "Expand full checklist"

    ```
    APK / IPA ACQUISITION
    □ Download from APKPure/APKMirror (Android) or ipatool (iOS)
    □ Extract from connected device via adb pull / frida-ios-dump

    STATIC ANALYSIS
    □ APKTool decode → AndroidManifest.xml review
    □ JADX decompile → Java source search for secrets and endpoints
    □ MobSF automated scan → review full report
    □ Manifest: exported components, debuggable flag, backup flag, URL schemes
    □ Search source for: API keys, hardcoded credentials, internal URLs
    □ Search strings.xml, assets/, .plist files for secrets
    □ trufflehog on decompiled source
    □ Firebase google-services.json → test api_key permissions

    DYNAMIC ANALYSIS SETUP
    □ Android: configure proxy, install Burp CA, run apk-mitm or Frida
    □ iOS: configure proxy, install Burp CA, Objection patchipa or SSL Kill Switch
    □ SSL pinning bypass confirmed (Burp sees decrypted traffic)

    TRAFFIC ANALYSIS
    □ Map all API endpoints observed in traffic
    □ Compare to web app API: new endpoints? Different version? Different base URL?
    □ Test all discovered endpoints: IDOR, mass assignment, auth bypass
    □ Mobile API vs web API: different rate limiting or WAF rules?

    EXPORTED COMPONENTS (ANDROID)
    □ List exported activities, services, providers, receivers
    □ Launch exported activities directly without auth via adb
    □ Query exported content providers
    □ Inject parameters via deep links

    LOCAL STORAGE
    □ Android: SharedPreferences, SQLite DBs, files directory, cache
    □ iOS: Keychain dump, NSUserDefaults, Core Data, app backgrounding screenshots
    □ Look for: auth tokens, session IDs, PII, passwords in plain text

    DEEP LINKS
    □ Find all URL schemes from manifest / Info.plist
    □ Test parameter injection: redirect=, url=, token=
    □ Test WebView URL handling via deep link → XSS / open redirect
    □ Universal Links: review apple-app-site-association path scope
    □ URL scheme uniqueness: could another app register the same scheme?

    FIREBASE
    □ Firebase Realtime Database: <project>.firebaseio.com/.json → open?
    □ google-services.json api_key: user registration open?
    □ api_key: Firestore documents accessible?
    □ Firebase Auth: email enumeration via createAuthUri
    ```

---

## References

<div class="grid cards" markdown>

-   :material-school:{ .lg .middle } __Standards__

    ---

    The definitive mobile security testing methodology and vulnerability classification.

    [:octicons-arrow-right-24: OWASP MASTG](https://mas.owasp.org/MASTG/)
    [:octicons-arrow-right-24: OWASP Mobile Top 10](https://owasp.org/www-project-mobile-top-10/)

-   :material-tools:{ .lg .middle } __Tools__

    ---

    Core toolchain for mobile APK analysis, instrumentation, and SSL bypass.

    [:octicons-arrow-right-24: MobSF](https://github.com/MobSF/Mobile-Security-Framework-MobSF)
    [:octicons-arrow-right-24: JADX](https://github.com/skylot/jadx)
    [:octicons-arrow-right-24: APKTool](https://apktool.org)
    [:octicons-arrow-right-24: Frida](https://frida.re)
    [:octicons-arrow-right-24: Objection](https://github.com/sensepost/objection)
    [:octicons-arrow-right-24: apk-mitm](https://github.com/shroudedcode/apk-mitm)

-   :material-code-braces:{ .lg .middle } __Frida Scripts__

    ---

    Community SSL pinning bypass script — covers most pinning implementations.

    [:octicons-arrow-right-24: Universal Android SSL bypass](https://codeshare.frida.re/@pcipolloni/universal-android-ssl-pinning-bypass-with-frida/)

-   :material-book-open-variant:{ .lg .middle } __References__

    ---

    Comprehensive Android and iOS pentesting methodology with examples.

    [:octicons-arrow-right-24: HackTricks Android](https://book.hacktricks.xyz/mobile-pentesting/android-app-pentesting)
    [:octicons-arrow-right-24: HackTricks iOS](https://book.hacktricks.xyz/mobile-pentesting/ios-pentesting)

</div>