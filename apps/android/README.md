# SecTalk for Android

This standalone Gradle project launches the existing free SecTalk web app as a Trusted Web Activity (TWA) with [Android Browser Helper 2.8.0](https://github.com/GoogleChrome/android-browser-helper). It uses the web app's account, data, and Supabase backend and ships no separate backend credentials. The only launch origin is `https://sectalk-v6-pilot.vercel.app`. Android handles supported account, invitation, guest, and shared-file links for that origin once verified. Other links continue through the browser. If TWA verification or browser support is unavailable, the app uses a browser Custom Tab or the installed browser. No embedded WebView is configured.

## Incoming call alerts

In SecTalk, open **Notifications → Preferences → Browser push** and allow notifications when prompted. The TWA delegates notifications from its verified browser to the SecTalk package. Android controls alert sound and vibration based on device settings, permissions and Do Not Disturb. Tapping the alert opens SecTalk, where an active call can be answered before it expires.

To verify a signed build with hosted push enabled, sign in as a dummy recipient, grant notifications from that setting, then send the app to the background with Home. From a second signed-in client, place an audio call and then a video call. For each, verify that Android posts the alert under SecTalk, the device plays the permitted notification sound, and tapping the alert opens the ringing call. Repeat with notifications denied to verify Android honors the setting.

## Build and test

Use JDK 17, Gradle 8.13, Android SDK Platform 36, and Build Tools 35.0.0. Set `ANDROID_HOME` to the SDK path or select the SDK in Android Studio. From `apps/android` run:

```sh
gradle :app:testDebugUnitTest :app:lintDebug :app:assembleDebug :app:assembleRelease :app:bundleRelease
```

The workflow uploads three packages without requiring signing secrets. The debug APK at `app/build/outputs/apk/debug/app-debug.apk` can be used for smoke tests. The unsigned release APK at `app/build/outputs/apk/release/app-release-unsigned.apk` is for direct distribution after signing. The unsigned AAB at `app/build/outputs/bundle/release/app-release.aab` is for Play upload after signing. Browser UI is expected on ordinary debug builds because their certificate has no production association.

## Owner signing and verified links

For direct distribution, use SDK Build Tools to align and sign the CI release APK on the owner's computer. `apksigner` prompts for the keystore password. Compare its public SHA-256 certificate fingerprint with the expected owner certificate before publishing.

```sh
zipalign -P 16 -f 4 app-release-unsigned.apk sectalk-aligned.apk
apksigner sign --ks /secure/path/sectalk.jks --ks-key-alias sectalk --out sectalk-release.apk sectalk-aligned.apk
apksigner verify --verbose --print-certs sectalk-release.apk
```

1. Use Android Studio **Build → Generate Signed Bundle / APK** with the owner's Android upload keystore. If this is a new Play listing, the owner can create an upload key in that dialog and enroll in Play App Signing. Securely back up the keystore credentials outside this repository and keep `com.eaglesecurity.sectalk` as the application ID. The workflow does not sign or publish.
2. Obtain the SHA-256 fingerprint of the certificate that will sign installed APKs. For Google Play installs use the **app signing key certificate** from Play Console, not the upload certificate. For direct APK distribution obtain it with `apksigner verify --print-certs path/to/signed.apk`.
3. Set the public Web deployment's `SECTALK_ANDROID_CERT_SHA256` to the colon-delimited SHA-256 fingerprint (or comma-separated fingerprints for multiple approved signers). Verify the deployed Digital Asset Links response at `https://sectalk-v6-pilot.vercel.app/.well-known/assetlinks.json`. It must return HTTP 200 with JSON without login or redirects. The required target is `android_app`, package `com.eaglesecurity.sectalk`, relation `delegate_permission/common.handle_all_urls`, and the exact SHA-256 fingerprint under `sha256_cert_fingerprints`. Do not publish placeholders or CI debug keys to production. See [Android App Links verification](https://developer.android.com/training/app-links/configure-assetlinks).
4. Install the signed build and verify it on Android 12 or newer. Run `adb shell pm verify-app-links --re-verify com.eaglesecurity.sectalk`, then `adb shell pm get-app-links com.eaglesecurity.sectalk` and check the canonical host is `verified`. Tap real account and invitation links from email, open guest and shared-file links, and test sign-in, messaging, and calling on a device. Check unrelated or off-origin links stay in the browser. Verify that the TWA opens without a browser address bar after association succeeds.

## Independent release tags

Android's first tag is `android-v6.0.0-free.1`, corresponding to `versionName '6.0.0-free.1'` and `versionCode 6000001`. Create it only on the intended Android release commit after the build and device checks. Future Android tags use `android-v<versionName>` and require a strictly increasing `versionCode`. This tag triggers the Android build workflow only and does not deploy the website or publish to Google Play.
