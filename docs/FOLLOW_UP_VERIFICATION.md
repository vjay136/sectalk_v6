# SecTalk follow-up verification

Web release under review is `web-v6.0.0-free.3`. This follow-up covers the v6 Free-tier release.

| Phase | Completion evidence | Status |
| --- | --- | --- |
| 1. Hosted signup and recovery | Verify public readiness, confirmation email and OTP recovery with a disposable mailbox. | Passed on production. The test confirmed the public link, old-password rejection, and sign-in with the new password. |
| 2. Private Admin access | Verify the production protection boundary and both assigned roles. The owner completes authenticator enrollment and first sign-in. | Anonymous visitors are redirected by Vercel. Both roles were verified on the owner account. Personal enrollment and sign-in are pending. |
| 3. V6 regression | Check controls with synthetic accounts and run the Free-tier registry, unit suite and release-matched database fixtures. | Registry passed 234 required entries. Unit suite passed 118 with three platform skips. The database suite passed 242 of 248 rollback-only fixtures after targeted retests. |
| 4. Android release | Verify the exact signed APK checksum, signature, Android App Links, install and render against production. | Android 15 emulator run `45839845729`, attempt 2, passed. Signed-in native interaction coverage remains open. |
| 5. Hosted provider and advanced checks | Configure and verify hosted media, voice notes, paid checkout, and other enabled provider paths. Repeat provider-dependent checks on the Web and Android. | Hosted group SFU, meeting media, voice notes and checkout report unconfigured. Relay, push and other external-provider flows need hosted acceptance. |

## Existing v6 evidence

The release browser tests verified 15 desktop tabs, private messaging, two-way audio and video, encrypted group chat, report handling, attachment search, mobile navigation, and Find Friends search and privacy controls. A five-account local run verified group audio and video, fallback and recovery between native direct peers and LiveKit, and return to direct peers. The production browser confirmed signup and password recovery through the real mail provider. The recovery form was reopened with a simulated resend cooldown to reuse the real delivered OTP without sending it again.

The Android package points to the live v6 Web origin. Its successful launch confirms that the signed package opens the updated site. The emulator workflow verifies the rendered entry screen and native link association. It does not exercise every signed-in Android tab, media path or physical device.

The release-matched rollback suite excludes two fixtures that are not single rollback-only scripts. Six remaining assertions concern SSO-related notification delivery and workspace planning, external tenant key reuse, and workspace offboarding reconciliation or retained evidence. These results do not provide hosted acceptance for those paths. The corrected presence and authenticator fixtures verify current authorization behavior without changing runtime access controls.
