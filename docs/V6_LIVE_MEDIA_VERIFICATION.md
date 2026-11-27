# SecTalk v6 live media verification

The release target is the isolated v6 Supabase project and the `sectalk-v6-pilot` Vercel project. The owner confirmed retirement of the legacy SecTalk database, and Supabase removed it on 27 November 2026. The v6 migration chain still includes the shared schema and tests for features introduced in earlier releases.

| Phase | Evidence or remaining check |
| --- | --- |
| Live Web baseline | Three synthetic accounts signed in and completed onboarding. One regular account opened all 15 main tabs. Two accounts accepted a contact request and sent and read a direct message. Search returned the private message for a participant and omitted it for the outsider. The accounts used Admin confirmation, so email delivery was outside this run. |
| TURN and direct calls | An authenticated call can request a short-lived coturn or Turnix lease. The group-side admission tests verified rate limits and denied access to unauthorized participants. Two ephemeral peers in Washington, D.C. and Singapore exchanged synthetic Opus audio in both directions using v6 Turnix credentials. In a separate application test, two signed-in SecTalk users in those regions started, answered and hung up direct audio and video calls. Both browsers sent and received media over selected relay-only ICE pairs. The caller also opened all 15 main tabs in the protected candidate. |
| Group calls | Local browser audio and video passed with four participants on mesh, including retry after an ICE endpoint error. A fifth invite was unavailable without an SFU. Five-participant local LiveKit audio and video passed with real media, topology transitions in both directions and failed handoff rollback. An earlier run timed out during a video handoff retry. Protected staging reports `sfu: true` and `mediaConfigured: true`. Signed-in staged browsers in Washington, D.C. and Singapore started, joined and ended two-user group audio and video over relay. The recipient's end-of-video state timed out on the first run and passed on retry. The five-participant hosted test then measured real media on a four-person mesh, verified all five participants published and received audio and video after the fifth joined, matched the exact LiveKit server roster and tracks, and verified end-of-call state on all five. |
| Android call alerts | The local push API test advanced the opted-in recipient's job through a simulated delivery endpoint. Mobile Chromium displayed the service-worker notification. A non-promoted Vercel build verified that the v6 Supabase push secret is accepted and the configured VAPID pair matches. Android candidate `729d257` passed two Gradle unit tests, lint and assembly. The APK passed zip alignment, v2/v3 signature verification against the owner certificate and notification delegation manifest checks. The signed APK installed on a Google Play Android 15 emulator. Android verified the canonical App Link and displayed the live SecTalk sign-in screen. A synthetic generic push dispatched to the canonical Chrome service worker while Android Home was foregrounded produced a native notification attributed to the SecTalk package. Actual incoming-call delivery via FCM, alert sound and tap-to-answer are still open. |
| Full live coverage | `FEATURE_MATRIX.md` identifies 234 in-scope features and five deferred entries. Opening a tab proves navigation only. Record a separate passing result for each applicable feature on live Web and Android, or identify its external dependency and disposition before publication. |
| Versioned release | Publish and redeploy v6 from the tested revision after the full live verification requested for this release. Confirm v5 still responds independently. |

LiveKit's Build plan and Turnix Free have hard caps. A coturn instance on existing infrastructure can also use the app's short-lived credentials. Web Push uses VAPID with a server-only Supabase key and requires recipient permission. Android controls notification sound and vibration.

## Activation

In the v6 Vercel project, keep `TURNIX_API_TOKEN`, `LIVEKIT_API_SECRET` and `SECTALK_PUSH_SERVICE_KEY` server-only. Configure `LIVEKIT_URL` and `LIVEKIT_API_KEY` for the same project. For coturn, use `TURN_URLS` and `TURN_SHARED_SECRET` in place of the Turnix token. Preserve the VAPID pair already saved for v6.

The v6 Supabase database has the incoming-call push and group ICE admission migrations through `20261127031756`. Hosted readback confirmed the push function is service-only, and the group ICE entry requires an authenticated account. On the signed Android app, enable **Notifications → Preferences → Browser push** for the receiving account, send a new call while the app is in the background, and confirm that tapping the alert opens the ringing call. Repeat with the sound enabled in Android settings and record the specific OS and browser versions.

The hosted v6 ledger had 397 entries, consisting of the 392-entry baseline plus five later discovery, Admin, and calling migrations. A fresh Docker rehearsal reproduced the exact ledger and atomically applied seven intermediate workspace SSO and residency migrations and four later message-safety migrations. Forwarding, report advisories, and workspace schedule SSO SQL tests passed. The same guarded bundle was applied to the hosted v6 project on 27 November 2026. Hosted readback confirmed 408 migrations through `20261127053633`, the full expected ledger digest, and the forwarding and URL reputation objects.

## Hosted acceptance coverage

The registry marks 234 required rows DONE for implementation. Of those rows, 227 reference an `.e2e.mjs` test and zero cite an Android-specific result. The registry checker validates the evidence fields and statuses. The Android workflow checks the APK artifact and certificate, app-link association, and rendering of the sign-in screen. Neither check measures feature-by-feature acceptance in the hosted Web and Android clients.

Read-only checks against public v6 on November 27, 2026 returned four billing plans, with Stripe checkout, the billing portal, and provider tax disabled and no Razorpay offers. Recording, captions, and voice-note endpoints also reported that their providers were unconfigured. The public Android association returned the SecTalk package. Those results show the current capability state and do not verify an actual recording, checkout, or Android alert.

The v6 Production environment audit found the TURN, LiveKit and push settings. The following requirements still need configuration or evidence to verify their full hosted behavior.

| Required rows | Missing hosted capability or acceptance step |
| --- | --- |
| AUTH-04, AUTH-06 | Passkey enablement and a hosted HTTPS relying party test. Hosted SCIM service credential and identity-provider interoperability. |
| MSG-22, CALL-14, CALL-15 | Voice-note encryption and service configuration, signed recording and egress storage, and a speech worker reachable from the deployed application. |
| NOTIF-03, ANL-07 | Notification SMTP and scheduled delivery for email notifications and operational reports. Account confirmation email uses separate settings. |
| FILE-05, FILE-06, AI-03 | Hosted malware scanning, isolated PDF rasterization, and the URL inspection worker. Basic preview and local inspection paths have separate evidence. |
| CALL-21, CALL-23 | Guest meeting service configuration and Turnstile. Dedicated diagnostic relay and bandwidth settings. The Turnix call token does not configure the diagnostics endpoint. |
| Paid billing | Deferred by the owner. The v6 candidate offers the Free plan and blocks new paid actions. See Free billing below for verification. |
| SOC-13, PLAT-05 | Hosted credentials and workers for signed SIEM and outbound webhook delivery. |

The signed release APK trusts the canonical v6 Web origin. The canonical service worker has no incoming-call handler, the expected call push API URL returns the HTML shell, and the push subscription endpoint reports HTTP 503. The Android QA APK uses a distinct package, the same owner certificate, and a separate HTTPS origin with public Digital Asset Links. The QA app and APIs require a temporary access cookie, and public signup is disabled there. Only two synthetic users were seeded for the background-call test. Server-only checks such as the disaster recovery verification job (PLAT-10) and the independent audit receipt worker (SEC-06) need hosted service evidence rather than a screen assertion in the APK.

The signed Android QA build verified its own App Link and entered SecTalk with a synthetic account on Android 15. The authenticated QA push configuration returned HTTP 200 with a valid-length VAPID public key and no stored device subscription. The real Chrome push subscription failed before a subscription request reached the app. Google Play services recorded `GCM-GMS: AUTHENTICATION_FAILED`. The Windows host could connect to `mtalk.google.com:5228` and `fcm.googleapis.com:443`. A separate real ringing call returned HTTP 204 from the push route. Chrome accepted an injected v2 push event, but no Android incoming-call notification appeared. This leaves real FCM delivery, ringtone, and notification tap-to-answer open.

With the Android QA app in the foreground, the signed-in recipient saw and answered separate live audio and video calls from Edge. Both clients reached Connected. Edge verified inbound and outbound audio and video RTP on the applicable calls, and Android decoded the remote camera at 640×480 before hang-up.

The signed Android QA app opened all 15 main tabs, each showed the expected active navigation state, and none produced horizontal page overflow at the emulator's viewport. These checks cover navigation and layout. The separately gated Android QA URL uses two synthetic accounts.

The owner created SecTalk Android QA on Firebase Spark and authenticated Google's signed Android CLI. The project listing reported permissions available, Device Streaming API disabled, and billing disabled. No billing was enabled and no cloud device was reserved. The no-cost Android 16 Google Play emulator booted after formatting its disposable data partition and verified the signed QA App Link. Chrome 133 registered with `fcm.googleapis.com`. A real audio call posted the native SecTalk alert while the launcher was foregrounded, Android recorded sound dispatch, tapping the alert reopened the ringing call, and Answer connected with two-way audio RTP. The first tap automation failed to read the notification shade. The repeat verified the native tap using the compressed Android accessibility hierarchy. Audible playback on physical hardware remains unverified.

## Release phases

The release uses disposable accounts for an unconfirmed signup, a confirmed member, an accepted contact, an unrelated member, and an operator. Mailpit checks local link and code behavior. Hosted email delivery needs a separate real test inbox. Record evidence against the tested revision and environment.

| Acceptance pass | User actions and release evidence |
| --- | --- |
| 1. Account | Submit signup, open the confirmation email, verify the account, and sign in with the original password. Check expired or reused links, incorrect credentials, recovery code, and sign-in with the new password. Confirm that successful authentication reaches the workspace. |
| 2. Messaging and calling | Connect two dummy members. Verify message delivery, read and typing state, updates and revocation in both sessions. Place or decline audio and video calls, verify two-way media, and check ringing, hang-up, and background notification behavior on Android. |
| 3. Navigation and data | Open all 15 member tabs on desktop and Android. Exercise applicable forms, filters, options and role boundaries, including empty, loading and error states. Check updates from a second account and distinguish navigation coverage from feature coverage. |
| 4. Admin | Verify that an ordinary user cannot enter. Enroll and verify MFA for a disposable operator. Exercise the activity, storage, safety, feature inventory and moderation views, plus permitted actions and denied cross-tenant access. |
| 5. Hosted release | Run the candidate against v6 Supabase, verify real provider paths, and retest the exact signed APK on Android. Publish the verified GitHub tag, deploy Web and Admin to their v6 projects, and check the public Web URL, private Admin URL, APK signature and checksum. |

The current working-tree retest passed seven member browser suites and the Admin suite. The signup suite checked passive link preview, confirmation, replay rejection, password sign-in, recovery code, and all 15 navigation tabs. Three disposable accounts verified bidirectional direct messaging, denial for the outsider, audio ringing, two-way audio and video, noise reduction, and private report history. Additional suites covered mobile layout at 320–390 px, discovery, Free billing, report updates, and moderator warning retraction. The Admin suite covered regular-account denial, QR enrollment, operator MFA, activity, storage, moderation navigation, and the 234-entry feature inventory.

The existing GitHub Android release `android-v6.0.0-free.2` was downloaded for verification. Its bytes matched the published checksum and GitHub asset digest. APK signatures v2 and v3 passed, the signer matched the live site's App Links association, and the published package installed and launched on Android 16. The candidate's new signed artifact remains open.

The current local candidate also passed report submission, forwarding, private staff origin tracking, and live warning retraction with the recipient in Chrome on the Android 16 emulator. All 15 member tabs opened without horizontal overflow. The existing Vercel pilot returned `ready` but reported voice notes, captions, and recording unconfigured. Local Mailpit evidence and emulator Chrome evidence do not replace hosted mailbox and signed-candidate checks.

| Order | Phase | State and exit criteria |
| --- | --- | --- |
| 1 | Keep the v6 pilot and QA origin reachable | The v6 pilot responded, and the QA hostname served its signed Android App Link. The legacy SecTalk backend was retired separately. |
| 2 | Verify core hosted chat and media | Direct and five-person group media passed. Existing QA accounts passed password sign-in, direct send, read receipts, quote, edit and history, reaction sync, pins, saved messages, private hide, revoke, quote redaction and participant search. The typing indicator passed all three dedicated sequential typing trials. Some earlier one-shot input tests timed out. The profile photo preview, cancellation, save, contact-side display and removal passed against hosted QA. |
| 3 | Prove signed Android background calls | Android 16 passed real FCM delivery, OS sound dispatch, notification tap, answer and audio RTP with the signed QA build. Earlier foreground audio and video and navigation passed. Physical-phone audible playback is open. |
| 4 | Complete live acceptance for the 234 required features | Open. Record passing Web and Android results for client controls and hosted service results for backend-only requirements. Provider prerequisites are listed above. |
| 5 | Publish and deploy the exact verified revision | Waiting for phases 2–4. Push to the v6 repository, tag verified artifacts, and publish on the v6 project, then verify the Web, Admin, and Android release artifacts. |

| Phase 4 batch | Required rows | Evidence to close the batch |
| --- | ---: | --- |
| Member access and messaging | 50 | AUTH, MSG, PRES, SRCH. Run signup, recovery, session, discovery, inbox and search tests across the two client platforms with separate accounts. |
| Workspaces and collaboration | 38 | ORG, THR, ROOM, TASK. Exercise room, thread, membership and task controls as owner, member and unrelated account. |
| Calls and notifications | 33 | CALL, NOTIF. Record media, sound, background delivery and call control results. Verify meeting and email delivery services with configured fixtures. |
| Files and risk signals | 30 | FILE, AI. Exercise upload and download paths, chat warnings and user actions. Collect hosted scanner, preview and worker evidence. |
| Safety and staff operations | 43 | SEC, SOC, ADM. Run role-scoped safety, reporting, ticket, moderation and audit workflows. Verify hosted service-only security controls separately. |
| Billing and platform operations | 40 | BILL, PLT, ANL, PLAT. Run provider transactions in test mode, operational analytics, scheduled services and the release verification jobs. |

- [LiveKit quotas and limits](https://docs.livekit.io/deploy/admin/quotas-and-limits/)
- [Turnix Free usage limits](https://turnix.io/docs/concepts/usage-limits)
- [Previous signed Android emulator run](https://github.com/vjay136/sectalk_v6/actions/runs/45839845729/attempts/3)
- [Protected v6 media staging deployment](https://vercel.com/silent-soldier-vjay/sectalk-v6-pilot/Hs6L4WGP9PwHPoJpwzQPetT7xPVQ)
- [Turnix cross-network audio result](https://vercel.com/silent-soldier-vjay/sectalk-v6-pilot/5Bm8hCtumSBPc6jQj9epTphJwsu3)
- [LiveKit cross-network audio result](https://vercel.com/silent-soldier-vjay/sectalk-v6-pilot/CuANZ2gdDwrQ83K6ZVj6EKN1d2An)
- [SecTalk staged cross-network direct audio and video result](https://vercel.com/silent-soldier-vjay/sectalk-v6-pilot/G5BYuKQRMMhqGjt8g6czM2bxA1wK)
- [First SecTalk staged cross-network group call run](https://vercel.com/silent-soldier-vjay/sectalk-v6-pilot/AHg6M74crozrjoEnvgY5xmWuqvZw)
- [Passing SecTalk staged cross-network group call rerun](https://vercel.com/silent-soldier-vjay/sectalk-v6-pilot/Gs9RGXjPW9BiJBBzLvu6JQr1rD9k)
- [Passing hosted five-participant LiveKit handoff](https://vercel.com/silent-soldier-vjay/sectalk-v6-pilot/1k8LGwR9KgjotmXnGAKaSi5mXYe5)
- [Separate Android QA deployment record](https://vercel.com/silent-soldier-vjay/sectalk-v6-pilot/HLyyYbnXyaa7MKVX8iWHWxPXzJNX)

## Additional local browser verification

Chrome exercised candidate `441fc30` with the free release scope and a loopback Supabase stack through migration `20261122122000`. The `tests/chat-storage.e2e.mjs` suite exited successfully with isolated synthetic accounts and actual Web API, SQL, and Storage operations. This verification applies to local Web. Automatic approval review blocked an additional protected hosted build before any deployment or test-data creation.

| Feature rows | Observed behavior |
| --- | --- |
| AUTH-02, MSG-01, MSG-12, MSG-20, MSG-21 | Confirmed accounts signed in with passwords. Accepted contacts exchanged direct messages, pinned and unpinned across accounts, and saved and removed a private saved message. One scheduled message arrived through the local scheduler. A separate cancellation appeared in the sender’s history and delivered no message. |
| MSG-09, MSG-10 | Both browsers displayed the original text in a quote and automatically replaced it with an unavailable-source message after revocation. |
| FILE-01, FILE-03, FILE-07, FILE-12 | The composer published a valid file through the resumable endpoint. File-type validation rejected a mismatched extension and MIME claim. The signed download served exact bytes and rejected an unrelated account and a revoked file. The file library filtered incoming attachments and downloaded the selected file in a ZIP. |
| SRCH-01, SRCH-02, SRCH-05, SRCH-07, SRCH-08, SRCH-09 | Direct and workspace search exercised all seven filters and restored saved filter values. Highlighting rendered source text literally and disappeared on revocation. The command palette supported keyboard navigation and restored focus. The browser saved, reran, and removed a search. Workspace audit search succeeded for the owner and denied the member. |
| ROOM-01, ROOM-03, ROOM-07, ROOM-08 | The owner created a private room, an invited member joined, a post appeared across sessions, and the audit tab displayed the creation entry for the owner only. |
| TASK-01 through TASK-10, NOTIF-01 | Both sessions exercised task creation in rooms and chats, source links, assignment and watching, status change, an overdue date, priority and labels, list/board/calendar, grouped notifications and read state, the task audit, and the task record after source revocation. |
| CALL-04, CALL-06, CALL-17, CALL-18 | The browser verified recurring scheduling, ICS export, a member-only join link, bulk admission from the waiting room, and server media admission. Video callback retained the call mode, displayed ringing, and recorded the decline. |
| AI-07, AI-10 | The risk warning displayed reasons and contextual report and dismissal actions. The low-risk case accepted incorrect-warning feedback and reset after a message edit. The test closed the report form before submission. |

The browser also saved and displayed a profile photo and synchronized addition and removal of a custom direct-message reaction. The suite follows the redesigned interface by opening the collapsed Search filters before interacting with them.

## Current working-tree retest

These checks used the v6 working tree, Edge, and disposable loopback Supabase fixtures. The earlier hosted results apply to their own deployed revisions.

| Check | Result |
| --- | --- |
| Static and unit baseline | Web, Admin and Workers TypeScript passed. The unit suite passed 121 tests, skipped three and reported no failures. The feature registry identified 234 implemented rows. The working-tree secret scan passed after handling the intentionally removed release notes and including new publishable source files. |
| Signup and recovery | The browser confirmed the signup link, branded confirmation screen, password sign-in, OTP reset, and native password hash with Mailpit. A stale local email template caused the first run to fail. The separate account recovery suite passed after configuring the local device service credential. No real mailbox received email in this run. |
| Messaging, calls and presence | Three isolated browser accounts passed the direct messaging, call tone, audio/video media and noise-control suite. Discovery and messenger layout suites passed. The chat and storage suite passed real upload/download, revocation, profile photos, reactions, search, room and task changes, and meeting and call controls. SQL tests passed for scoped discovery, online visibility, group call admission, call notifications and private presence. |
| Reviewed safety labels | The browser submitted a report, showed the private pending marker to the reporter, forwarded the exact message, displayed a confirmed fraud label to the downstream recipient, and removed the label after retraction. This passed in Edge and in a cross-client run with the downstream account in Android emulator Chrome. The moderator could see the original sender and forward count. Private comments stayed in the case. The database test verified scope-only private update hints, exact revision isolation and the staff-only account roster. |
| URL inspection | Browser and SQL regression tests passed using the isolated URL worker and synthetic destinations. |
| Separate Admin console | A regular account was denied. A synthetic operator enrolled with a QR code, failed an incorrect code, and completed verification with the correct code. The operator opened activity, storage, safety and feature inventory, filtered the inventory, and reached moderation. The dashboard reports implementation state from the release matrix. |
| Android | Recreated one local Android 16 Google Play emulator using the checksum-verified official image. Both previously signed APKs installed, the canonical launcher started, and Android verified its App Link. Emulator Chrome opened all 15 navigation tabs on the current loopback candidate without horizontal page overflow. The signed APKs retain their original signing and release provenance. |

The rollback-only SQL batch covered 253 scripts. The first fixture passed 232, failed 19, and skipped two that did not meet the batch's rollback-only filter. The alternate v6 fixture passed 16 of the 19 rechecks, including audit integrity, protected notification delivery, and workspace SSO. The remaining three exercise provider key reuse and tenant offboarding, which are deferred in the Free-tier scope. These counts measure test scripts and do not map one-to-one to feature rows.

The 234-feature hosted acceptance gate stays open. New moderation labels cover direct-message evidence. Room forwarding has provenance counts, and room and channel reports retain their own workflows. A full hosted retest needs the provider capabilities listed above and current-revision evidence for each applicable client.

## Media provisioning and Free billing

| Capability | Verification and remaining hosted requirement |
| --- | --- |
| Voice notes | Edge passed microphone capture with synthetic input, peer playback, waveform, ciphertext, optional offline transcription, and revocation. A separate Android 16 Chrome test verified playback with transcription disabled. Hosted playback requires a stable encryption key and a server-only v6 Supabase credential. |
| Captions | Two browsers passed the loopback Faster Whisper worker with separate live meeting microphone sources, authenticated speaker labels, a saved transcript, and consent withdrawal. The current candidate also accepts a dedicated HTTPS worker from an explicitly configured origin. Hosted inference still requires the worker deployment and an end-to-end consent test. |
| Recording | The candidate accepts LiveKit's app-issued participant and binding format while keeping consent keyed to the account and connection. The browser passed recording consent, safe discard, withdrawal, late-join invalidation, and private file access with actual local LiveKit participants and a simulated Egress provider. The v6 dashboard shows the private `recordings` bucket, enabled S3 protocol, and zero generated S3 access keys. Supabase project-wide keys bypass Storage policies across all buckets. Use a recording-scoped destination or obtain authorization for the broader credential before sharing it with LiveKit Egress. |
| Free billing | Paid subscriptions and hosted checkout are deferred. The candidate defaults to Free on Vercel. The local Edge test confirmed the Free entitlement on a new account, the Free-only billing screen at desktop and mobile widths, and rejection of direct purchase, upgrade, portal, workspace seat, refund, trial and renewal-notice requests with mock payment credentials configured. The existing paid catalog and signed Stripe webhook reconciliation also passed with `SECTALK_BILLING_MODE=paid` and a loopback provider. The billing change still needs deployment and a hosted smoke test. |

### Remaining release checks

| Work | Latest evidence | Required to close |
| --- | --- | --- |
| Voice notes | The local test passed in two Edge sessions and then from Edge to Chrome 133 on Android 16 with speech disabled. Both runs verified waveform, encrypted storage, outsider denial, deletion after revocation, and blocked-contact denial. The first Android run timed out during workspace loading. | Repeat on the protected hosted candidate and the exact signed APK with a stable v6 encryption key and server credential. |
| Captions and optional transcription | Both routes now accept a dedicated, explicitly configured HTTPS worker. Unit tests passed for origin, path, credential, and loopback validation. | Deploy the private Faster Whisper worker and repeat consent, speaker identity, and audio-retention checks against the hosted candidate. |
| Recording | Local media admission, consent, and storage tests have evidence. Hosted recording remains unavailable. | Connect a recording-scoped destination and verify real LiveKit Egress, access, deletion, and consent withdrawal. |
| Free-only billing | `SECTALK_BILLING_MODE=free` is saved in the v6 Vercel Production environment. | Verify the deployed candidate presents Free as its only plan and rejects payment actions. |
| Final release | The v6 database holds all 408 migrations. | Finish hosted acceptance, build and verify the exact Android artifact under a new version, and publish the verified revision. |

The Supabase and Vercel v6 dashboards were accessible. The v6 Production environment now has `MEETING_RECORDING_S3_ENDPOINT` and `MEETING_RECORDING_WEBHOOK_URL` saved as non-secret configuration. Both keys were verified in the Vercel environment list. Provider credentials, payment settings, and the deployed revision are unchanged.

### November 27 follow-up candidate

- The local browser runs verified signup confirmation and password sign-in, Admin authenticator enrollment, mobile navigation and tab counts, Find Friends search, and contact presence changes. The automatic-presence migration preserves previous manual settings and continues to honor sharing preferences.
- Be Safe searches reviewed direct-message fingerprints, active global URL restrictions, and permitted account restrictions. The evidence includes a pending complaint remaining private, a reviewed warning reaching a forwarded copy, and the warning clearing after withdrawal. The Android 16 Chrome session verified the downstream warning and its details. Local SQL tests covered private accounts, unapproved contact requests, exact URL matches, restricted links inside chat, and expired restrictions.
- Direct audio and video calls filled both browser viewports during ringing. An Android 16 Chrome session also verified the incoming full-screen layout and decline for both call types. A three-account call test measured received video pixels after monochrome and butterfly effects, switching the camera off, and restoring the raw track. The group tests verified the received video filter with four mesh participants and again after moving into five-person local LiveKit media. The separate forced-rollback browser scenario remains unverified.
- The Admin browser test verified authenticator enrollment, normal-account denial, a 320 px viewport, and role-gated API access for blocklists, detection rules, and incident management.
- The ringtone browser test exercised all four presets, preview, rejection of a 21-second clip, persistence and incoming playback of a two-second custom clip, stopping playback on decline, and reverting to the default. Custom foreground audio stays on the device. Android background alerts use the system notification channel.
- Android unit tests, lint, and debug packaging passed. The Android SDK inspection reported the published APK and local candidate as `com.eaglesecurity.sectalk` with the `SecTalk` application label. The candidate also explicitly sets the launcher label and adds the Eagle Security app description.

This evidence covers the local follow-up candidate. The new migrations and binaries still need release verification against the hosted v6 stack.

### Rollback and release verification

- A failed shared-media setup can now cancel its own promotion generation without interrupting the established four-person mesh. The disposable database test verified immediate rollback, the timeout fallback, retry with a new generation, reverse rollback, and denial for outsiders, unrelated devices, and stale generations.
- The strict five-browser audio and video suites passed on the checksum-verified native Windows LiveKit v1.13.11 fixture. Each forced a fifth endpoint's shared-media admission to fail, checked that the original four retained real media and the fifth could rejoin, then verified five-person media. Video also checked the receiver's filter. Both tests forced failure during the return to mesh, verified shared media stayed live, and passed the subsequent return to direct media. The earlier Docker fixture reached rollback but timed out reconnecting to shared media.
- The feature registry validates 234 implemented rows and five deferred rows. Of the 234 rows, 227 reference browser E2E files. The registry contains zero row-level Android acceptance references. The registry status measures recorded implementation evidence.
- The public pilot returned a ready health check. Its voice-note, caption, and recording endpoints report that providers are unconfigured, and its push endpoint returned HTTP 503. The Vercel connector returned HTTP 403 on the deployment workspace. These checks leave the hosted release requirement open.
- The local messaging stress smoke delivered all 48 messages in six concurrent bursts with zero duplicate or outsider events. The write API p95 was 256 ms and peer-delivery p95 was 280 ms. The operator browser passed 14 repeated section transitions at 320 px and 1280 px, with role checks and a single selected section.
- The owner-signed Android `6.0.0-free.3` candidate (`6000003`) passed alignment, signature checks, installation, and verified App Link launch. With the new Web code loaded in the APK's Android custom tab through an isolated loopback test, its real camera frames verified monochrome, butterflies, camera-off black output, and restored original color. A separate Android-to-Edge test passed ringing, answer, and ICE authorization but failed to reach connected media, so remote effects in that path remain open. The APK SHA-256 is `108fc379b7163e15d0baa6b3cea5d29a62e398a2f689958e1ce9a04899b8b0d0`.
