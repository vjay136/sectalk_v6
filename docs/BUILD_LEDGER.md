# V6 build ledger

| Phase | Slice | Evidence |
| --- | --- | --- |
| P0 | Inventory the release target, environment names, and existing v5 behavior | `npm run preflight`, GitHub repository lookup, Vercel v5 project inspection |
| P1 | Extract and validate the 239 IDs | `features.md`, `docs/FEATURE_MATRIX.md`, `npm run verify:registry` |
| P2 | Add an anonymous readiness probe with a database marker | `tests/readiness.test.mjs`, `tests/v6-database.sql` |
| P5 | Add a private Saved messages view and a permission-scoped Files tab | `tests/v6-database.sql`, local two-account browser and storage checks |
| P5 | Add tenant-scoped rooms, invites, request approval, moderation, pins and room audit | `tests/v6-rooms-database.sql` and two-browser role and synchronization checks |
| P5 | Add scoped thread replies, synchronized reply counts and private follow/unfollow | `tests/v6-rooms-database.sql`, two-browser thread checks |
| P5 | Add account-private saved search terms and filters | `tests/v6-database.sql`, browser save, run and remove flow |
| P5 | Add scoped tasks, assignment, watchers, source links, audited transitions and deadline reminders | `tests/v6-tasks-database.sql`, two-browser workflow and local scheduler |
| P5 | Group live meeting and task notifications and verify read state | `tests/chat-storage.e2e.mjs`, meeting and task recipient SQL fixtures |
| P5 | Add a global command palette and permission-filtered search snippets with live revocation | `tests/v6-database.sql`, `tests/v3-database.sql` and two-browser keyboard, search and revocation checks |
| P5 | Add host-only bulk meeting lobby admission | `tests/v6-lobby-database.sql`, two-browser waiting-room transition and local media token checks |
| P5 | Record call outcomes and add a Missed calls view with same-mode callback | `tests/v6-call-history-database.sql` and two-browser callback and decline |
| P5 | Add scheduled direct messages and a private sender outbox | `tests/v6-scheduled-messages-database.sql`, actual local cron and two-browser delivery checks |
| P5 | Validate direct reply quotes and remove revoked sources from open conversations | `tests/v6-database.sql` and two-browser source revocation |
| P5 | Add Meet now for authorized workspace hosts | `tests/v6-instant-meeting-database.sql` and a two-browser lobby, notice and retry check |
| P5 | Enforce pin permissions and publish room templates with pinned guides | SQL permission fixtures and two-browser pin, template and directory checks |
| P5 | Synchronize contact presence with rate-limited heartbeats | `tests/v6-presence-database.sql` and two-browser state, expiry and block checks |
| P5 | Add a separate admin audit search with workspace scoping | `tests/v6-audit-search-database.sql` and two-browser admin and member verification |
| P5 | Schedule recurring meetings and export calendar invites with scoped join links | Recurrence SQL fixture, ICS unit check and browser download and link tests |
| P5 | Preserve room threads after a parent is edited, deleted or redacted | Room thread SQL fixture and two-browser edit, follow and redaction checks |
| P5 | Share a permission-scoped active workspace across collaboration views | Membership SQL fixture and workspace switching, immediate role removal and account isolation browser checks |
| P5 | Add direct-message delivery acknowledgments and stable-ID retry | Delivery SQL fixture and two-browser queued-through-read checks |
| P5 | Persist offline text and replies with account-local encryption and replay on reconnect | Browser reload, lost-response deduplication, account switch, blocked retry, and damaged-entry checks |
| P5 | Issue per-call ICE credentials and renew short leases | Active-call SQL fixture and local browser test for signature, TTL and renewal |
| P5 | Authorize and audit short-lived attachment downloads | Signing unit test, permission SQL, successful local byte retrieval and download audit records |
| P5 | Validate stored attachment bytes before publishing a chat message | File-type unit test, normal composer upload and rejection of mismatched bytes and raw RPC bypass |
| P5 | Add workspace groups, teams and departments | Workspace lifecycle SQL fixture and two-browser membership and tenant isolation |
| P5 | Add typed workspace setup with enforced privacy defaults | Workspace onboarding SQL fixture and two-browser creation, room and lobby checks |
| P5 | Assign immutable direct-message sequence numbers and fill reconnect gaps | Legacy backfill, rollback fixture and two-browser multi-page catch-up and dedupe |
| P5 | Set one winning call session and synchronize outcomes across devices | Call endpoint SQL fixture, three-browser answer race and ICE regression |
| P5 | Add live hand raises and transient meeting reactions | Meeting roster SQL and two-browser Realtime and expiry checks |
| P5 | Add explainable safety warnings with contextual report review | Local warning heuristics and browser dismissal, edit and consent flow |
| P5 | Apply direct-chat edit windows and per-author revision visibility | SQL authorization and two-browser live edit, sharing and revocation |
| P10 | Report delivery latency percentiles to MFA-verified staff | Exact synthetic percentile fixture and local authenticator step-up browser check |
| P10 | Report product usage as rounded aggregates with small-group suppression | Aggregate privacy SQL and local staff MFA and browser check |
| P10 | Add public vulnerability disclosure routes and repository reporting guidance | Unit and production HTTP tests passed with local configuration. A monitored contact is pending for v6. |
| P10 | Add portable PostgreSQL backup and restore verification | Disposable recovery drill passed. Managed PITR, private Storage, Auth and cutover rehearsal are pending. |
| P10 | Add in-product help and a keyboard shortcut sheet | Fresh-account browser onboarding, empty Inbox, keyboard and mobile help checks |
| P10 | Add a public status page and installable PWA with an offline shell | Local HTTP probes and `tests/pwa.e2e.mjs` |
| P5 | Add workspace emoji policy and reaction limits to room messages and threads | Room reactions SQL and two-browser policy, cap and Realtime checks |
| P5 | Schedule profile status and mute, snooze or silence global and direct alerts | Quiet-hours SQL and two-browser settings and presence checks. Room-level notification settings remain open. |
| P5 | Add meeting media controls, chat, roster, private pin and host spotlight | Meeting collaboration SQL and two authenticated browser sessions with local LiveKit |
| P10 | Add audited feature rollouts and an emergency stop | Feature flag SQL and authenticator step-up browser checks for Release controls. The first flags cover tasks and recurring meetings. |
| P5 | Add room and channel quiet hours and suppress incoming call-end alerts | Quiet-hours SQL fixtures and two-browser tests across account, direct chat, room and workspace channel scopes |
| P5 | Manage visibility, ownership, membership and archives for rooms and workspace channels | Room and channel lifecycle SQL and browser tests, including private history restrictions for managers |
| P5 | Add saved room, sender, date, type, status, file and mention filters | Search SQL and integrated browser checks for all filters and saved value restoration |
| P10 | Journal existing audit changes and periodically verify and checkpoint the chain | Audit integrity SQL fixture covers edit, delete, chain corruption and a checkpoint held outside the database. Independent log retention for the hosted target remains open. |
| P5 | Suspend and restore workspace members and invite existing accounts from CSV | Workspace roster SQL and two-browser invitations, suspension and restoration |
| P5 | Route prioritized mentions for room posts and replies | Mention SQL and two-browser delivery, navigation and read state |
| P5 | Summarize missed incoming calls and room mentions in a private digest | Digest SQL and browser cases for both periods, links and permission changes |
| P5 | Adapt meeting video quality and recover from audio-only mode | Two-browser LiveKit test with simulated quality ratings and actual audio and video tracks |
| P9 | Score warnings locally and let verified staff propose rule or threshold evaluation | Feedback SQL and browser checks verified aggregate access, independent TOTP review and preserved warning feedback |
| P5 | Add member and workspace controls for presence privacy and Invisible mode | Presence privacy SQL and two-browser settings, policy and contact views |
| P5 | Add private typing controls to direct chats, rooms and threads | Typing SQL and two-browser checks for signal delivery, suppression and conversation isolation |
| P5 | Forward text between eligible direct chats and public rooms | SQL and browser checks for labels, restricted destinations, moderator policy and protection of source identity |
| P9 | Let workspace managers review possible executive and VIP impersonation | Unicode name comparison tests, SQL access and audit fixtures, and two-browser watch-list verification |
| P9 | Classify scam and phishing patterns locally in message warnings | Nine category fixtures, benign cases, and a browser-verified scam warning |
| P5 | Add workspace, room and account read receipt controls | Two browsers and permission SQL verified suppressed signals and preserved delivery |
| P5 | Detect repeat attachment content within the uploading account and direct chat | SQL and Edge verified same-byte detection, isolation, retry and independent authorization. Workspace, vault and earlier files remain open. |
| P3 | Add authenticator setup and one-time recovery codes | Browser and SQL verified enrollment, sign-in step-up, regeneration, reset and replay denial. Direct API assurance enforcement remains open. |
| P3 | Enforce source and browser asset secret checks and redact provider diagnostics | Unit checks and production asset scan, wired into the release validator |
| P5 | Synchronize account-private encrypted drafts across eligible conversations | Two-device browser and private SQL fixtures, including concurrent edits and clearing on send |
| P5 | Add notification preferences, priority, and admin-room delivery status | Per-category policy fixtures, live browser alert ordering, and recipient-acknowledged audit records |
| P5 | Add meeting pre-join checks and one-presenter screen sharing | Real local LiveKit and Edge with synthetic capture, GPU background processing, and permission revocation scenarios |
| P10 | Add a restricted tenant lookup and versioned member-count cache | Browser real TOTP and SQL verified metadata scope, count caching, TTL and roster invalidation |
| P10 | Stream delivery and usage metrics and show threat-reporting trends | SQL and real browser evidence for private hints, reconnect catch-up, completed weeks and suppressed cohorts |
| P5 | Allow case staff to redact a specifically reported, unchanged conversation message | Real TOTP browser and SQL tests for live removal, retained authorized evidence, and audit status |
| P10 | Add an English and Arabic locale scaffold with ICU messages | Locale unit tests and production browser checks on public and signed-in screens |
| P5 | Add workspace-wide mandatory notification categories and quiet caps | Tenant policy SQL and two browsers with existing notification preferences and quiet hours |
| P5 | Enforce direct-chat attachment budgets by plan and account policy | Concurrent reservation SQL and browser tests for normal uploads, quota rejection and secure download |
| P5 | Add live meeting host controls | Three-session LiveKit browser test passed. Replay of outstanding provider tokens remains open. |
| P5 | Add browser push enrollment and private payloads | VAPID provider contract, local queue tests and Chromium service-worker notification checks. Hosted scheduler and credentials are deployment prerequisites. |
| P10 | Measure aggregate API latency, errors and instance concurrency | Production-route tests and genuine staff MFA dashboard access |
| P10 | Collect coarse call and meeting quality metrics | Real direct WebRTC, LiveKit, staff dashboard MFA and privacy SQL tests |
| P5 | Add uploader access history for direct-chat files | Two-account browser and bounded access-history SQL checks. Tenant-level scope remains open. |
| P1 | Add workspace onboarding links with authenticated SMTP delivery | Local mail capture, separate Edge sessions and invite-expiry, domain, replay and seat fixtures |
| P5 | Add healthcare, education, finance and GDPR-style setup profiles | Workspace wizard browser and database tests verify effective room, admission and invite settings |
| P5 | Add bounded notification retries, dead letters and in-app fallback | SQL, loopback SMTP and browser verified Web Push and email failure paths, valid delivery, private in-app fallback, and consent revocation |
| P10 | Expand privacy-preserving call quality analytics | WebRTC and LiveKit audio quality samples, actual direct ICE restart offer, controlled relay percentages and verified staff dashboard |
| P5 | Add password-protected links for direct-chat attachments | Guest browser download and revocation, concurrent limits, source authorization and audit SQL |
| P5 | Add private opt-in email alerts and digests | Local SMTP and browser verified preference changes, cadence and unsubscribe for room mentions, tasks and missed calls |
| P5 | Add on-demand network diagnostics for calls | Edge and local Coturn verified STUN, UDP, TCP, TLS on 443 and a bounded relay bandwidth sample |
| P5 | Index and scope search for rooms, files, people, messages and tasks | Browser and SQL verify categories, phrase and fragment matching, navigation and access boundaries |
| P5 | Render safe attachment previews | Edge and isolated worker verified image and PDF rasterization, escaped text, deny paths and resource limits |
| P5 | Recover direct and scheduled calls without duplicating participants or call rows | Forced TURN restart, RTP recovery, Realtime socket replacement and live provider session reconnect |
| P5 | Soft-delete direct-chat attachments and purge bytes after a grace period | Edge, SQL and real private Storage verified access removal, grace, retries, evidence protection and quota recovery |
| P10 | Add idempotent, ordered worker claims and audited replay for notification queues | SQL, real staff TOTP browser, and push/email regressions |
| P10 | Preserve scoped workspace records under legal hold | Genuine TOTP, encrypted previous content, tenant and date boundaries, purge blocking and audited release |
| P5 | Schedule reversible archived-room deletion with a retention period | Role-scoped browser controls and SQL verification of grace, actual purge, hold and restore |
| P10 | Preserve direct attachment bytes on qualified holds | Genuine staff TOTP, independent assignment and overlap tests, real Storage purge after release |
| P10 | Send and export scheduled private operational reports | Browser and Mailpit verify identical suppressed CSV, proper role checks and pause |
| P5 | Remove redacted or deleted search results without exposing protected originals | Browser observed live removal under a hold and SQL verified encryption and scope |
| P10 | Add response targets and filters to the abuse moderation queue | Staff MFA, typed timer tests, normal review, reporter timeline and evidence redaction passed |
| P5 | Scan validated attachment bytes and support controlled quarantine review | Local ClamAV, real outage recovery, authenticated sender retry, staff step-up and audit |
| P10 | Manage workspace retention and scoped file preservation in their operator tabs | Separate role-verified browser gates and actual protected room and Storage purge checks |
| P5 | Record consented meeting audio and a selected camera | Actual isolated LiveKit Egress, playable OGG/MP4, exact tracks, private downloads and fail-closed discard |
| P10 | Verify visible audit rows and sign filtered workspace exports | Genuine MFA, database integrity checks, Edge file export and independent Ed25519 verification |
| P10 | Export anonymized daily and weekly security reports | Browser and API verified PDF and CSV, period boundaries and small-cohort suppression |
| P5 | Add expiring view-only attachment sharing and optional watermark | Browser and SQL verify safe guest pixels, original-byte denial, view limits, expiry, revoke and audit |
| P5 | Verify direct audio and video between isolated networks | Real Chromium endpoints with no direct transport and bidirectional RTP over disposable TURN |
| P10 | Add the MFA-gated Security overview | SQL and browser verify queue arithmetic, incident scope, privacy-safe trend and audited response times |
| P5 | Add bounded Office and compressed PDF inspection to the quarantine pipeline | Actual ClamAV worker and Edge verified clean files, scoped quarantine, benign macro/link/script markers and staff release |
| P5 | Add consent-based live captions and saved transcripts | Offline Faster Whisper and Edge verified real speech, correct speakers, rejoin consent, transcript access and withdrawal |
| P10 | Add scoped security incident workflow | Two verified staff browsers exercised linked report, responder assignment, status, timeline and postmortem |
| P5 | Verify attachment inspection across all six detection categories | Type mismatch, macro, script and link markers, archive budgets and local hash reputation passed with benign fixtures |
| P10 | Add private case notes, staff mentions and shared evidence links | Two TOTP browser sessions and SQL verify recipient-only alerts, audited evidence and reporter isolation |
| P5 | Add room classification and prevent in-app forwarding downgrades | Browser labels and strong authorization, SQL visibility floors, forwarding rules and audited changes |
| P10 | Add a role-scoped workspace overview | Browser and SQL verified health, plan seats, invitation alerts, adoption suppression and tenant boundaries |
| P5 | Draft scoped meeting summaries and action items | Browser verified approved source selection, redaction, editing, policy and withdrawal |
| P10 | Persist private generated exports under a separate lifecycle | Real Storage verified source reauthorization, exact bytes, expiry, retries and deletion |
| P10 | Route personal cases and consented workspace room reports through staff escalation | Edge and SQL verified stage assignments, real TOTP, private live alerts, scoped handoff, SLA deadlines, acknowledgment and reporting status |
| P10 | Add tenant-scoped workspace analytics | SQL and real MFA browser verified usage suppression, meeting quality, role boundaries and room security posture |
| P5 | Add guest meeting links with a host-controlled lobby | Browser and real LiveKit verified expiry, challenge rejection, owner approval, mic access and revocation. Hosted CAPTCHA still needs a configured domain. |
| P10 | Version workspace retention and notification policies with simulation and rollback | Edge and SQL verified scoped previews, stale change rejection, applied enforcement and restored settings |
| P5 | Resume direct attachment uploads after interrupted requests | Edge and local Storage verified offset replay, per-chunk and final checksums, scanner publication, and physical staging cleanup |
| P10 | Publish a versioned multi-currency billing catalog with grandfathered terms | Edge, SQL and a signed local webhook verified active offers, interval and currency controls, historical pricing and account scope |
| P5 | Offer room-only guest access for selected owner-authored posts | Edge and SQL verified link and credential expiry, no account privileges, blocked cross-room access, and revocation after edits or policy changes |
| P5 | Draft private, opt-in summaries of eligible room threads | Edge and local data verified role, per-author consent, scope, unsafe input filtering, and automatic invalidation after edits or withdrawal |
| P5 | Add timed direct text messages | Real Edge confirmed sender and recipient expiry, cached quote removal, bounded server policy and physical scrubbing. Task and thread regressions passed after restoring the current room-source rule. |
| P5 | Detect independently stored duplicate files within each workspace | Plural tenants and real Storage verified isolated byte fingerprints, existing-object backfill, rejection after removal and independent copies. |
| P10 | Export privacy-filtered traces, metrics, and correlated errors to a Collector | Official local Collector decoded all three signals and confirmed availability after interrupted export. |
| P4 | Finish secure password, email and authenticator change lifecycles | Real Mailpit and Edge verified email and authenticator delay, secure dual confirmation, immediate OTP recovery, and private device alerts |
| P10 | Add queue health and service objectives alongside dead-letter replay | Edge verified live backlog, operator verification, replay and readiness. SQL verified complete time windows and exact objective math. |
| P5 | Add permission-scoped access history for workspace files | Edge with two scopes and private Storage verified member access, audited owner policy, permitted admin history, revoked links and archival history |
| P4 | Enforce native account session management and rotation | Edge and the configured GoTrue sidecar verified scoped session listing, live revocation, idle and absolute limits, and strict stale-token family denial |
| P10 | Add two-party emergency access with one-time evidence and post-access review | Edge and SQL verified current owner approval, source consent, redaction boundaries, replay denial and auditable closure |
| P5 | Protect direct calls and fixed-roster meetings with browser media transforms and verification codes | Native Edge and real LiveKit verified encrypted Opus and VP8 in direct calls, three meeting participants, wrong-key denial, roster departure and managed meeting regression |
| P4 | Add authenticated device trust and public key bundles | Three Edge contexts verified native session binding, nonextractable private keys, signed bundles, remote blocking and independent device approval |
| P4 | Add remote browser revoke, lock and local-key wipe | Real Edge and SQL verified offline command state, targeted session revoke, IndexedDB key removal and interrupted receipt recovery |
| P5 | Add same-room Files and Calls tabs | Edge and real services verified private file transfer, scoped participant admission, room media and immediate client access loss |
| P5 | Enforce per-room contribution and call overrides | Exact Edge controls and database regressions verified role restrictions, live broadcast delivery, room-limited call hosting and permission changes |
| P10 | Add mobile public product pages and legal drafts | Edge verified touch navigation, live pricing, signup entry and all public routes. Operator approval for Terms and Privacy remains open. |
| P5 | Add group audio and video with automatic native mesh and LiveKit handoff | Five Edge browsers verified decoded media, continuity during failures in both directions, retry, and an audio-only fallback on camera denial |
| P4 | Alert trusted devices to suspicious sign-ins and lock the account on request | Native sign-in, two browser sessions, database isolation and Mailpit verified private alerts, controlled recovery and invalid revoked tokens |
| P10 | Add workspace-level feature pauses constrained by entitlements and global releases | Two-tenant Edge and SQL verified room tasks, recurring meetings, API key access, downgrades, scoped roles and the emergency global override |
| P10 | Publish an owner-managed Workspace API and signed webhook delivery | Production-mode Edge, SQL and a local receiver verified plan and key scope, private-room exclusion, pagination, limits, HMAC, backoff, history and revocation |
| P10 | Notify customers during time-boxed emergency access and post-access review | Edge verified real private Realtime alerts, durable read acknowledgment and exact evidence and access history for the current owner |
| P5 | Add encrypted direct voice notes with optional transcription | Two Edge browsers and a real isolated speech worker verified microphone, waveform, audio playback, opt-in transcript, access denial and physical purge |
| P4 | Add contact key comparison, QR and live change warnings | Real Edge and SQL verified symmetric signed keys, wrong-code handling, approved-key changes and scoped notifications |
| P4 | Require stronger proof for risky sign-ins | Real Edge, Mailpit and SQL verified uniform sign-in failures, protected operations, native TOTP, trusted-device proof and session invalidation |
| P5 | Add group chats with membership-triggered key rotation | Four Edge contexts and SQL verified signed messages, plan limits, approved device wraps, join history boundaries and removal |
| P4 | Score sessions before issuing app sign-in credentials | Chromium and SQL verified a signed test reputation provider, step-up, safe owner risk summaries and session revocation |
| P10 | Add scoped workspace user management and separate account operations | Edge and SQL verified scoped roles, suspension, fresh TOTP, independent reset approval, target notices and two-device sign-out |
| P10 | Guard extractive meeting summary drafts | Two Edge browsers, unit tests and SQL verified opt-in, output shape, prompt isolation and filtering of representative secrets and PII |
| P10 | Require a per-response script nonce, verify browser origins and harden the language cookie | Actual HTTPS Edge verified inline script blocking, UI hydration, voice worklet initialization, mutation boundaries and limited CORS. Signup and password recovery still passed. |
| P10 | Add local safety warnings and optional evidence reporting for encrypted groups | Four Edge contexts, network inspection and SQL verified metadata-only reporting by default, exact consented disclosure and private review |
| P10 | Run scoped isolation acceptance as one repeatable QA command | Seven rollback suites and nine Edge workflows verified role, tenant, storage, API, private Realtime and cache boundaries |
| P10 | Add global domain, file digest and network rules | Real Edge, file bytes and rollback SQL verified fresh operator proof, three rule types, enforceable existing surfaces, release and retained audit |
| P4 | Add account recovery keys and trusted-device approval | Chromium and SQL verified key issuance, revocation, signed device approval, private alerts, delay and native session and factor reset |
| P5 | Search previously opened encrypted group messages locally | Four Edge contexts and SQL verified encrypted indexing, metadata authorization, reload, account switching and removal on group revocation |
| P10 | Review and revoke an individual native session from a verified operator account | Edge and SQL verified scoped risk, reason audit, revoked-device sign-out and retained access on the second device |
| P5 | Queue, backfill and rebuild managed search indexes | Three Edge sessions, PostgreSQL cron and SQL verified authenticated queue controls, bounded processing, immediate source permission checks and live search |
| P4 | Enforce native authenticator assurance across data, Storage and Realtime | GoTrue, PostgREST, Storage, Realtime and Edge verified stale assurance denial and genuine TOTP, with existing recovery key and code compatibility |
| P10 | Manage registered account devices with separate revoke, block and wipe actions | Edge and SQL verified managed status, stale-media denial, signed offline wipe, retained audit and no re-registration using a blocked key |
| P10 | Add enforceable workspace AI policy, consent controls and transcript retention | Two Edge contexts, LiveKit, the local speech worker and SQL verified role scope, valid lease epochs, managed summary controls, immediate retention and scheduled purge |
| P4 | Add native WebAuthn passkeys and a passwordless-only setting | Chromium virtual authenticator, GoTrue and SQL verified scoped credentials, native sign-in, challenge replay denial, password-mode enforcement and restoration |
| P10 | Build separately approved, integrity-checked workspace compliance exports | Edge, SQL and Storage verified exact selected evidence, distinct owner approval, per-record and bundle hashes, live scope rechecks and access audit |
| P10 | Add an operator risk console with live fresh authenticator requests | Edge, GoTrue and SQL verified risky location filtering, targeted step-up, stale AAL2 denial, verified re-entry and audited termination |
| P10 | Add a versioned impersonation rule registry with shadow evaluation | Native Edge, SQL and an offline benchmark verified generation rules, aggregate synthetic disagreement, live promotion and rollback |
| P10 | Add a privacy-thresholded threat map and network aggregates | Edge and SQL verified coarse cells, five-account thresholds, distinct account counting, ASN summaries, date and event switches, and authorized display |
| P4 | Require fresh native proof before sensitive actions | Edge, HTTP and SQL verified stale proof denial and genuine step-up before room roles, reports, audit and integration keys, plus the billing entry gate |
| P10 | Apply local safety thresholds and explicit priority reporting | Two Edge sessions, real local attachment quarantine and SQL verified warning, defanging, reveal, consented reporting and MFA-only human review |
| P10 | Add a behavior advisory with opt-in browser linkage | Edge and SQL verified live activity counts, decayed reviewed findings, dual browser proofs, withdrawal and MFA-only aggregate review |
| P10 | Bound streamed input and preserve exact webhook verification | Local Stripe and LiveKit signing fixtures, direct HTTP, Edge and unit tests verified byte limits, UTF-8, file handling, output defenses and destination restrictions |
| P4 | Enforce risk-adaptive token buckets on authentication and files | Chromium, HTTP and SQL verified atomic limits, independent user, network, device and workspace scopes, generic failures and refill |
| P10 | Preserve approved room evidence under a workspace legal hold | Real Edge, private Storage and SQL verified immutable bytes, SHA-256, chained custody, authorization changes and bounded cleanup |
| P4 | Add adaptive signup proof and native admission enforcement | Chromium, Mailpit, GoTrue and SQL verified ordinary email signup, suspicious-context proof, native bypass denial and replay rejection |
| P10 | Complete human review for assigned workspace abuse reports | Three browsers and SQL verified reassignment, reasoned closure, minimal reporter status and escalation to separate Platform reviewers for severe cases |
| P10 | Enforce workspace text data loss rules through rooms and channels | Two Edge sessions and SQL verified policy authorization, draft retention, warning confirmation, delivery prevention, managed redaction and scoped edits and forwarding |
| P10 | Manage structured detection rule versions in Safety | Real application metrics, Edge and SQL verified historical tests, shadow, enable, pause, rollback and review-only matches |
| P10 | Inspect explicitly submitted links in an isolated worker | Edge, local HTTPS fixtures, unit tests and SQL verified normalization, bounded redirects, signed intelligence and fail-closed destination checks |
| P10 | Generate the permissions catalog from HTTP and native database interfaces | Browser and SQL verified positive and denied role paths, and drift checks inventoried 80 HTTP methods and 435 native signatures in integrated QA |
| P10 | Triage automated detections and attachment signals through a scoped threat queue | Four browser roles and SQL verified filters, shadow suppression, whole-batch denial, revision checks and reasoned audit |
| P9 | Pin billing entitlements to purchased plan versions | Browser and SQL verified live downgrade on expiry, atomic public offers, and exact workspace, seat, file and workspace API limits |
| P10 | Evaluate and explain managed file egress requirements | Edge and SQL verified versioned owner policy, six trusted attributes, denied and allowed private downloads, scoped explanations and tenant isolation |
| P10 | Deliver signed workspace SIEM digests | Browser, SQL and isolated collectors verified redacted hourly counts, webhook, TLS syslog/CEF, S3 SigV4, retry and replay protection |
| P10 | Run versioned SOC playbooks after separate human approval | Browser and SQL verified an actual queue transition, checklist completion, a distinct reviewer, stale revision denial and replay-safe audit |
| P5 | Render sanitized Markdown and scoped link previews | Managed and encrypted Edge conversations verified live rendering, safe edits, opt-in checks and no encrypted URL disclosure |
| P9 | Offer a single 14-day Professional or Business trial per workspace | Browser, signed local provider fixtures and SQL verified both card configurations, owner scope, retries and automatic expiry |
| P9 | Meter workspace recording, transcription, storage and file inspection usage | LiveKit Egress, Faster Whisper, private Storage, Edge and SQL verified real usage, period totals, retry deduplication and tenant-scoped access |
| P4 | Manage organization identity and defaults | Edge, a local TXT resolver and SQL verified branding, verified domain lifecycle, enforced hold-aware retention and separately persisted region preference |
| P9 | Reconcile signed payment events and stored subscriptions | Local provider contracts and SQL verified bounded replay and retry processing, event order, customer scope and scheduled reconciliation |
| P10 | Manage organization invitation email templates | Edge, real Mailpit delivery and SQL verified native assurance, preview parity, immutable versions, rollback and recipient denial |
| P4 | Add enforceable Healthcare defaults and exact emergency review | Local Edge and SQL verified confidential controls, managed identifier blocks, genuine operator and owner approval, private alerts and single-use evidence |
| P9 | Delegate workspace billing reads to an explicit billing administrator | Browser, SQL and local Stripe contracts verified grant and revoke, tenant and owner scopes, paid or trial entitlements and provider redaction |
| P4 | Establish consented managed accounts in Family and School workspaces | Edge and SQL verified scoped supervisor authority, allowed and denied new contacts, coarse device counts and revocation without content disclosure |
| P9 | Download finalized invoice and payment receipt copies | Browser, SQL and local Stripe contracts verified exact sequence and tax, authorized PDF bytes, expired ticket denial and live revocation |
| P4 | Add the Family oversight dashboard and safe-sharing defaults | Edge and SQL verified guardian and participant controls, coarse trusted-device state, link issuance and redemption protection and preserved private access |
| P10 | Route explicitly consented channel message reports to Safety | Native Edge and SQL verified exact evidence, separate platform and workspace review, severe-report scope and two private live reporter updates |
| P10 | Require separate approval for scoped SOC actions | Edge and SQL verified exact evidence consent, live room and channel tombstones, encrypted-group protection, private file withdrawal, link rules, account/device actions and retained evidence |
| P4 | Add School classes, scoped teachers and supervised rooms | Four Edge roles and SQL verified class membership, posting, revocation, forwarding and guest restrictions and independently consented contact rules |
| P9 | Process failed renewals and recovery through authenticated billing workers | Local provider, Mailpit, Edge and SQL verified staged retries, one verified mailbox notice, stable grace and paid or canceled reconciliation |
| P9 | Enforce post-grace workspace read-only operation | Edge, signed local provider events and SQL verified denied posting, files and tasks, preserved private reads and authorized export, and immediate payment recovery |
| P4 | Add a scoped custom role editor with trusted attributes | Edge and SQL verified directory, room and managed file permissions, policy precedence, live revocation and concurrent revision handling |
| P9 | Open actor-bound hosted subscription portal flows | Edge, SQL and local Stripe contracts verified payment, plan, invoice and tax flows plus cancellation, reactivation and foreign-provider denial |
| P10 | Manage eight native policy areas with preview and version rollback | Edge and SQL verified real owner controls, previews without side effects, native enforcement and exact historical restoration |
| P9 | Apply versioned promotion codes in hosted checkout | Edge, local Stripe and SQL verified fixed and percentage terms, bounded redemption, no stacking, signed expiry, paid settlement and reconciliation |
| P5 | Upload and receive browser-encrypted group attachments | Edge and SQL verified two approved browsers, outsider and signed-link denial, content authentication, native quota and atomic publication |
| P5 | Transfer encrypted group history to an approved browser | Edge and SQL verified native step-up, source signature, actual receiver decryption and scope and replay protection |
| P11–P13 | Full verification and production promotion | The release gate remains closed while registry entries and required verification are open |

See the branch history for slice commits.

This local checkpoint covers 217 verified features and 22 pending. The next checkpoint is due at 227 verified features.

## Remaining work by dependency

The [feature matrix](FEATURE_MATRIX.md) is the task list. Each of its 19 module prefixes belongs to one implementation phase below. Dependencies can be built in earlier phases, and a feature row becomes DONE after its own tests pass.

| Phase | Modules | Evidence needed before closing |
| --- | --- | --- |
| Identity and access | AUTH, SEC, ORG | Session and permission tests, tenant isolation, provider-backed identity and cryptographic lifecycle checks |
| Collaboration | MSG, THR, ROOM, PRES, TASK, SRCH | Two-account live workflows, membership changes, scoped search, offline recovery and cross-tenant denials |
| Delivery and media | NOTIF, FILE, CALL | Reliable delivery and retry tests, attachment scanning and retention, cross-network media and recording checks |
| Commerce | BILL | Test-provider checkout, webhooks, billing reconciliation, entitlement and tax cases |
| Safety and governance | AI, ADM, SOC, PLT, ANL | Human review, role-specific consoles, classifier evaluation and aggregate data isolation |
| Platform | PLAT | Build and infrastructure verification, accessibility, load, telemetry and recovery checks |

Publishing the GitHub release and deploying a separate Vercel production project require every matrix entry to be DONE. V5 is the production baseline while the candidate is being verified.
