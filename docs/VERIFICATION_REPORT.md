# V6 candidate verification

## Completed checks

| Check | Result |
| --- | --- |
| Feature registry structure | 239 unique IDs across 19 modules, with matching matrix rows |
| Clean source snapshot | The staged 157-feature snapshot passed a production build on checksum-verified Node 24.22.3, source and browser secret checks, and the production dependency audit. The staged app passed Edge tests for public mobile navigation, trusted device and contact key verification, signed workspace integrations, and emergency access against the local QA backend. |
| Unit tests | 36 passed, including webhook transport, document heuristics, attachment MIME handling, export payloads, SMTP, VAPID and readiness. |
| Supabase database integration | A fresh local Supabase project installed the exact staged migrations and passed all 101 rollback suites. |
| Readiness and status | Local health, readiness and JSON status returned healthy results. The public status page rendered the same database check. |
| Two-browser chat | Direct messaging, custom reaction synchronization and removal, Find Friends navigation passed |
| New UI | Saved-message creation and removal, filename and direction filters, and authorized ZIP download passed |
| Rooms and searches | Two browser sessions verified room creation, joining, live posts, reply counts and follow/unfollow. Member audit access was denied. Saving, running and deleting searches passed. |
| Scoped tasks | Two browser sessions verified room and direct-chat task flows, list, board, agenda, month grid, linked sources, assignment, watching, audit, live completion notices and mark-read. SQL verified private reminders and source deletion. The local scheduler recorded a successful reminder job run. |
| Notification center | Two browser sessions verified live delivery, separate Meetings and Task updates groups, and notifications moving out of Unread after marking them read. |
| Command palette and search snippets | Browser verified Control and Meta shortcuts, arrows and Enter, Escape and focus restoration, navigation, saved messages, authorized search, literal highlighting and live removal of a revoked result. SQL verified API-level access restrictions and private hiding. |
| Vulnerability disclosure | The candidate returned a matching disclosure page and UTF-8 `security.txt` with a configured test contact. Unconfigured mode returned 503 for `security.txt` and withheld a reporting link. A monitored deployment contact remains pending. |
| Meeting lobby | Two browser sessions verified the waiting-room state and host-only Admit all action. SQL verified individual decline, oldest-first bulk admission, capacity, isolation and audit. Using synthetic signing credentials, the local token route returned 403 before admission and a room-scoped token afterward. No media stream was required for this check. |
| Call history | SQL verified participant-only outcomes for missed, declined, cancelled and answered calls. Two local browsers with simulated devices verified the Missed tab and a video callback from history through ringing and decline. Cross-network audio and video still require their provider tests. |
| Scheduled messages | SQL verified sender-only access, cancellation, retries, delivery-time block enforcement and one message on repeated dispatch. The local cron job delivered a scheduled message to a second browser and changed outbox history to Sent. |
| Reply quotes | SQL verified caller visibility checks and denial of new replies to hidden or revoked sources. Both browsers showed a quote, then removed its original text after revocation and preserved the reply. |
| Instant meetings | SQL and two browsers verified immediate host entry, private notices, member waiting and admission, and one meeting and one notification after concurrent retries. |
| Database recovery | The isolated Docker drill verified a custom-format PostgreSQL archive and SHA-256 manifest, restored data and row policies, ran read-only assertions, and rejected a corrupt archive or invalid destination. Hosted recovery is pending. |
| Direct-chat pinning | Two browsers verified live pin and unpin. SQL verified authorization, hidden and revoked source denial and cleanup on revocation. |
| Audit search | SQL verified workspace admin authorization, private room and tenant isolation, and search filters. The browser verified a room audit result and showed no audit tab to a workspace member. |
| Room templates | SQL and two browsers verified all four templates with starter pins, visibility defaults, Class slow mode and idempotent creation. |
| Contact presence | SQL and two browsers verified all four availability states, heartbeat throttling, expiry, and permission changes when a contact is blocked. |
| Onboarding and help | A fresh account completed profile and discovery setup. The browser verified the empty Inbox, the Help tab, keyboard shortcuts, help links, and mobile access. |
| Recurring meetings | SQL verified recurrence across a daylight-saving change and retry and role checks. Browser verified a weekly series and downloaded three calendar events. A linked occurrence opened in a member session and the same link disclosed no meeting details to an outsider. |
| Room thread integrity | Two browsers verified that edit and redaction retain replies, counts and follows. SQL checked author deletion, moderator authorization, removal of pins, and hiding both copies of a linked task source. |
| Workspace switcher | Two-browser and SQL checks covered workspace-bound views, invitations, permissions, meeting links, immediate account-scoped membership invalidation and sign-out isolation. |
| Message delivery | Two browsers verified queued, failed, same-ID retry, sent, delivered and read. SQL exercised private acknowledgment constraints and idempotency. |
| Offline message queue | Browser verified encrypted storage, persistence across reload and account switches, replay with the same IDs, reply linkage, blocked retry, and isolating an unreadable entry while other messages continued. |
| ICE credential leases | Browser and SQL verified per-call signing, distinct participants, bounded expiry, renewal and denial for ineligible callers with simulated TURN settings. Cross-network relay remains pending. |
| Signed attachment downloads | The local app issued and redeemed user-bound 30-second links, rechecked access, logged retrieval and rejected a stale link after revocation. Unit tests exercised the expiry boundary and tampering. |
| Attachment type policy | Unit and browser checks verified agreement between extension, requested MIME and stored bytes. The normal composer published an approved file. The API rejected a renamed text file and the database denied raw publication. |
| Workspace directory | SQL and two browsers verified groups, teams and departments, assignment, audit, archive and restore, membership cleanup and tenant isolation. |
| Typed workspace onboarding | Browser verified the wizard, persisted Family policy, restricted room options and individual admission. SQL verified standard and restricted defaults, role enforcement, quota, audit and legacy compatibility. |
| Direct message ordering | SQL and browser checks verified legacy backfill, equal-time ordering, concurrent deduplication, and recovery across 120 missed messages with ordered pagination. |
| Incoming call ownership | Three local browser contexts exercised a competing answer, a losing device, busy, decline and caller cancellation. SQL verified ownership of ICE, signaling and hangup. Synthetic TURN settings were used. |
| Meeting interactions | Two browsers verified realtime hand changes and the expiry of a reaction after eight seconds. SQL verified waiting and outside attendee denial, cross-meeting isolation, and leave and readmission cleanup. |
| Safety warnings | Browser verified tentative language, a specific reason, report review with the original message, dismissal and a fresh warning after edit. |
| Message delivery latency | SQL verified p50, p95 and p99 calculations, small-cohort suppression and MFA gating. Browser used a real TOTP challenge in isolated Supabase to open the metrics view. |
| Message edit privacy | SQL and two browsers verified the edit window, per-author sharing, raw history denial, edited markers and removal of open revision history after redaction or a privacy change. |
| Product usage | SQL verified rounded aggregate counts and suppression for a single contributor. The browser reached the aggregate-only view after authenticator step-up. |
| Room reaction policy | Two accounts tested a live policy change, reaction on a thread reply, the reaction cap and removal after the policy was disabled. SQL verified tenant isolation and reaction access after deletion. |
| Scheduled presence and direct alerts | Two accounts tested scheduled status, Busy and Online transitions, direct chat muting and snoozing, and incoming call alert suppression. SQL verified time zones, overnight boundaries and schedule privacy. Room-level notification settings remain open. |
| Meeting collaboration | Two authenticated browsers used a local LiveKit server and synthetic devices to verify audio and video tracks, mute and camera changes, live roster and chat, private pin and host spotlight. SQL and browser checks covered waiting and departed participants. |
| Staged feature release | SQL verified stable rollout cohorts, account and workspace precedence, audited changes, MFA and role checks, and enforced emergency stop for both capabilities. A browser performed authenticator step-up and exercised rollout changes and the emergency stop. |
| Conversation quiet hours | Two browsers verified mute, snooze and schedules in direct chats and rooms, channel alert suppression, notification scope, and incoming call alert suppression. SQL verified room and channel isolation, global suppression and continued message delivery. |
| Room and channel management | Browser and SQL checks covered changing visibility, explicit private membership, ownership transfer, archive and restore, posting restrictions and audit scope. Managers without private membership could manage metadata while message reads remained restricted. |
| Search filters | SQL checked permissions and filter semantics. The browser verified room, sender, dates, type, status, has-file, mentions and saved filter restoration. |
| Audit integrity | SQL checked the SHA-256 journal, hourly verifier configuration, source-row changes, cascades, and rewind detection with an independently held digest. A hosted destination for independent receipt retention is pending. |
| Workspace membership | Browser verified bulk invitations for existing handles and workspace access disappearing and returning after a member was suspended and restored. SQL verified role and workspace isolation. |
| Room mention priority | SQL and browser verified eligible recipients, quiet-hour filtering, direct mention priority, live delivery, read state and room links. |
| Missed-call and mention digest | SQL verified recipient scope, room access removal and period boundaries. Browser verified the 24-hour and seven-day views and navigation to room and chat. |
| Meeting network adaptation | Two browsers exchanged media over a real loopback LiveKit server while the test injected poor and recovered quality signals. The test verified lower video quality, continuous audio, and pause and resume of incoming and outgoing video. Impaired WAN and physical devices remain unverified. |
| Warning score and feedback | Unit and browser tests verified score, confidence, severity and the feedback payload. SQL verified cohort scope, proposal limits and review permissions. Two separate staff accounts completed TOTP before submitting and approving a proposal. |
| Read receipt controls | SQL and browser verified user, workspace and room settings. Direct-chat delivery remains visible, and room authors see eligible aggregate counts. |
| Duplicate attachment checks | SQL and browser verified identical bytes, concurrent publication, isolated sender and conversation authorization, and independent Storage objects. Coverage is for new personal direct uploads. |
| Account authenticators | Local SQL and browser verified TOTP enrollment and sign-in, hashed one-time codes, rotation, and recovery with session revocation. Hosted Auth schema compatibility and direct API assurance are still open. |
| Secret hygiene | Unit tests verified rule-only findings and redacted provider diagnostics. The local production artifact scan checked browser environment keys, recognized credentials and configured server-only values. |
| Presence privacy | Browser and SQL verified account visibility, Invisible, workspace-required disclosure, legacy preference preservation, and no hidden-presence disclosure through contact feeds or room mentions. |
| Typing indicators | Browser verified direct and room-thread indicators and opt-out. Database tests verified separate conversations and threads, limits, expiry, blocks, timeouts and outsider denial. |
| Message forwarding | SQL and browser verified live forwarded text and labels, same-workspace room policy, denied restricted destinations and sources, and no copied author identity or mention notification. |
| Impersonation watch | SQL verified manager-only access and audited changes. Browser verified adding a VIP, seeing a possible lookalike in the workspace roster, and removing the watch entry. |
| Scam classification | Unit fixtures exercised nine categories, benign texts and normalization. The browser displayed a job-scam warning, its reasons and rule confidence and verified the previous feedback payload stayed unchanged. Rules are English-only and indicate possible matches. |
| Locale scaffold | Browser verified English and Arabic switching and persistence across reload, preserved form input, mobile signed-in navigation and the Help shortcut count. Unit tests exercised all six Arabic ICU plural forms. |
| Local database security advisor | No warning or error reported for the isolated candidate at test time. |
| PWA | A fresh persistent Chromium profile reported zero installability errors. A mobile viewport, icon size, public-only cache, offline navigation and reconnect passed. |
| Encrypted drafts | Two sessions verified private synchronization, reload restore, conflict resolution and clearing after send. SQL verified encrypted storage, account and thread isolation and stale-save denial. |
| Notifications | Browser and SQL verified category persistence, mandatory priority, alert ordering, and real browser acknowledgments in the admin-room audit. |
| Meeting preview and presenting | Loopback LiveKit and Edge verified media devices, real GPU background blur, network checks, single-presenter claims and permission-loss cleanup. Native capture selection was simulated. |
| Tenant operations and cache | Real TOTP and SQL verified metadata-only permissions, TTL, version and tenant isolation, and invalidation on roster updates. |
| Analytics | Edge and local cron verified minute-based delivery and usage refresh and WebSocket recovery. SQL and browser tested rounded weekly threat-reporting and enforcement counts. |
| Workspace invitations and profiles | Local SMTP and Edge verified single-use emailed invitations, role and recipient limits, and manual link sharing. SQL and the browser verified four available presets and effective meeting, room and invite controls. |
| Attachment quota and guest links | Browser and SQL verified upload limits, concurrency, password checks, guest bytes, link revocation and access history. Attachment scope is personal direct chats. |
| Push and email fallback | Browser, Mailpit, database and provider fixtures verified consent, encrypted version-only push, subtype and cadence selection, generic private fallback for both channels, retry and unsubscribe. |
| Staff metrics and QoS | Genuine TOTP protected aggregate metrics. Client and server tests measured request latency and concurrency, real call setup and audio quality, and a direct ICE restart. Relay rate used controlled fixtures. |
| Meeting moderation | Three local browsers verified co-host, mute, lock, removal, communication restrictions and ending a call. Self-hosted provider token replay remains open. |
| Network diagnostics and call recovery | Edge and isolated Coturn verified UDP, TCP and TLS relay checks, then restored an active real call after TURN and signaling disruption. LiveKit preserved the attendee during signaling resume. |
| Attachment processing | Edge, real private Storage and a separate worker verified safe image/text/PDF preview, delete access revocation, purge grace and physical bytes removal. |
| Search and governance | Browser verified phrase and partial searches, protected files and room navigation, real TOTP, private hold status, scheduling and room restore. SQL verified no early purge, hold precedence, encrypted preservation, and audited release. |
| Abuse queue and signed audits | A clean Edge build verified genuine TOTP, report timer filters, review and reporter progress, and Ed25519-signed audit downloads. Database fixtures denied other tenants and detected a changed audit row. |
| Protected file rendering and review | ClamAV and real private Storage verified scanner outage quarantine, clean re-scan, staff review and sender retry. Clean Edge verified password-protected guest rendering with a pixel watermark and denial of original-byte retrieval from view-only links. |
| Meeting recordings | Disposable LiveKit Egress encoded real synthetic audio and single-camera video. Both outputs decoded in Edge. Consent, exact tracks, withdrawal, camera loss, late joins and private download boundaries passed. |
| Reports | A local Mailpit inbox received privacy-suppressed scheduled CSV, and the browser exported the identical file. Clean Edge and the protected export API passed daily and weekly PDF and CSV checks. |
| Direct voice and video | Separate isolated Chromium networks used real forced TURN and exchanged two-way audio and video through Inbox and Calls. WAN carriers were outside the test. |
| Live captions | Real offline Faster Whisper transcribed both synthetic English speakers with correct labels. Edge verified saved transcripts, rejoin consent, withdrawal and wrong-speaker denial. |
| Case and workspace operations | Clean Edge verified real native MFA, scoped assignments, case mentions and evidence links, classification and room state, seats and readiness. |
| Office and compressed PDF inspection | The updated isolated ClamAV pipeline and clean Edge candidate verified document structure, mismatch denial, bounded archives, macro and embedded-link quarantine, known hashes and authorized release. |
| Workspace governance, escalation and guest access | Edge and SQL verified policy simulation and rollback, scoped workspace analytics, personal and consented room escalation with real TOTP, room-only guest leases, and real lobby-approved LiveKit guest media. Hosted CAPTCHA remains a setup and acceptance item. |
| Billing, resumable uploads, private exports and draft summaries | Edge verified scheduled multi-currency pricing and grandfathered terms through HTTP and SQL, resumable bytes and cleanup using real local Storage, scoped private export artifacts, and consent-gated meeting and room summaries. Stripe checkout in a provider sandbox remains open. |
| Account lifecycle, emergency access and operations | Exact staged Edge verified signup link and numeric recovery OTP, another device receiving a security alert, delayed account changes, device trust, owner-approved one-time evidence, file history, queue replay and timed expiration. Native encrypted direct and three-person meetings passed in Edge with a local media provider. |
| Updated candidate | `npm run build` passed with synchronized drafts, private notification controls, media checks and scoped analytics. |
| Real Storage | Upload, authorized download, revoke, private profile photos and blocking passed |
| Local Auth and mail | Signup link delivery, passive link preview, confirmation, replay rejection, recovery OTP and password replacement passed |
| Production npm dependency advisory check | 0 reported advisories at test time |
| Prior production deployment | Existing v5 health route returned configured and version 5.0.0 |

Browser and storage tests used local Supabase, local test accounts, and a local mail inbox. The v6 migration was tested in that isolated database.

## Release gate

The production release check blocks promotion while feature rows are unfinished. Full provider integration, accessibility, network failure, load, hosted recovery, and separate admin and worker deployment checks are pending. External setup is tracked in the [deployment report](DEPLOYMENT_REPORT.md). The [feature matrix](FEATURE_MATRIX.md) records feature-level evidence, and `npm run verify:registry` reports the current counts.
