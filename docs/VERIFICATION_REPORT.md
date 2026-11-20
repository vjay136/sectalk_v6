# V6 candidate verification

## Completed checks

| Check | Result |
| --- | --- |
| Feature registry structure | 239 unique IDs across 19 modules, with matching matrix rows |
| Clean source snapshot | `npm ci`, registry verification, unit tests and production build passed on commit `5fe30cd`. The Windows npm launcher reported Node 26 for dependency installation despite Node 24 being first on the test shell's path. |
| Unit tests | 14 passed, including file type and ticket checks, calendar export, readiness, safety heuristics, vault, emoji data and disclosure configuration |
| Supabase database integration | All 28 rollback suites passed, including workspace and room policies, message ordering and edit privacy, media ownership, meeting engagement and aggregate analytics |
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
| Local database security advisor | No warning or error reported for the isolated candidate at test time. |
| PWA | A fresh persistent Chromium profile reported zero installability errors. A mobile viewport, icon size, public-only cache, offline navigation and reconnect passed. |
| Updated candidate | `npm run build` passed after the rooms, search, status, PWA and thread changes. |
| Real Storage | Upload, authorized download, revoke, private profile photos and blocking passed |
| Local Auth and mail | Signup link delivery, passive link preview, confirmation, replay rejection, recovery OTP and password replacement passed |
| Production npm dependency advisory check | 0 reported advisories at test time |
| Prior production deployment | Existing v5 health route returned configured and version 5.0.0 |

Browser and storage tests used local Supabase, local test accounts, and a local mail inbox. The v6 migration was tested in that isolated database.

## Release gate

The production release check blocks promotion while feature rows are unfinished. Full provider integration, accessibility, network failure, load, hosted recovery, and separate admin and worker deployment checks are pending. External setup is tracked in the [deployment report](DEPLOYMENT_REPORT.md). The [feature matrix](FEATURE_MATRIX.md) records feature-level evidence, and `npm run verify:registry` reports the current counts.
