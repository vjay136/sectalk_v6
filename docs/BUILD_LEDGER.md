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
| P9 | Score message warnings on-device and collect privacy-preserving feedback | Safety unit and browser tests, aggregate review SQL and TOTP browser access. Rule and threshold proposal workflows remain open. |
| P5 | Add member and workspace controls for presence privacy and Invisible mode | Presence privacy SQL and two-browser settings, policy and contact views |
| P5 | Add private typing controls to direct chats, rooms and threads | Typing SQL and two-browser checks for signal delivery, suppression and conversation isolation |
| P5 | Forward text between eligible direct chats and public rooms | SQL and browser checks for labels, restricted destinations, moderator policy and protection of source identity |
| P9 | Let workspace managers review possible executive and VIP impersonation | Unicode name comparison tests, SQL access and audit fixtures, and two-browser watch-list verification |
| P9 | Classify scam and phishing patterns locally in message warnings | Nine category fixtures, benign cases, and a browser-verified scam warning |
| P10 | Add an English and Arabic locale scaffold with ICU messages | Locale unit tests and production browser checks on public and signed-in screens |
| P11–P13 | Full verification and production promotion | The release gate remains closed while registry entries and required verification are open |

See the branch history for slice commits.

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
