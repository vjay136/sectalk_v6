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
| P10 | Add public vulnerability disclosure routes and repository reporting guidance | Unit and production HTTP tests passed with local configuration. A monitored contact is pending for v6. |
| P10 | Add portable PostgreSQL backup and restore verification | Disposable recovery drill passed. Managed PITR, private Storage, Auth and cutover rehearsal are pending. |
| P10 | Add a public status page and installable PWA with an offline shell | Local HTTP probes and `tests/pwa.e2e.mjs` |
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
