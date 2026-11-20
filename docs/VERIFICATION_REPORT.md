# V6 candidate verification

## Completed checks

| Check | Result |
| --- | --- |
| Feature registry structure | 239 unique IDs across 19 modules, with matching matrix rows |
| Clean source snapshot | `npm ci`, registry verification, unit tests and production build passed on commit `5fe30cd`. The Windows npm launcher reported Node 26 for dependency installation despite Node 24 being first on the test shell's path. |
| Unit tests | 11 passed, including readiness failure handling, safety heuristics, vault authentication, emoji data and disclosure configuration validation |
| Supabase database integration | All 9 rollback suites passed, including room isolation, membership and moderation, private saved searches, thread preferences, scoped tasks and meeting lobby admission |
| Readiness and status | Local health, readiness and JSON status returned healthy results. The public status page rendered the same database check. |
| Two-browser chat | Direct messaging, custom reaction synchronization and removal, Find Friends navigation passed |
| New UI | Saved-message creation and removal, filename and direction filters, and authorized ZIP download passed |
| Rooms and searches | Two browser sessions verified room creation, joining, live posts, reply counts and follow/unfollow. Member audit access was denied. Saving, running and deleting searches passed. |
| Scoped tasks | Two browser sessions verified room and direct-chat task flows, list, board, agenda, month grid, linked sources, assignment, watching, audit, live completion notices and mark-read. SQL verified private reminders and source deletion. The local scheduler recorded a successful reminder job run. |
| Notification center | Two browser sessions verified live delivery, separate Meetings and Task updates groups, and notifications moving out of Unread after marking them read. |
| Command palette and search snippets | Browser verified Control and Meta shortcuts, arrows and Enter, Escape and focus restoration, navigation, saved messages, authorized search, literal highlighting and live removal of a revoked result. SQL verified API-level access restrictions and private hiding. |
| Vulnerability disclosure | The candidate returned a matching disclosure page and UTF-8 `security.txt` with a configured test contact. Unconfigured mode returned 503 for `security.txt` and withheld a reporting link. A monitored deployment contact remains pending. |
| Meeting lobby | Two browser sessions verified the waiting-room state and host-only Admit all action. SQL verified individual decline, oldest-first bulk admission, capacity, isolation and audit. Using synthetic signing credentials, the local token route returned 403 before admission and a room-scoped token afterward. No media stream was required for this check. |
| PWA | A fresh persistent Chromium profile reported zero installability errors. A mobile viewport, icon size, public-only cache, offline navigation and reconnect passed. |
| Updated candidate | `npm run build` passed after the rooms, search, status, PWA and thread changes. |
| Real Storage | Upload, authorized download, revoke, private profile photos and blocking passed |
| Local Auth and mail | Signup link delivery, passive link preview, confirmation, replay rejection, recovery OTP and password replacement passed |
| Production npm dependency advisory check | 0 reported advisories at test time |
| Prior production deployment | Existing v5 health route returned configured and version 5.0.0 |

Browser and storage tests used local Supabase, local test accounts, and a local mail inbox. The v6 migration was tested in that isolated database.

## Release gate

The structural registry check passed with 28 of 239 rows marked DONE. The production release check blocks promotion while feature rows are unfinished. Full provider integration, accessibility, network failure, load, backup recovery, and separate admin and worker deployment checks are pending. External setup is tracked in the [deployment report](DEPLOYMENT_REPORT.md). The [feature matrix](FEATURE_MATRIX.md) records feature-level evidence.
