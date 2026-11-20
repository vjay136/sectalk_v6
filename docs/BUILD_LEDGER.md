# V6 build ledger

| Phase | Slice | Evidence |
| --- | --- | --- |
| P0 | Inventory the release target, environment names, and existing v5 behavior | `npm run preflight`, GitHub repository lookup, Vercel v5 project inspection |
| P1 | Extract and validate the 239 IDs | `features.md`, `docs/FEATURE_MATRIX.md`, `npm run verify:registry` |
| P2 | Add an anonymous readiness probe with a database marker | `tests/readiness.test.mjs`, `tests/v6-database.sql` |
| P5 | Add a private Saved messages view and a permission-scoped Files tab | `tests/v6-database.sql`, local two-account browser and storage checks |
| P11–P13 | Full verification and production promotion | The release gate remains closed while registry entries and required verification are open |

See the branch history for slice commits.
