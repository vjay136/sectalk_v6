# SecTalk disaster recovery

Use a recovery environment dedicated to v6. Record the selected backup time, recovery start and finish, and verification results outside the incident’s affected system. Compare the data loss window and elapsed recovery time with the agreed recovery point and recovery time objectives before cutover.

## Portable database backup

Install `pg_dump`, `pg_restore`, and `psql` for your database major version. Configure an explicit libpq service for the backup source and use a protected password file outside the checkout. Use an encrypted backup location with permissions limited to the backup and recovery operators. The destination directory for a new archive must be absent.

```sh
node scripts/disaster-recovery.mjs backup --service sectalk_backup_source --archive /protected/sectalk/backup-id
```

The job writes a PostgreSQL custom-format dump and a SHA-256 manifest. The dump may contain private messages, user records, and other sensitive data. Store both artifacts together in restricted, immutable storage. Record provenance separately. The checksum detects changed bytes and depends on trusting the manifest. Publication and subscription definitions and the data in the `pg_cron` job tables are omitted. Keep approved extensions, roles, and operational job definitions available separately.

## Restore verification job

Provision a fresh database from `template0` on an isolated PostgreSQL instance with outbound networking disabled. Use a `sectalk_restore_*` database name. Prepare the source roles and required server extensions in advance. Keep credentials in a protected password file. Use a trusted assertion file that raises an error if a recovery check fails. Keep its output free of customer data.

```sh
node scripts/disaster-recovery.mjs verify --archive /protected/sectalk/backup-id --database sectalk_restore_drill --port 55443 --user recovery_operator --assert /protected/sectalk/restore-checks.sql
```

The verification job connects only to a loopback listener or a network-disabled, labelled Docker container. It rejects a populated target and checks the archive against its manifest before the restore. Restore writes run in one transaction. Assertions run in a read-only transaction after the restore. A failed assertion leaves the restored copy available for private investigation and returns a nonzero status. Use a fresh target for a retry.

Schedule the verification command on a dedicated recovery runner with a fresh target each time. Send its structured result to the private operations log. Alert on nonzero exit, a missing verification result, or a backup older than the agreed recovery point objective. Save the resulting manifest and elapsed time without copying row content to monitoring.

The local integration job creates and stops its own network-disabled container from the locally available `postgres:17.6-alpine` image. It uses synthetic data.

```sh
node tests/disaster-recovery.e2e.mjs
```

## Managed Supabase recovery

1. Identify the affected project and choose a backup or point-in-time recovery timestamp. Use an approved recovery project and capture evidence before changing traffic. Follow the current provider procedures for supported backups and project restoration. [Supabase backups](https://supabase.com/docs/guides/platform/backups) · [Restore to a new project](https://supabase.com/docs/guides/platform/clone-project)
2. Recover object bytes from the matching private Storage backup using the same bucket and object keys. Compare expected object counts and checksums with the backup inventory. Supabase database backups include Storage metadata, while recovering object bytes requires a separate backup. [Supabase Storage download guidance](https://supabase.com/docs/guides/storage/management/download-objects)
3. Restore and review Auth callback URLs, SMTP and templates, managed keys, Storage configuration, Realtime, and Edge Functions against the release settings. Keep external webhooks, cron tasks, and outbound mail disabled until their owners approve reactivation. Restore credentials through each provider’s secret-management flow.
4. Test the v6 readiness route, account sign-in and password recovery, message isolation across two workspaces, auditor and moderator access, a private attachment download, and key availability for any recoverable encrypted data. Compare record counts and object checksums to the captured baseline. Verify writes and account flows with QA identities on the recovery environment.
5. Record the independent verification outcome and have the release owner review the cutoff. Coordinate any Vercel environment switch, DNS, or webhook changes with the incident owner. Keep the previous environment available for rollback until service health and authorized writes are confirmed.

The portable PostgreSQL drill has local evidence. Full hosted recovery still needs an authorized rehearsal covering the matching Storage backup, Auth configuration, secret reissue, and release cutover.

## Private Storage drill

Pause writes, uploads, and scheduled cleanup for the selected backup interval. Capture the private Storage metadata inventory before the database backup and again after the Storage copy. Compare the two inventories byte for byte. A changed inventory requires a fresh capture so the database metadata and object bytes refer to the same object versions. Store the inventory, database archive, and object archive together under the same restricted backup identifier.

```sh
psql --no-psqlrc --no-align --tuples-only --set=ON_ERROR_STOP=1 \
  --dbname=service=sectalk_backup_source --file=scripts/storage-recovery-inventory.sql \
  --output=/protected/sectalk/backup-id/storage-inventory.jsonl
node scripts/storage-recovery.mjs backup --archive /protected/sectalk/backup-id/objects \
  --inventory /protected/sectalk/backup-id/storage-inventory.jsonl
node scripts/storage-recovery.mjs verify --archive /protected/sectalk/backup-id/objects
```

Provide the explicit Storage origin and scoped recovery credential through `SECTALK_DR_STORAGE_URL` and `SECTALK_DR_STORAGE_KEY` for the backup process. The archive stores object bytes and their SHA-256 digests. It keeps object identifiers in a protected manifest and writes only aggregate completion status to the log. A backup interrupted before writing the manifest needs a fresh archive directory. Protect the archive with the same encryption and access policy as the database backup.

Prepare a disposable loopback Supabase recovery project with the matching private buckets and app policies. Set the two environment values for that target, then run `node scripts/storage-recovery.mjs restore --archive /protected/sectalk/backup-id/objects`. The job verifies every archive file before writing and reads every recovered object to check its digest. Repeated runs reuse exact existing bytes. Conflicts stop the drill. Validate app access with a recoverable owner identity and an unrelated synthetic account. Use the provider recovery process for native Storage metadata and ownership in a hosted recovery.

## Scheduled Supabase project rehearsal

Use the weekly `sectalk-supabase-recovery.timer` and its matching service from `ops/systemd` on a dedicated Linux Docker runner. The runner needs Node.js, version-matched PostgreSQL clients, an encrypted archive volume, and private, read-capable backup credentials. Restrict the recovery machine and Docker daemon to recovery operators. Install the timer separately after completing a manually initiated drill and verifying the destination and alert routing.

On the approved runner, install both units in `/etc/systemd/system`, reload the systemd configuration, and run `systemctl start sectalk-supabase-recovery.service` for the first drill. Check the structured result in `journalctl -u sectalk-supabase-recovery.service` before enabling the timer with `systemctl enable --now sectalk-supabase-recovery.timer`.

The scheduled runner calls the trusted freeze hook, captures the database and Storage generation, releases the source, provisions a clean disposable target, and then verifies the generation there. Use a quiesced source or a deliberately frozen backup clone. The freeze hook must gate app writes, Auth writes, uploads, webhooks, workers and cleanup. Inventory and row-count comparisons detect drift but cannot prove that a writer did not change and revert data. Make the release hook safe to run repeatedly, including after a partially failed freeze, and arrange a separate timeout and alert for the freeze mechanism.

Keep the following settings in a mode-0600 environment file outside the repository. The hooks are trusted executable files owned by the recovery operator.

| Setting | Purpose |
| --- | --- |
| `SECTALK_DR_ARCHIVE_ROOT` | Encrypted directory outside the checkout. Each generation gets its own restricted directory. |
| `SECTALK_DR_SOURCE_LIBPQ_SERVICE`, `PGSERVICEFILE`, `PGPASSFILE` | Explicit read source, TLS settings and private libpq password file. |
| `SECTALK_DR_SOURCE_API`, `SECTALK_DR_SOURCE_SERVICE` | Storage API origin and the minimal private credential for the same backup project. |
| `SECTALK_DR_FREEZE_HOOK`, `SECTALK_DR_RELEASE_HOOK`, `SECTALK_DR_TARGET_HOOK` | Absolute hook paths for gating source writes, reopening the source and preparing a fresh disposable target. |
| `SECTALK_DR_TARGET_CONTAINER`, `SECTALK_DR_TARGET_API` | Disposable project database container and corresponding loopback API. Use `supabase_db_sectalk-dr-*` and bind the gateway to loopback. |
| `SECTALK_DR_TARGET_SERVICE`, `SECTALK_DR_TARGET_PUBLISHABLE` | Disposable target's service and public credentials. |
| `SECTALK_DR_ASSERTIONS` | Absolute path to trusted SQL that raises on inconsistent restored audit records or grant checks. |
| `SECTALK_DR_CANARY_BUCKET`, `SECTALK_DR_CANARY_OBJECT`, `SECTALK_DR_CANARY_WORKSPACE` | Private synthetic object and audited workspace known to be present in the source. |
| `SECTALK_DR_CANARY_OWNER_{ID,EMAIL,PASSWORD}`, `SECTALK_DR_CANARY_OUTSIDER_{ID,EMAIL,PASSWORD}` | Separate synthetic identities. The owner must be able to read the private object and workspace creation audit event. The outsider must be denied the object and receive an empty audit result for that workspace. |

The target hook must initialize the identical application migrations, Supabase component versions, roles, grants, policies, and private buckets. Use separate service secrets and signing keys. Disable external SMTP, scheduler jobs, outbound integrations, and public traffic. The generation contains a full PostgreSQL custom archive with the portable-job exclusions, a private Storage metadata inventory, and verified object bytes. The verifier checks the target's schema and ACL fingerprint, refuses populated Auth or Storage targets, validates the archive checksums, and restores the application and Auth schemas' data into their migrated definitions. Storage is restored via its API. The verifier preserves the owner and validates bucket, key, size and content type. Storage regenerates physical object versions. Configuration, unmanaged schemas, external secrets, Realtime publications, and provider-side settings still use the approved provider recovery process.

A successful capture emits `project_backup_created`. A successful rehearsal emits `project_restore_verified` with captured time, elapsed verification time, object count, and check names. Alert on a nonzero run, a missing result, or a generation older than the stated RPO. Treat a directory without a manifest as incomplete. Keep failed targets and artifacts private during investigation and provision a clean target for retries. Apply the operator-approved retention policy to archives and dispose of targets with the runner's approved cleanup procedure.

For a controlled one-off local rehearsal, initialize separate disposable CLI projects, seed the synthetic identities and audit event, and run the commands below. Set `SECTALK_DR_SYNTHETIC_LOCAL=yes` only with synthetic local data when the CLI publishes its development ports on all interfaces. The scheduled path using a libpq service requires loopback-only target bindings.

```sh
SECTALK_DR_SOURCE_FROZEN=yes node scripts/supabase-recovery.mjs capture \
  --source-container supabase_db_sectalk-dr-source --archive /protected/sectalk/drill
node scripts/supabase-recovery.mjs verify \
  --target-container supabase_db_sectalk-dr-target --archive /protected/sectalk/drill \
  --assert /protected/sectalk/verify.sql
```

Local evidence covers the scheduled runner's component operations against independent disposable projects. It does not establish a hosted recovery or production cutover.
