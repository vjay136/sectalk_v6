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
