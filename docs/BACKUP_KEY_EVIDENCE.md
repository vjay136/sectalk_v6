# Workspace key records in recovery archives

Use this check to determine whether one existing SecTalk recovery generation still holds wrapped managed keys or references to an external key for an exact workspace. A recovery operator records the SHA-256 of `project-manifest.json` in the private operations log at capture. A separate reviewer retrieves that digest from the log and checks the protected generation in an isolated recovery environment with a compatible `pg_restore`.

```sh
node scripts/backup-key-evidence.mjs --archive /protected/sectalk/backup-id --workspace WORKSPACE_UUID --manifest-sha256 DIGEST_FROM_OPERATIONS_LOG
```

Add `--key-version VERSION` to inspect the matching workspace key record. For an external key, add `--provider-pin=DIGEST` from the independently recorded provider evidence. The receipt reports the scoped record type and whether the pin matched. Keep the supplied pin and the archive in restricted operations storage.

For a provider event already verified in SecTalk, the independent destruction reviewer can use **Artifact keys → Provider key erasure evidence → Download provider key evidence**. Record the receipt SHA-256 shown in SecTalk in the private operations log. Supply that independently retrieved digest separately from the downloaded file.

```sh
node scripts/backup-key-evidence.mjs --archive /protected/sectalk/backup-id --workspace WORKSPACE_UUID --manifest-sha256 ARCHIVE_DIGEST --key-version VERSION --provider-evidence /protected/sectalk/provider-evidence.json --provider-evidence-sha256 RECEIPT_DIGEST
```

The combined report binds a single provider event to the exact workspace and key version inspected in the archive. It reports whether the archived external reference matches the receipt, differs, or cannot be compared because the archive lacks the comparable marker. The receipt contains a commitment to the provider pin. The combined report excludes that commitment, the raw pin, and wrapped keys.

The verifier checks the independently recorded manifest digest and the digests of `project.pgdump`, `private-inventory.jsonl` and `objects/storage-manifest.json`. It uses `pg_restore` to inspect the archived key tables and never executes the generated SQL. The receipt reports scoped counts and the exact generation digest. It excludes wrapped key bytes and external references from its output. [PostgreSQL `pg_restore`](https://www.postgresql.org/docs/current/app-pgrestore.html)

- `wrapped_managed_keys_retained` means the generation holds one or more managed KEK envelopes. An accessible historical wrapping secret can make those copies usable even after the live rows are removed.
- `external_key_records_retained` means the generation holds external provider references or encrypted legacy envelopes. Check the separate provider key lifecycle evidence for the exact versions.
- `no_listed_key_records` means the selected generation contains no scoped records in the inspected tables. Its other data, older generations and independent replicas may still exist.

The receipt always reports source deletion, provider deletion and backup erasure as unverified. Retain separate evidence for each applicable generation, Storage backup and object version, Supabase hosted backup and PITR window, recovery replica or restored clone, independent export, and recoverable copy of the wrapping secret. A database backup contains Storage metadata. Recovery of the object bytes uses a separate Storage backup. [Supabase database backups and PITR](https://supabase.com/docs/guides/platform/backups)

## Exact S3 archive-copy inventories

For SecTalk archives stored in a versioned AWS S3 bucket, use `s3-recovery-copy-inventory.mjs` from the tenant custody image. A reviewer independently approves each bucket, owner account, Region, and exact prefix applicable to the selected workspace and key version. Use `--mode=scope` with those six values to compute the SHA-256 to record in the restricted operations log. The prefix must identify a nonempty archive namespace and end with a slash.

```sh
node /srv/tenant-dek/s3-recovery-copy-inventory.mjs --mode=scope \
  --workspace WORKSPACE_UUID --version KEY_VERSION --bucket BUCKET --owner AWS_ACCOUNT \
  --region AWS_REGION --prefix archive/project/
```

For capture, reuse the six values with `--mode=capture`, add `--scope-sha256` from the independent scope approval and `--inventory` for a new file in restricted storage. Use an ECS or EKS workload in the bucket owner's account with read-only `s3:GetBucketLocation` and `s3:GetBucketVersioning` on the exact bucket, plus `s3:ListBucketVersions` on the exact bucket and prefix. The tool confirms the bucket's actual Region and versioning state, enumerates object versions and delete markers across all pages, and compares two complete observations. The provider calls are subject to AWS usage charges. [S3 bucket location API](https://docs.aws.amazon.com/AmazonS3/latest/API/API_GetBucketLocation.html) · [S3 versioning API](https://docs.aws.amazon.com/AmazonS3/latest/API/API_GetBucketVersioning.html) · [S3 version listing API](https://docs.aws.amazon.com/AmazonS3/latest/API/API_ListObjectVersions.html)

Log the emitted inventory SHA-256 separately from the protected file. A reviewer uses the six scope values with `--mode=verify`, the approved scope SHA-256, the restricted inventory path, and `--inventory-sha256` from that log. Verification uses the file offline. The protected inventory records exact keys, version IDs and ETags. The receipt reports counts and digests, including noncurrent versions hidden by current delete markers. If the version list changes, a version ID is ambiguous, or the page limit is reached, stop and reconcile the provider inventory before relying on it. Large namespaces can use independently approved, non-overlapping prefixes.

Two matching listings establish a stable observation within the approved prefix. Account for concurrent writers through the recovery process and use separately approved scopes for additional buckets, copies, replicas and provider-managed backups. Use the archive byte checks above for checksums. S3 ETags serve only as additional inventory metadata here. The inventory always leaves backup erasure unverified.

## Join one archived key finding to the exact S3 copies

Use `recovery-copy-provenance.mjs` from the custody image when a separately reviewed provider receipt already matches the exact external-key reference inspected by `backup-key-evidence.mjs`. Assemble a restricted bundle outside the checkout. Preserve raw file bytes so independent digests remain valid.

| Bundle file | Required content |
| --- | --- |
| `s3-inventory.json` | Independently verified scoped version inventory from the preceding check |
| `s3-archive-plan.json` | JSON with `format` set to `sectalk-s3-archive-version-plan-v1`, the `scopeSha256` and `inventorySha256`, the exact `generationPrefix`, and `versions` mapping the four archive paths to exact S3 version IDs |
| `project-manifest.json` | The raw capture manifest previously verified by the archive tool |
| `archive-key-evidence.json` | The archived-key finding showing that the exact version's external provider receipt matches |
| `provider-key-evidence.json` | The raw receipt downloaded by the independent SecTalk reviewer |
| `copy-approval.json` | JSON with `format` set to `sectalk-s3-archive-copy-approval-v1` and individually retrieved `scopeSha256`, `inventorySha256`, `planSha256`, `projectManifestSha256`, `archiveFindingSha256` and `providerReceiptSha256` |

The four scoped paths are `project-manifest.json`, `project.pgdump`, `private-inventory.jsonl` and `objects/storage-manifest.json`. Record the copy approval SHA-256 separately in the restricted operations log after reviewing the source and destination scope. Run the command with `--check-inputs-only` for an offline check, or with `--confirm-version-downloads` for an authorized hosted byte check.

```sh
node /srv/tenant-dek/recovery-copy-provenance.mjs --bundle /protected/recovery/evidence \
  --approval-sha256 DIGEST_FROM_OPERATIONS_LOG --check-inputs-only
```

Exact downloads require an approved workload role with scoped `s3:GetObjectVersion` and any applicable wrapping-key access for the selected backup objects. The command checks AWS ownership, version identity, length, observed modification time, ETag metadata and SHA-256 of the actual downloaded bytes. Bytes pass through a pipe without creating another archive file. The reads may incur AWS charges. Multipart archive copies are hashed as complete byte streams. S3’s SHA-256 result for a multipart upload can instead be a composite checksum. [Versioned S3 reads](https://docs.aws.amazon.com/AmazonS3/latest/API/API_GetObject.html) · [S3 upload checksums](https://docs.aws.amazon.com/AmazonS3/latest/userguide/checking-object-integrity-upload.html)

The result binds one generation and provider receipt to the four verified version IDs through the approval and inventory digests. Reconcile the count of other listed records separately. Individual archived Storage objects, separate archive copies, and evidence of provider or backup deletion remain separate checks.

## Reconcile approved recovery locations

Use `recovery-coverage.mjs` from the custody image to compare independently recorded baseline and later version inventories across known S3 recovery locations. The command runs offline. Approve each replica, mirror and backup prefix separately. Cover the applicable buckets and use non-overlapping prefixes within each bucket.

Prepare `coverage-approval.json` with `format` set to `sectalk-s3-recovery-coverage-approval-v1`, the exact `workspace` and integer `keyVersion`, `providerReceiptSha256`, an approved UTC `observationFrom` and `observationThrough`, and `cohorts`. Each cohort has a simple lowercase `id`, `scopeSha256`, `baselineInventorySha256`, `observedInventorySha256` and an `archiveProvenance` array of `{ "receiptSha256": "...", "planSha256": "..." }` entries. Populate the array for a baseline containing object versions. An empty baseline uses an empty array.

Place the raw provider receipt at `provider-key-evidence.json`. Place the independently pinned inventories at `<id>-baseline.json` and `<id>-observed.json`. For each provenance entry, use `provenance-<receiptSha256>.json` for the exact versioned archive check and `plan-<planSha256>.json` for its independently recorded version plan. The archive check must follow the baseline and precede the later observation. Use a later observation for every cohort, within the approved window and after the provider event and independent receipt.

```sh
node /srv/tenant-dek/recovery-coverage.mjs --bundle /protected/recovery/coverage \
  --approval-sha256 DIGEST_FROM_OPERATIONS_LOG
```

The coverage receipt counts previously seen versions still present, new versions such as copies created in a replica, and versions absent from the later captured scope. Noncurrent versions remain visible even when the latest entry is a delete marker. The receipt counts markers and separates baseline versions with a verified byte-provenance plan from other listed versions. A failed or missing scope or a later observation outside the approved window produces no coverage receipt. Empty approved observations describe that window and scope. Other replicas, managed database backup and PITR windows, restored clones, exports, wrapping-secret copies and backup erasure require independent evidence.

## Observe provider-managed Supabase backups and PITR

Use `scripts/supabase-backup-observation.mjs` to capture the documented backup catalog for an independently approved test project. Prepare a protected approval outside the checkout with `format` set to `sectalk-supabase-backup-approval-v1`. Include the distinct `sourceProject` and `testProject` refs, exact expected `region`, `workspace` UUID and integer `keyVersion`. Provide the UTC key-review interval in `reviewFrom` and `reviewThrough`, and the later allowed capture interval in `observeFrom` and `observeThrough`. Have the independent reviewer record the raw approval file SHA-256 in the protected operations log.

For a hosted rehearsal, use `--capture-confirmed-test-project` and pass a project-scoped Management API credential in `SECTALK_BACKUP_OBSERVER_TOKEN`. Restrict the credential to the approved test project and backup reads. The documented GET endpoint accepts OAuth `database:read` or a fine-grained token with `backups_read`. The command checks the approved region and records the exact response bytes in a new restricted inventory file. Record that inventory digest independently. [Supabase backup listing API and permissions](https://supabase.com/docs/reference/api/v1-list-all-backups)

```sh
node scripts/supabase-backup-observation.mjs --approval /protected/recovery/approval.json \
  --approval-sha256 APPROVAL_DIGEST --inventory /protected/recovery/test-backups.json \
  --capture-confirmed-test-project
```

Offline review uses the same inputs and replaces the capture flag with `--inventory-sha256 INVENTORY_DIGEST`. The report distinguishes an empty provider list from omitted or malformed catalog data. It reports catalog status counts, unknown statuses, PITR/WAL-G flags, and whether the provider reported both, one, or neither physical bound. It compares both valid bounds with the approved review interval. A listed status of `REMOVED`, disabled PITR, empty results, or omitted bounds leave provider deletion, restore availability and backup erasure unverified. The endpoint describes the selected project. Coverage for the live source, Storage bytes, individual recovery-chain points, provider replicas and restored copies requires separate evidence. [Supabase backup and PITR behavior](https://supabase.com/docs/guides/platform/backups)

### Compare managed backup observations across a reviewed key event

Capture two independently approved observations for the same test project, region, workspace, key version and key-review interval. Their allowed observation windows must be disjoint. Capture the baseline before the provider event and the later observation at or after the independently reviewed receipt. The provider receipt must match the exact workspace and version.

Keep the raw approvals and observations in a restricted bundle as `baseline-approval.json`, `baseline-inventory.json`, `later-approval.json` and `later-inventory.json`. Save the raw provider receipt as `provider-key-evidence.json`. Prepare `timeline-approval.json` with `format` set to `sectalk-supabase-backup-timeline-approval-v1` and the independently retrieved `baselineApprovalSha256`, `baselineInventorySha256`, `laterApprovalSha256`, `laterInventorySha256` and `providerReceiptSha256`. Record the raw timeline-approval file SHA-256 separately.

```sh
node scripts/supabase-backup-timeline.mjs --bundle /protected/recovery/supabase-timeline \
  --approval-sha256 DIGEST_FROM_OPERATIONS_LOG
```

The offline comparison counts unchanged backup identities, status transitions to `REMOVED`, newly listed records and omissions from the later provider catalog. Catalog comparison stays unknown when either observation lacks a complete reported list. Physical backup bounds are compared separately when both observations contain both endpoints. A provider status, an omission or a shift in reported bounds cannot establish that a database recovery chain or key copy was erased.
