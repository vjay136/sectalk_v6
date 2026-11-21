# External tenant DEK custody

## Scheduled managed rotation

A workspace owner with fresh authenticator verification can choose an automatic rotation interval in **Workspaces → Compliance exports → Managed artifact keys → Automatic managed-key rotation**. The interval is 30, 60 or 90 days from the later of the policy change and activation of the current key. Version history remains available for existing and held ciphertext. A pending destruction review, read-only offboarding, loss of owner authority or a switch to external custody pauses future activation.

The private worker at `/api/tenant-keys/rotate-due` checks up to 32 due workspaces at 03:12 UTC each day when Vercel Cron is enabled. Set the production-only `CRON_SECRET` to a high-entropy value of at least 32 bytes. The worker uses the existing server-only storage service credential and managed wrapping key. Its response contains counts. Native activation rechecks the exact workspace, policy revision and current managed key version, so repeated worker requests can activate a given version once. An activation failure leaves the policy due for the next run. [Vercel Cron configuration](https://vercel.com/docs/project-configuration/vercel-json#crons)

The automatic schedule applies to managed custody. Enterprise external key activation uses the existing provider verification and operator-controlled immutable key mapping described below. Historical envelopes retain their key versions through scheduled rotation.

## Managed channel and room DEK rewrap

An operator can run a batch of up to 16 historical managed messages with `POST /api/tenant-keys/rewrap`. Send the workspace UUID as `workspace` and authorize with the dedicated server-only `SECTALK_DEK_REWRAP_SECRET` bearer. Set a high-entropy value of at least 32 bytes. An active owner-authorized managed rotation policy is required. Send `kind: "room"` for rooms. The default is `channel`. A full batch or a batch with a processing failure includes `next`. Pass that cursor unchanged as `after` with the same workspace and kind to continue past those records. Check unresolved failures before retrying from the start. Rewrap has no cron registration.

The worker verifies that the same DEK opens the exact unchanged authenticated ciphertext with the previous and current KEKs. It commits the new capsule separately from the original ciphertext and envelope, with a receipt tied to the source revision. Timeline reads and search use the additional capsule under the existing session and membership checks. Reports and held evidence retain their original envelope and revision. Workspace holds, existing reports, in-progress channel reports, quarantined channel posts, archived rooms, external custody, pending key destruction and read-only offboarding are excluded. The historical keys remain necessary for original evidence envelopes and existing backup or recovery paths.

## External custody workflow

Use **Workspaces → Compliance exports → Managed artifact keys** to activate configured Enterprise external custody. A workspace owner needs fresh authenticator verification and an audit reason. Rotation activates a new version after an authenticated wrap/unwrap proof against the configured provider. The previous key stays available for existing ciphertext and held records.

New compliance and evidence envelopes and managed channel records use a unique data encryption key (DEK). The app encrypts content locally and asks the external provider to wrap or unwrap the DEK. SecTalk stores the wrapped DEK with the ciphertext and a versioned, pinned reference to an immutable provider key. This mode has no app-generated tenant root. The database prevents registration of the same provider-key fingerprint across workspaces or rotations. Earlier managed and legacy fixture BYOK versions keep their original formats.

## Provider configuration

- Set server-only `SECTALK_EXTERNAL_KMS_URL` to the approved provider adapter's HTTPS endpoint at `/v1/tenant-dek`. The disposable Supabase fixture also permits a loopback HTTP adapter.
- Set `SECTALK_EXTERNAL_KMS_TOKEN` to a restricted adapter credential. Give the adapter wrap and unwrap rights for the approved immutable provider keys only. Configure its provider identity to prevent tenant root export and keep lifecycle administration separate.
- Set `SECTALK_EXTERNAL_KMS_KEYS` to a JSON object keyed by workspace UUID. Each value contains `active`, the reference to use for the next rotation, and `keys`, a reference-to-immutable-provider-key-ID map. Add a distinct immutable ID for each workspace version. Keep the original endpoint and mapping for historical versions while they are required.
- The adapter accepts an authenticated JSON POST with `operation` (`wrap` or `unwrap`), `workspace`, `version`, `reference`, `keyId`, `context` and `value`. Bind the exact context to the ciphertext using the provider's authenticated context mechanism. Return `keyId`, `context` and `value` from the completed operation. A wrap receives one base64url-encoded 32-byte DEK and returns an opaque base64url capsule. An unwrap reverses that operation. The request supplies a digest of the record scope with the tenant/version/key context. It carries no message body or export bytes. Keep DEKs and request bodies out of provider and adapter logs. [Encryption context guidance](https://docs.aws.amazon.com/kms/latest/developerguide/encrypt_context.html)

## AWS KMS adapter

Build the separate adapter image with `docker build -t sectalk-tenant-dek services/tenant-dek-aws`. The image listens on port 8080. Put it behind the approved HTTPS ingress and restrict access to the application. The ingress must forward the JSON content type and length and exclude request and response bodies from logging. Use a TCP health check for the adapter listener. [Official AWS CLI images](https://docs.aws.amazon.com/cli/latest/userguide/getting-started-docker.html)

Set `SECTALK_TENANT_DEK_ADAPTER_TOKEN` in the adapter to the same secret as the application's `SECTALK_EXTERNAL_KMS_TOKEN`. Set the adapter's `SECTALK_TENANT_DEK_AWS_KEYS` to the exact approved workspace, version and reference bindings. Each binding uses a distinct symmetric KMS key ARN. Keep bindings for historical records until their retention and recovery obligations are cleared.

```json
[
  {
    "workspace": "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
    "version": 1,
    "reference": "external_v1",
    "keyId": "arn:aws:kms:ap-southeast-2:111111111111:key/11111111-aaaa-bbbb-cccc-111111111111"
  }
]
```

Run the image with an ECS task role or an EKS IAM role for a service account. Use exactly one workload identity and give it `kms:Encrypt` and `kms:Decrypt` for the configured key ARNs. Restrict those policy permissions to `kms:EncryptionContext:purpose` equal to `sectalk-tenant-dek-v2`. The other context field is a SHA-256 digest of the exact application key binding and record context. The customer key policy must authorize the workload role. Keep key administration, import and deletion authority with the key custodian. The adapter passes DEK bytes through a binary pipe and supplies the operation, ARN, region and hashed scope as command arguments. [KMS encryption context conditions](https://docs.aws.amazon.com/kms/latest/developerguide/conditions-kms.html) · [ECS task roles](https://docs.aws.amazon.com/AmazonECS/latest/developerguide/task-iam-roles.html) · [EKS workload roles](https://docs.aws.amazon.com/eks/latest/userguide/iam-roles-for-service-accounts.html)

Run `node --test tests/tenant-dek-aws-adapter.test.mjs tests/tenant-artifact-key-custody.test.mjs` to check the adapter with local synthetic keys. The test covers the application rotation probe, per-record envelopes, distinct key bindings and failure when a key becomes unavailable. On Linux, it also checks that the subprocess can open and read the binary pipe. The hosted check requires the deployed image, a customer-approved test key, a real workload role and a recorded rotation and recovery drill.

The local Node 24 Linux Docker run passed all eight tests with networking disabled, including the binary pipe check and loopback custody service.

## Hosted custody checks

The adapter image includes `/srv/tenant-dek/verify-custody.mjs`. Select one customer-approved disposable binding using `--workspace`, `--version` and `--reference`. Load the approved app and adapter maps through `SECTALK_EXTERNAL_KMS_KEYS` and `SECTALK_TENANT_DEK_AWS_KEYS`. Supply the independently approved immutable ARN in `SECTALK_CUSTODY_EXPECTED_KEY_ARN`. The tool checks these three inputs agree before making any request.

- Run with `--mode=inspect --origin=AWS_KMS` from the selected AWS workload. Supply its approved IAM role ARN and unique role ID via `SECTALK_CUSTODY_EXPECTED_ROLE_ARN` and `SECTALK_CUSTODY_EXPECTED_ROLE_ID`. Use the actual expected material origin, such as `EXTERNAL` for imported material. This mode calls STS `GetCallerIdentity` and KMS `DescribeKey` only. Use a read-only inspection role with `kms:DescribeKey` for that ARN. The result distinguishes a regional key in a multi-Region set from a single-Region key. [STS identity reference](https://docs.aws.amazon.com/cli/latest/reference/sts/get-caller-identity.html) · [KMS key metadata](https://docs.aws.amazon.com/kms/latest/APIReference/API_DescribeKey.html)
- Run with `--mode=drill --confirm-non-production-key` after the independent metadata check. Provide the deployed HTTPS endpoint in `SECTALK_EXTERNAL_KMS_URL`, its independently approved origin in `SECTALK_CUSTODY_EXPECTED_ADAPTER_ORIGIN`, and the token in `SECTALK_EXTERNAL_KMS_TOKEN` through the approved secret channel. It checks round-trip, changed-context refusal, corrupted-capsule refusal and mismatched ARN refusal using a fresh synthetic DEK. This mode uses the live adapter and its AWS encryption permissions. Use an isolated test workspace and provider key. The calls are subject to AWS usage charges.

Retain the redacted JSON results in the independent operations log. Keep the role pin and source configuration under restricted access. The reports leave provider and backup erasure unverified. Record held material recovery, every applicable replica or imported copy, and final provider lifecycle and backup evidence separately.

## Holds, recovery and destruction

The application blocks its managed-key destruction workflow when an external version is present. Rotation leaves historical keys and held records in place. External key operators must retain versions needed by active holds, authorized recovery and in-flight exports. If an external operator makes a retained key unavailable, the app cannot decrypt that ciphertext.

Ciphertext backups depend on the same historical provider keys, bindings and authorization. Restoring a database or object backup does not recreate an external key. Older managed versions, separate key replicas, exported plaintext and independently retained copies have their own recovery paths. A decryption failure alone is evidence of current unavailability. Provider lifecycle evidence is needed to establish whether deletion completed. [Example provider deletion lifecycle](https://docs.aws.amazon.com/kms/latest/developerguide/deleting-keys.html)

Local acceptance uses a disposable adapter with synthetic keys. It verifies pinned external wraps, authorization and denial after removal of a synthetic provider key. Hosted provider integration and independently retained data or key erasure are outside that evidence.

## Independent provider key evidence

For a staged workspace, an independent offboarding and key destruction reviewer with fresh TOTP can verify a pinned external key version. The receipt requires the exact AWS account, region and key ARN, a matching service-generated `DeleteKey` event after staging, and a provider lookup consistent with key removal. Current workspace holds and reviewer authorization are checked again before the receipt is committed. Pending deletion, an unrecognized event and a failed lookup alone confer no proof. [AWS CloudTrail key deletion](https://docs.aws.amazon.com/kms/latest/developerguide/ct-delete-key.html)

The receipt is available for an exact single-Region key. A multi-Region key can report its live or pending state. Completion for a multi-Region key requires independent inventory and lifecycle evidence for the primary and every replica, because AWS permits a regional replica to be deleted while related copies remain. For records dated December 2022 or later, the response ARN must be present and match the approved resource. The event must identify AWS internal activity for the same account and be marked as a management event. New receipts bind that provenance into their digest. Earlier stored receipts retain their original digest. [AWS CloudTrail key deletion](https://docs.aws.amazon.com/kms/latest/developerguide/ct-delete-key.html) · [AWS multi-Region deletion behavior](https://docs.aws.amazon.com/kms/latest/developerguide/deleting-keys.html)

For an AWS CloudHSM custom key store, the event must identify the store and cluster and report one successful deletion result for every listed backing key. The receipt digest also binds that exact backing-key inventory. A missing, repeated, mismatched or failed result leaves the event unverified. CloudHSM backups and key material managed by a separate external key store require their own evidence. [AWS CloudHSM key deletion results](https://docs.aws.amazon.com/kms/latest/developerguide/fix-keystore.html#delete-orphaned-key-material) · [AWS external key stores](https://docs.aws.amazon.com/kms/latest/developerguide/keystore-external.html)

Run `/srv/tenant-dek/erasure-worker.mjs` as a separate read-only service using the scoped binding allowlist and a workload role limited to `kms:DescribeKey` and `cloudtrail:LookupEvents`. Use the matching `SECTALK_PROVIDER_ERASURE_ADAPTER_TOKEN` and `SECTALK_PROVIDER_ERASURE_TOKEN` on the two services. The web origin uses `SECTALK_PROVIDER_ERASURE_URL` with the exact HTTPS path `/v1/provider-key-erasure`. The app records provider key evidence, source deletion and backup erasure as distinct statuses. Only provider key evidence is covered by this attestor.
