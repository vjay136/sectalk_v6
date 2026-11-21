# Independent audit receipt worker

The native database verifies the audit source rows and hash chain. This worker compares that result with the newest digest receipt in an independently administered S3 bucket. It advances the receipt after successful verification and returns an error if either store is unavailable or the chain differs. Its output contains the sequence and SHA-256 digest.

Use a separate AWS security account and an S3 general-purpose bucket with versioning, default Object Lock in Compliance mode, and Block Public Access. Require a conditional create on the receipt object prefix and deny delete markers, object version deletion, and changes to the bucket configuration for the worker credential. Give the worker prefix-scoped list, head, version reads and conditional writes, with access to the checksum and retention metadata. Retain the receipts for the approved incident window. The script also sets and verifies active Compliance retention for each new object. [Configure S3 Object Lock](https://docs.aws.amazon.com/AmazonS3/latest/userguide/object-lock-configure.html)

Create a dedicated PostgreSQL login granted membership in `sectalk_audit_anchor_reader`. The role can invoke only the digest verifier in the private schema. Configure a libpq service for that login with server identity verification and a query timeout appropriate to the journal size. Keep the DB authentication, AWS credentials and the job's logs under separate operator control. Install Node.js, PostgreSQL `psql` and AWS CLI v2 on the worker host.

Set the following worker-only environment variables.

| Variable | Value |
| --- | --- |
| `SECTALK_AUDIT_PG_SERVICE` | Dedicated libpq service name |
| `SECTALK_AUDIT_RECEIPT_BUCKET` | Independently administered bucket name |
| `SECTALK_AUDIT_RECEIPT_OWNER` | Twelve-digit AWS account ID of the bucket owner |
| `SECTALK_AUDIT_RECEIPT_NAMESPACE` | Stable, unique release environment identifier |
| `SECTALK_AUDIT_RECEIPT_DAYS` | Compliance retention for new receipts, 365 by default |

After an operator reviews the current journal and empty namespace, run `node scripts/audit-anchor.mjs bootstrap` once. Schedule `node scripts/audit-anchor.mjs verify-and-anchor` at minute 23 every hour with a single active worker. Monitor failed and missing executions independently of the database. A normal run returning `verified` has confirmed the externally anchored head. An `anchored` result means a new receipt was written, independently read back and validated. Never bootstrap to clear a reported mismatch or missing receipt. Keep the namespace and receipt history available during restore and cutover. The worker fails if it cannot enumerate the namespace within 50,000 objects. Plan archival and an independently recorded handoff before reaching that bound.
