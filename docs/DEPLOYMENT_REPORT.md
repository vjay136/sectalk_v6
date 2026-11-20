# V6 deployment status

The existing SecTalk v5 Vercel project and GitHub release are the live baseline. V6 is a release candidate. Production promotion and a published release require the full verification described in the supplied brief.

Run `npm run verify:registry -- --release` to check feature completion. V6 requires all 239 rows to be DONE before publication or deployment. The structural registry check runs separately as `npm run verify:registry`. The release gate also requires the brief's integration, security, accessibility, load, recovery, and provider tests.

| External setup | What the target environment requires |
| --- | --- |
| Auth email | Grant access to the target Supabase Auth settings, add the exact callback, and configure a verified transactional sender. Apply the templates and test delivery to a real inbox. |
| Calls | Configure TURN over UDP and TLS and provide a dedicated test LiveKit project. Verify direct, relay-only, reconnect, and group-call paths across real networks. |
| Billing | Configure Stripe test prices, signing secrets and webhook delivery. For Razorpay, provide a test merchant account and webhook signing secret after the adapter is built. |
| Realtime and jobs | Provide isolated Ably, Redis and queue credentials for the adapters and failure-path verification. |
| Storage and encryption | Provision a dedicated nonproduction S3-compatible bucket and KMS key with narrowly scoped grants for scanner, retention and key-management tests after the adapters are implemented. |
| V6 chat attachments | Configure a v6-only Supabase server key as `SECTALK_FILE_STORAGE_KEY` and a separate random signing secret as `SECTALK_FILE_TICKET_SECRET`. Keep both server-side. Verify uploads and signed retrieval against the migrated v6 Storage bucket. |
| Push and safety AI | Provision the push keys and a policy-approved test model or gateway account after the delivery and classification paths are implemented. |
| Vulnerability disclosure | Set the stable v6 HTTPS origin, a verified and monitored private contact, and the contact expiry documented in [SECURITY.md](../SECURITY.md). Verify both public disclosure routes on the target deployment. |
| Audit chain | Retain PostgreSQL audit checkpoint receipts in a log destination with independent access and retention. Verify a retained receipt against the private audit verifier after initializing the target. |
| Disaster recovery | Rehearse managed database recovery, recovery of matching private Storage objects, Auth, provider configuration and isolated cutover using the [disaster recovery runbook](DISASTER_RECOVERY.md). |

The matrix uses BLOCKED_EXTERNAL only when the implementation and its test-mode proof are present. Missing configuration and missing code are tracked separately.
