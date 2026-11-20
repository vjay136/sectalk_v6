# V6 deployment status

The existing SecTalk v5 Vercel project and GitHub release are the live baseline. V6 is a release candidate. Production promotion and a published release require the full verification described in the supplied brief.

Run `npm run verify:registry -- --release` to check feature completion. The structural registry check runs separately as `npm run verify:registry`. The release gate also requires the brief's integration, security, accessibility, load, recovery, and provider tests.

| External setup | What the target environment requires |
| --- | --- |
| Auth email | Grant access to the target Supabase Auth settings, add the exact callback, and configure a verified transactional sender. Apply the templates and test delivery to a real inbox. |
| Calls | Configure TURN over UDP and TLS and provide a dedicated test LiveKit project. Verify direct, relay-only, reconnect, and group-call paths across real networks. |
| Billing | Configure Stripe test prices, signing secrets and webhook delivery. For Razorpay, provide a test merchant account and webhook signing secret after the adapter is built. |
| Realtime and jobs | Provide isolated Ably, Redis and queue credentials for the adapters and failure-path verification. |
| Storage and encryption | Provision a dedicated nonproduction S3-compatible bucket and KMS key with narrowly scoped grants for scanner, retention and key-management tests after the adapters are implemented. |
| Push and safety AI | Provision the push keys and a policy-approved test model or gateway account after the delivery and classification paths are implemented. |

The matrix uses BLOCKED_EXTERNAL only when the implementation and its test-mode proof are present. Missing configuration and missing code are tracked separately.
