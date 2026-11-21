# V6 deployment status

The existing SecTalk v5 Vercel project and GitHub release are the live baseline. The [v6.0.0-alpha.1 prerelease](https://github.com/vjay136/sectalk_v6/releases/tag/v6.0.0-alpha.1) records the Free-tier candidate at commit `55aa6b1` and includes its 367-migration fresh-install schema. The [SecTalk v6 Web pilot](https://sectalk-v6-pilot.vercel.app) runs that commit in the separate `sectalk-v6-pilot` project. The account owner opened the protected app and verified the email/password entry, Free-tier SSO notice and pricing page. An anonymous request returned HTTP 302 and v5 returned HTTP 200. Hosted Admin, Workers and signed-in application checks are pending.

The pilot tracks `main` in the separate [SecTalk v6 GitHub repository](https://github.com/vjay136/sectalk_v6), rooted at `apps/web` in the `silent-soldier-vjay` scope. An update to that branch can trigger a new pilot deployment. The existing `origin` points to the v5 repository.

Deploy the updated Web app alongside the workspace trial SSO migration before enabling hosted trials. The migration replaces the older service entry point with one that takes the authenticated owner's native session. The pilot keeps billing disabled.

Run `npm run verify:registry -- --release-free` to check the 234 required rows for the Free-tier source. The full-scope gate is `npm run verify:registry -- --release` and requires all 239 rows. Both release gates scan the Web, Admin and Workers browser assets. The structural registry check runs separately as `npm run verify:registry`.

The current candidate's generated schema installed all 378 migrations on a fresh disposable Supabase project. SHA-256 is `2cfa16e620ee72114a58a65c4feafb8fd4a4e3c9e17f11838846cd8f1bfd9443`. The install recorded every repository version and name in Supabase migration history, created no Auth users, and matched the checked-in RPC permission inventory. A second-install check rejected the existing schema. The Supabase CLI dry run recognized the full history and selected only a later synthetic migration. The published pilot remains on the earlier release schema and hosted backend.

Local production builds passed for Web, Admin and Workers with loopback fixture settings. The isolated Web build passed its browser asset scan. The Free-tier gate passed the three project asset scans. A synthetic full-gate check verified that a server-only value in a Workers browser asset blocks release and the error redacts the value.

| Optional in the Free-tier scope | Current boundary |
| --- | --- |
| AUTH-05 Enterprise SSO | Native OIDC and signed SAML have local evidence. Configure enterprise providers only after hosted gateway verification. |
| ORG-08 Regional residency | Approved transfer and several rollback workflows have local evidence. Regional placement, full restoration and live cutover require separately verified installations. |
| ORG-09 Tenant erasure | Offboarding exports, custody, review and the rollback-only database rehearsal are available. The private native removal transaction passed local verification. Hosted provider and backup erasure and application activation remain open. |
| SEC-04 Tenant key lifecycle | Managed key features and synthetic provider checks have local evidence. Enable hosted BYOK only after scoped provider and recovery verification. |
| PLAT-13 Effective legal documents | Public pages and versioned acceptance are implemented. Terms and Privacy render as drafts until the actual operator approves and configures the effective documents. |

Set `SECTALK_RELEASE_SCOPE=free` on the Vercel Web project. The UI presents availability notices for Enterprise SSO, dedicated regions, permanent tenant erasure and external tenant keys. Terms and Privacy remain available as labeled drafts until operator approval. Existing workspace access rules still apply. Run the hosted readiness, integration, security, accessibility, load and recovery checks for enabled services before opening it to users.

Keep the Free-tier defaults when upgrading the v6 backend. Enable each optional capability after its own hosted check passes:

| Capability | Activation check after upgrade |
| --- | --- |
| Enterprise SSO | Configure the workspace identity provider and exact hosted callback. Verify sign-in and revocation with a named test account before requiring SSO for that workspace. |
| Regional residency | Verify a separate destination in the requested region. Rehearse migration, rollback, and recovery of private files before enabling routing. |
| Permanent tenant erasure | Verify actual erasure and retention rules across the database, Storage, backups, and key provider before enabling the terminal executor. |
| External tenant keys | Configure a scoped KMS and rehearse key rotation and recovery against a matching database and private Storage restore. Use managed application keys until those checks pass. |
| Effective legal documents | Publish the operator-approved documents and verify versioned acceptance with a fresh account. This can be configured on either plan. |

Before opening the Free-tier deployment and again after enabling any optional capability, check signup confirmation, password reset, chat, audio and video calls, and a report from submission through operator review. Use test accounts on v6 so that these checks leave v5 traffic and data in place. Supabase lists daily database backups and SAML for Pro. Point-in-time recovery is a separate add-on. [Supabase plan comparison](https://supabase.com/pricing)

The release uses the `sectalk-web`, `sectalk-admin` and `sectalk-workers` Vercel projects, rooted at `apps/web`, `apps/admin` and `apps/workers` respectively. Enable source files outside the app root for the shared npm workspaces. Apply the v6 migrations to the separate v6 backend before enabling traffic or job schedules.

`npm run build:workers` builds the worker API independently. Its health endpoint is public and returns a service identifier. Job endpoints require their existing server credentials. The worker project alone registers the tenant-key rotation cron, daily at 03:12 UTC. The signed managed DEK rewrap uses its own server credential and runs on demand. [Worker keys and schedule](EXTERNAL_TENANT_KEYS.md)

Configure the private scheduler to send authenticated `POST` requests to the worker origin for billing reconciliation and renewal mail, file and export maintenance, webhook and SIEM delivery, notification email, operational reports and web push. The scheduler should use each job's dedicated bearer from the worker environment. Verify one authenticated invocation and its durable queue outcome for each enabled job before enabling the schedule. [Stripe reconciliation](spec/stripe-reconciliation.md) · [SIEM delivery](spec/siem-export.md)

`npm run build:admin` builds the operator console independently. Staff use named accounts with assigned roles and a fresh authenticator code. Share the admin origin directly with authorized staff. The consumer navigation contains no link to it. [Operator console setup](spec/operator-console.md)

| External setup | What the target environment requires |
| --- | --- |
| Auth email | Grant access to the target Supabase Auth settings, add the exact callback, and configure a verified transactional sender. Apply the templates and test delivery to a real inbox. |
| Authenticator recovery | Verify the existing atomic reset and session revocation checks against the target Supabase Auth schema and direct Data API, Realtime and Storage surfaces. |
| Calls | Configure TURN over UDP and TLS and provide a dedicated test LiveKit project. Verify direct, relay-only, reconnect, and group-call paths across real networks. For gateway-managed meetings, measure refreshed-grant denial and active participant removal on the actual deployment. [Meeting media checks](MEETING_MEDIA_REVOCATION.md) |
| Billing | Configure Stripe test prices, signing secrets and webhook delivery. The hosted Razorpay check requires a test merchant account and signing secret. |
| Realtime and jobs | Provide isolated Ably, Redis and queue credentials for the adapters and failure-path verification. |
| Storage and encryption | Provision dedicated nonproduction Storage and scoped KMS keys to verify encrypted records, provider lifecycle, retention and recoverability against the target environment. |
| V6 chat attachments | Configure a v6-only Supabase server key as `SECTALK_FILE_STORAGE_KEY` and a separate random signing secret as `SECTALK_FILE_TICKET_SECRET`. Keep both server-side. Verify uploads and signed retrieval against the migrated v6 Storage bucket. |
| Push and safety AI | Provision the push keys and a policy-approved test model or gateway account after the delivery and classification paths are implemented. |
| Vulnerability disclosure | Set the v6 HTTPS origin, disclosure expiry, private service credential and envelope key. Assign verified reviewers to monitor the built-in queue. Verify public discovery, submission and restricted review in the target environment. [Security reporting configuration](../SECURITY.md) |
| Public legal pages | Confirm the actual operator details, monitored service and privacy contacts, active processors, applicable jurisdictions and approval record before enabling the effective documents. [Legal release configuration](PUBLIC_LEGAL_RELEASE.md) |
| Community Rules | Publish the approved version to the v6 backend and verify acceptance with a fresh account. Confirm the acceptance receipt persists and that a newly effective version asks the user to review it again. [Activation steps](PUBLIC_LEGAL_RELEASE.md) |
| Native Enterprise OIDC | Edge completed native OAuth with public HTTPS discovery and JWKS, signed identity, S256, workspace JIT and receipt revocation using a synthetic Vercel Sandbox issuer and disposable local GoTrue. An isolated hosted Supabase gateway, independently verified domain and exact hosted callback still need testing. [Workspace SSO](workspace-sso.md) |
| Enterprise region placement | Use a separately provisioned destination project with verified region and installation binding. Rehearse migration, routing, rollback and provider backup evidence for that target. [Feature matrix](FEATURE_MATRIX.md) |
| Audit chain | Retain PostgreSQL audit checkpoint receipts in a log destination with independent access and retention. Verify a retained receipt against the private audit verifier after initializing the target. |
| Disaster recovery | Rehearse managed database recovery, recovery of matching private Storage objects, Auth, provider configuration and isolated cutover using the [disaster recovery runbook](DISASTER_RECOVERY.md). |

The separate [SecTalk v6 Supabase project](https://supabase.com/dashboard/project/wbdaumglskakfnpqkafn) in `vijaycybereagle_Org` has all 359 migrations through `20261121120715`. A hosted SQL audit found zero migration version mismatches, zero Auth accounts, zero public SecTalk tables without row-level security, and eight Storage buckets. The dashboard install explicitly enabled row-level security on the migration history and the private foundation and billing tables that triggered the SQL Editor check. Apply hosted Auth URL, signup admission hook, confirmation and recovery templates, and SMTP configuration before testing email delivery.

The v6 Supabase dashboard confirmed that the pilot origin is saved as Site URL and that `https://sectalk-v6-pilot.vercel.app/auth/confirm` is allowlisted. The dashboard requires custom SMTP before editing the branded templates. Finish signup by privately configuring a fresh v6 signup service credential, installing `public.st_v7_before_signup(jsonb)` as Before User Created, connecting the transactional sender and applying the tracked confirmation and recovery templates.

The v6 email dashboard still showed the default templates and the custom SMTP setup notice. The selected Vercel workspace listed the v6 Web pilot as its only v6 project. A group readiness check needs separate invited browser sessions, real signup and recovery inboxes, and the private Admin deployment with a named, authenticator-enrolled operator. The Free-tier registry gate covers the source and asset checks for 234 features. Deployment verification requires the configured hosted surfaces and connected providers.

To inspect the release settings through the Management API, set `SECTALK_SUPABASE_PROJECT_REF`, `SECTALK_APP_URL` and a privately supplied `SUPABASE_ACCESS_TOKEN`, then run `node scripts/supabase-auth-release.mjs`. Once the v6 app and custom SMTP sender are ready, add `--apply` to save and read back the release settings. Existing redirect entries are retained. The tool reports field names without printing credential values or email template bodies. Verify the confirmation link and six-digit reset code through a real inbox after applying. [Supabase Auth configuration API](https://supabase.com/docs/reference/api/v1-update-auth-service-config)

The hosted v6 database passed the rollback-only signup permit and tenant root offboarding rehearsals. Signup admission enforced server-only permit consumption, email binding, single use and expiry. The offboarding rehearsal required an exact plan and separate reviewer, denied undisclosed cascade rows and triggers, and preserved the audit and workflow custody records. Final counts were zero signup proof rows, zero Auth accounts and zero workspaces. These SQL results cover the hosted database contracts. Live mail, permanent provider erasure and backup evidence remain pending.

Two rollback-only hosted key tests verified assurance and tenant restrictions, independent destruction approval, preservation holds, exact schedule revisions, idempotent commits and retained historical wrappers. Zero Auth accounts and zero fixture key versions remained. These tests used synthetic capsules. External KMS ownership, provider operations, and recoverability still require hosted verification with the intended provider.

The `sectalk-v6-pilot` project uses Vercel Authentication for all deployments and runs in the Hobby workspace for private evaluation with paid billing disabled. The v6 Supabase project has the 359-migration baseline. Apply the eight later migrations before verifying the full prerelease against that backend. The `vjayces-projects` workspace previously hosted the isolated `sectalk-oidc-issuer-qa` project. Its temporary Vercel Sandbox completed testing and stopped.

The new v6 Supabase project uses Free tier. Local Docker projects supply isolated database and browser verification. The portable recovery drill supports manual database and Storage backups. Managed branching, automatic backups and point-in-time recovery are outside the Free plan. [Supabase Free plan limits](https://supabase.com/pricing) · [Manual recovery drill](DISASTER_RECOVERY.md)

The public v5 JavaScript bundles reference the existing `sectalk` Supabase project. Its recorded migration history has eight applied entries and the v6 RPCs are absent. Seven applied SQL digests match the v5 tag after accounting for trailing whitespace. The deployed live-notifications SQL has a different digest and needs reconciliation before a shared-schema upgrade.

The disposable v5 upgrade rehearsal passed the tagged v5 database tests and uploaded and downloaded a synthetic attachment via v5's normal Storage calls. After the first v6 file download migration, the same v5 recipient could no longer download it directly. The original private bytes remained intact. V6 moves upload, publication and download to its protected server endpoints.

The same disposable database accepted all subsequent v6 migrations with existing synthetic users and a message in place. The tagged v5 contracts passed for session continuity, password sign-in for an account without MFA, text send and receipt, reporting, and calls between v5 clients. A v5 client could not accept a device-bound v6 call. The old data requests were blocked for a fresh password session with an enrolled authenticator, and an effective Community Rules version blocked v5 send and call actions until acceptance. Code review also found that installing the v6 signup hook would require an admission permit that v5's direct signup request omits. V5's meeting token endpoint only admits standard meetings.

A shared-project upgrade requires a v5 compatibility release covering protected attachments, mixed-version calls, and the project-wide Auth and policy prompts, followed by a verified cutover. A separate v6 Supabase project keeps the current v5 client and backend live through deployment. The hosted `sectalk` schema and configuration received no changes during the rehearsal.

The matrix uses BLOCKED_EXTERNAL only when the implementation and its test-mode proof are present. Missing configuration and missing code are tracked separately.
