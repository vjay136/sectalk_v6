# SecTalk Operator Console

`apps/admin` is an independently runnable Next.js app for direct-message moderation, workspace room and channel reports, threat triage, SOC response actions, vulnerability disclosure review, platform account administration, notification dead letters, service health, and managed search operations. Use a separate HTTPS origin for the operator deployment. It uses the existing account security and operator assignments in the selected SecTalk Supabase project.

Set `NEXT_PUBLIC_SUPABASE_URL` and `NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY` to the intended release project and `SECTALK_APP_URL` to the operator origin. For consented evidence downloads, configure the existing server-only `SECTALK_FILE_STORAGE_KEY` and a distinct `SECTALK_FILE_TICKET_SECRET` for this origin. Use `npm run build --workspace @sectalk/admin` for the standalone build and `npm run dev --workspace @sectalk/admin -- --hostname 127.0.0.1 --port 3597` to start it locally.

## Provision named operators

Use the separate v6 Supabase project. The owner first creates a SecTalk account, confirms the email address, completes the profile and enrolls a TOTP authenticator in Profile → Security. In that project's SQL Editor, a database administrator finds the exact account UUID in Authentication → Users and records the approved scope. Provision one capability at a time using the approved account and reference.

```sql
select sectalk_private.st_v8_provision_operator(
  '<verified-account-uuid>'::uuid,
  '<confirmed-email>',
  'moderation',
  '<approval-reference>'
);
```

Use `account_operator` for the account-management role or `account_reviewer` for independent approval of eligible authenticator resets. An account can hold only one of those two account-management roles. Other console capabilities retain their separate assignments. The function checks the UUID, confirmed email and enrollment, then records the granted capability and approval reference in the private database audit. Repeating the same grant returns false and keeps the original audit entry.

Share the separate Admin URL with the named operator. They sign in with their own SecTalk credentials and enter a current authenticator code. Before handing over the URL, verify the assigned tabs, denial for an ordinary account, and an action against a disposable test account. Remove the exact grant from its native assignment table to revoke it and check that the console closes on its next access refresh.

Moderation requires active staff and a verified authenticator. The standalone portal admits the operator with signed TOTP proof from the last ten minutes. The reused moderation queue includes filters, deadlines, consented evidence, decisions, staff collaboration, case escalation, eligible SOC response actions, and case history. Existing database functions enforce each action’s staff and case permissions. Queue operations additionally require the queue-operator assignment and a fresh native database TOTP record on each queue read and action. The console updates role access on its next check and signs out an idle browser view after fifteen minutes. The existing Safety center reuses its moderation queue and retains its own native access checks.

When resolving or dismissing a direct-message report, enter a private staff reason and a separate summary for the person who filed the report. The reporter sees the shared summary in Safety → My reports. The staff reason stays in the restricted audit log.

The open Moderation queue refreshes through a Realtime signal when a report is filed, removed, or changes status or priority. Staff with a current authenticator session can receive the signal. The queue fetches the actual reports through its existing access checks and also refreshes periodically and on reconnect.

Vulnerability disclosures arrive from the consumer site’s public report form. The Admin tab uses a separate disclosure assignment and the native five-minute TOTP requirement on every read and action. The server-only `SECTALK_DISCLOSURE_ENCRYPTION_KEY` must match the public intake’s key. The public intake’s service credential is required on the consumer origin only.

Authorized managed-room evidence downloads also use the existing v6 key custody configuration. Set `SECTALK_KMS_WRAPPING_KEY` for managed custody and the matching `SECTALK_EXTERNAL_KMS_URL`, `SECTALK_EXTERNAL_KMS_TOKEN` and `SECTALK_EXTERNAL_KMS_KEYS` if external custody is enabled. Keep these values server-only. [Artifact key custody](../EXTERNAL_TENANT_KEYS.md)

Workspace owners and administrators can sign in to review eligible room and channel reports. The database limits their queues to consented handoffs and checks workspace membership, channel access, room assignment, and permitted actions. Platform Safety staff retain the platform queues, including reporter notes and explicit handoff controls. Managed room evidence uses the existing protected read endpoint and requires the same file-storage and tenant key configuration as the consumer’s Platform Safety console.

Platform account administration requires the separate native operator or reviewer assignment and current TOTP. Operators manage eligible native sessions and request authenticator recovery. Independent reviewers can approve matured recovery requests. The database enforces protected-account exclusions, role-specific actions and audit attribution. The tab also includes the existing high-risk sessions and threat map views.

Threat triage uses native reviewer assignments per signal type and displays only the existing scoped detection, attachment inspection and malware signals. A separate Response actions tab requires an active native SOC grant. Each response applies its existing case or policy scope and requires a reason and an independent approver. The database checks current authenticator proof for reads and actions and preserves the decision history.

The operator browser tests use the disposable `v4-auth-qa` Supabase project and the same `SECTALK_STORAGE_TEST_*` and browser overrides as `tests/queue-operations.e2e.mjs`. `tests/operator-workspace-reports.e2e.mjs` covers platform handoff and scoped workspace decisions. `tests/operator-account-administration.e2e.mjs` covers role isolation, native session revocation and audit attribution. `tests/operator-threat-response.e2e.mjs` covers scoped triage and independently approved policy enforcement. The disclosure test starts the consumer and operator production builds on separate local ports. Incident linking, full separate tenant admin and SOC consoles, enforced staff SSO or passkeys, and a hosted operator project remain pending for this origin.

The Audit logs tab appears only for workspaces returned by the existing scoped audit eligibility check. Search, workspace SSO and signed-export authorization continue to use the native workspace rules; staff status alone does not grant tenant access. Configure server-only `SECTALK_AUDIT_SIGNING_PRIVATE_KEY` with the same base64url-encoded Ed25519 PKCS #8 DER key used by Web for a consistent signing identity. `SECTALK_FILE_STORAGE_KEY` enables private persistence of generated exports; signing and immediate download remain available without persistence. The export endpoint also requires current operator console admission.
