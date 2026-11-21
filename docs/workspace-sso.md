# Enterprise workspace SSO

Workspace owners can configure single sign-on under **Workspaces → Integrations → Single sign-on**. Verify your email domain under **Organization settings** first. The workspace needs Enterprise entitlement. Changes require fresh authenticator verification.

Register enterprise providers in Supabase Auth as an operator. SecTalk uses the native provider's HTTPS transport, signed assertions or tokens, and authorization-code exchange.

- For SAML, register the domain against the native SAML provider. Use the ACS URL and service-provider entity ID from Supabase Auth.
- For OpenID Connect, register a native **Custom OAuth/OIDC** provider with type OIDC and verified email support. Set the corresponding operator-approved domain and full `custom:...` identifier in the private `st_v7_oidc_domain_approvals` table. External third-party JWTs do not use this flow.
- Add the exact `/auth/workspace-sso` page at the configured app origin to Auth's redirect allowlist. Set `SECTALK_APP_URL` to the app origin and set `SECTALK_SSO_SERVICE_KEY` in server-only configuration. Leave `SECTALK_SSO_AUTH_URL` unset for the default Supabase Auth origin. An operator can override it only with a trusted gateway for the same Auth project. Protect the SSO API with your deployment's public login rate controls.
- Optional just-in-time admission creates an ordinary workspace member after verified domain and provider checks. Existing members keep their roles when the provider returns their existing Auth account. SecTalk does not merge distinct accounts by email. Removing a member prevents this workflow from automatically re-enrolling that account.
- Changing or disconnecting the provider invalidates the recorded workspace sign-in provenance. Ordinary account sign-in, recovery, and membership rules continue to apply. A password session cannot be used as proof of this SSO procedure.

## Member meeting media

Under **Integrations → Single sign-on → Member meeting media**, owners can require a live receipt from the pinned provider for newly issued member meeting media credentials. The policy covers managed meeting credentials and their network checks, and protected meeting credentials after existing admission and verification. Activation requires a fresh owner authenticator and a live sign-in already observed for the selected workspace provider. A provider change, disablement, removal or loss of domain verification keeps the policy closed. After verifying a replacement, owners can use **Use configured provider for member media**. They can also use a fresh authenticator and choose **Allow standard sign-in for new member media** to recover access.

## Standard channel messages

Under **Integrations → Single sign-on → Standard channel messages**, owners can require a current session receipt for reading and posting standard channel messages. New reports that reference a post and both server search entry points use the same post visibility check. Workspace membership, channel visibility and publishing authorization still apply. After a provider change, the scope stays closed until a fresh owner authenticator re-pins a configured provider with a current workspace sign-in or allows standard sign-in again.

This policy applies to newly authorized requests. Supabase Realtime checks post visibility before delivering insert and update contents. Existing private activity announcements carry the channel ID and a Realtime event ID. An unfiltered Realtime subscriber can receive a deleted post's opaque ID because the table uses primary-key replica identity. Previously delivered messages, existing evidence review, managed encrypted channels, and independently authorized background processing retain their existing boundaries.

## Standard room messages

Under **Integrations → Single sign-on → Standard room messages**, owners can independently require a live receipt for standard room messages. Existing room membership and publishing rules still apply. The room stays discoverable for eligible members, and its message panel explains how to sign in when the current session lacks the receipt.

The policy also applies to standard room message search, threads, linked task message previews, writing starter posts from a template, and the live authorization at the room thread-summary endpoint. Enabling the policy revokes guest message links for standard rooms. A provider change closes access until a fresh owner authenticator pins a verified replacement or chooses **Allow standard sign-in for standard room messages**.

## Managed encrypted messages

Under **Integrations → Single sign-on → Managed encrypted messages**, a freshly verified owner can require a live receipt for workspace users to open managed channel and managed room message feeds, publish, search, and submit new message reports. Enabling the policy requires an existing live workspace sign-in from the configured provider. Room membership, channel permissions, and posting rules still apply. The service rechecks the actor and native session recorded on managed message tickets before reading or writing encrypted content, including tickets issued before the policy changed.

Provider disconnect, disablement, or loss of verified domain eligibility closes the content gate. A freshly verified owner can pin a working replacement provider or allow standard sign-in again. Existing submitted evidence, held artifacts, and compliance downloads retain their separate access controls. [Supabase row-level security](https://supabase.com/docs/guides/database/postgres/row-level-security)

## Workspace boards and tasks

Under **Integrations → Single sign-on → Workspace boards and tasks**, a freshly verified owner can require a live receipt from the pinned workspace provider. The setting protects workspace board posts, task updates and checklists, room-scoped tasks, calendar events and task deadlines. Search and task detail queries use the same visibility checks as their underlying records. Existing membership, assignment, room permissions and payment restrictions still apply.

Direct-chat tasks, meeting schedules and workspace membership keep their existing access rules. Changing or disconnecting the provider closes the planner until a freshly verified owner pins a replacement with a live workspace sign-in or chooses **Allow standard sign-in for workspace planning**.

## Workspace authorization coverage

| Surface | Current enforcement |
| --- | --- |
| Member meeting media credentials | Optional receipt gate at the managed and protected token endpoints. Existing admission and cryptographic checks still apply. |
| In-app meeting collaboration | **Workspace entry** requires a current pinned session for admitted users to access the roster, chat, spotlight, hands, reactions, and presenter claim or renewal in standard and room meetings. Safety actions such as meeting shutdown keep their existing authorization. |
| Active provider connections and previously issued media credentials | Existing media provider semantics apply until disconnect or credential expiry. In-flight issuance may complete under the policy it checked. |
| Guest meetings, guest rooms and media workers | Independent guest or worker capabilities. Protected standard rooms revoke guest message links. Recording and caption egress retain their own policies. |
| Standard channel posts | Optional receipt gate for ordinary reads, sends, search results, new post reports, and Realtime insert and update contents. |
| Standard room posts and thread summaries | Optional receipt gate for message-feed queries, publishing and editing, authorized thread queries, Search and the summary endpoint. Membership checks continue to apply. |
| Workspace boards, tasks, room tasks and calendar events | Optional receipt gate for ordinary reads, writes and eligible Search results. Workspace reminders keep their existing participant checks. |
| Channel directory and administration | The **Channel directory and administration** setting requires a current pinned workspace session for discovery, creation, lifecycle changes, manager roster and audit details. Fresh authenticator verification lets the owner recover access after a provider change. |
| Room directory and administration | The **Workspace room directory** setting requires a current pinned workspace session for directory and administration reads, creation, membership decisions and room lifecycle settings. Fresh authenticator verification lets the owner recover administration access after a provider change. |
| Workspace, people, attendance and meeting schedules | Existing workspace membership, room roles and scoped permissions continue to apply. Some standard room actions using the current room role follow its receipt gate. |
| Managed encrypted message content | Optional receipt gate for message feed reads, sends, search, and new reports. The service checks the recorded actor and session at ticket redemption. Channel activity metadata and offline state require separate review. |
| File bytes and shares, exports, evidence and held artifacts | Separate current-actor, service-role handoff, guest capability and background job checks. Previously issued capabilities require separate review. |
| Workspace invitation administration | The **Workspace invitation management** scope adds a current provider receipt to staff listing and issuance, email link and invitation domain policy. Existing invitations still use their own recipient acceptance checks. |
| API key and webhook administration | The **Workspace API keys and webhooks** scope requires the pinned provider receipt and fresh authenticator verification to view or change integration settings. Issued keys and authorized delivery jobs retain their own capability checks. |
| Custom-role administration | The **Workspace custom roles** scope requires the pinned provider receipt and fresh authenticator verification for the role editor and its resource selectors. Existing member assignments retain the rules of the operation they authorize. |
| Workspace overview and analytics | Workspace entry enforcement requires the pinned provider receipt for both dashboard reads. Analytics also requires fresh authenticator verification. |
| SCIM credential management | Workspace entry enforcement requires the pinned provider receipt and fresh authenticator verification to view settings, rotate or revoke a provisioning token. Existing machine credentials continue under the SCIM endpoint's own checks until rotated, revoked or expired. |
| Notification, availability and data loss policies | Workspace entry enforcement checks the pinned receipt for notification and availability reads. Policy changes and the data loss editor also honor the separate policy management scope when enabled. |
| Impersonation watch and profile rule registry | Workspace entry enforcement checks the pinned receipt for manager reads and changes. Only the workspace owner can change registry versions. The rule evaluation service retains its existing service-only permission. |
| Workspace trials and Enterprise orders | Trial status and initiation require the applicable workspace entry and billing receipts. The trial service rechecks the same native session and both policy pins inside the write transaction. Workspace owners and billing delegates need the same receipts for Enterprise quotes and purchase orders. An independently assigned commercial operator retains that separate grant. |
| File-history settings and room reaction policy | File-history settings honor workspace entry and the separate Policy Center sign-in requirement. Workspace members need a current entry receipt for direct reads and Realtime delivery of reaction rules while entry SSO is required. |
| In-app meeting and room mention notices | The inbox and Realtime updates honor workspace entry. Meeting notices also honor the separate schedule requirement where applicable. Individual and bulk acknowledgements check the same scopes, and removed room posts no longer qualify for acknowledgement. |
| Billing, other workspace administration and scheduled operations | Existing role, assurance and capability boundaries also apply. Owner recovery uses a current native authenticator. |

Workspace-wide enforcement remains pending. Native SAML has been exercised against an isolated signed fixture. Native OpenID Connect completion requires an approved, reachable HTTPS provider. The local-only fixture is rejected by Supabase's private-network guard.

The Dashboard’s **Third-Party Auth → Custom OIDC** integration accepts external JWTs. SecTalk workspace sign-in uses **Custom OAuth/OIDC** under Supabase Auth, with the native `custom:...` provider identifier and authorization-code flow. Supabase documents up to three native custom providers on a Free project. The SecTalk workspace entitlement check still applies. [Supabase Third-Party Auth announcement](https://supabase.com/changelog/custom-oidc-third-party-auth) · [Native custom OAuth/OIDC configuration](https://supabase.com/docs/guides/auth/custom-oauth-providers)

For the isolated native rehearsal, deploy the existing `tests/fixtures/oidc-issuer.mjs` only under an approved, reachable HTTPS origin. Preserve its synthetic-only identity and exact callback contract for the disposable GoTrue gateway. Run `node tests/fixtures/oidc-preflight.mjs` with `SECTALK_OIDC_ISSUER` set to that origin. This public, read-only check verifies HTTPS discovery, the exact fixture endpoints, advertised S256 PKCE and public RS256 signing keys. The native browser fixture runs it before registering the disposable provider. Native completion still requires the authorized issuer to be reachable from GoTrue, exact redirect allowlisting, and a passing native sign-in and session test. [Self-hosted native custom OAuth/OIDC](https://supabase.com/docs/guides/self-hosting/self-hosted-custom-oauth-providers)

For a separately authorized disposable hosted project, set the synthetic issuer's `SECTALK_OIDC_DISPOSABLE_PROJECT_REF` to the approved test ref. It pins one default Supabase callback at `https://<test-ref>.supabase.co/auth/v1/callback`. Confirm it against the exact native provider callback displayed in the test project. The existing automated browser harness uses the disposable local GoTrue gateway. Hosted sign-in requires a separately approved native provider registration, the test application's exact redirect, and a scoped SecTalk domain and workspace setup. [Supabase callback URL format](https://supabase.com/docs/guides/platform/custom-domains)
