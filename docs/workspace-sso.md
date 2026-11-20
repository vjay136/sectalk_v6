# Enterprise workspace SSO

Workspace owners can configure single sign-on under **Workspaces → Integrations → Single sign-on**. Verify your email domain under **Organization settings** first. The workspace needs Enterprise entitlement. Changes require fresh authenticator verification.

Register enterprise providers in Supabase Auth as an operator. SecTalk uses the native provider's HTTPS transport, signed assertions or tokens, and authorization-code exchange.

- For SAML, register the domain against the native SAML provider. Use the ACS URL and service-provider entity ID from Supabase Auth.
- For OpenID Connect, register a native **Custom OAuth/OIDC** provider with type OIDC and verified email support. Set the corresponding operator-approved domain and full `custom:...` identifier in the private `st_v7_oidc_domain_approvals` table. External third-party JWTs do not use this flow.
- Add the exact `/auth/workspace-sso` page at the configured app origin to Auth's redirect allowlist. Set `SECTALK_APP_URL` to the app origin and set `SECTALK_SSO_SERVICE_KEY` in server-only configuration. Leave `SECTALK_SSO_AUTH_URL` unset for the default Supabase Auth origin. An operator can override it only with a trusted gateway for the same Auth project. Protect the SSO API with your deployment's public login rate controls.
- Optional just-in-time admission creates an ordinary workspace member after verified domain and provider checks. Existing members keep their roles when the provider returns their existing Auth account. SecTalk does not merge distinct accounts by email. Removing a member prevents this workflow from automatically re-enrolling that account.
- Changing or disconnecting the provider invalidates the recorded workspace sign-in provenance. Ordinary account sign-in, recovery, and membership rules continue to apply. A password session cannot be used as proof of this SSO procedure.

## Member meeting media

An opt-in policy can require a live receipt from the pinned provider for newly issued member meeting media credentials. It covers managed meeting credentials and their network checks, and protected meeting credentials after existing admission and verification. The control requires a fresh owner authenticator and a live sign-in already observed for the selected workspace provider before activation. A provider change, disablement, removal or loss of domain verification leaves the policy closed until the owner verifies the replacement and pins it or uses fresh authenticator verification to disable the requirement.

## Workspace authorization coverage

| Surface | Current enforcement |
| --- | --- |
| Member meeting media credentials | Optional receipt gate at the managed and protected token endpoints. Existing admission and cryptographic checks still apply. |
| Active provider connections and previously issued media credentials | Existing media provider semantics apply until disconnect or credential expiry. In-flight issuance may complete under the policy it checked. |
| Guest meetings, guest rooms and media workers | Independent guest or worker capabilities. Guest links, recording and caption egress retain their own policies. |
| Workspace, people, rooms and channels, attendance, schedules, boards and tasks | Direct database policies and RPCs use workspace membership, room roles or scoped permission logic. The receipt gate does not cover these operations. |
| Managed message content, thread summaries, search, realtime and offline state | Separate content RLS, ticket, indexing, subscription and local caching paths. These still require review before workspace-wide enforcement. |
| File bytes and shares, exports, evidence and held artifacts | Separate current-actor, service-role handoff, guest capability and background job checks. Previously issued capabilities require separate review. |
| Billing, workspace administration, invites, integrations, SCIM and scheduled operations | Existing role, assurance and capability boundaries apply. Owner recovery uses a current native authenticator. |

Workspace-wide enforcement remains pending. Native SAML has been exercised against an isolated signed fixture. Native OpenID Connect completion requires an approved, reachable HTTPS provider. The local-only fixture is rejected by Supabase's private-network guard.
