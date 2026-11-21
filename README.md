# SecTalk by Eagle Security

SecTalk is a web messaging service built around consent to contact. Users create a password, verify their email with a confirmation link, and then sign in with email and password. Password recovery uses a numeric code. They can approve contacts, exchange live messages, make one-to-one audio and video calls, and choose whether to share a specific message with safety staff. Authorized staff use authenticator MFA to review evidence and record moderation decisions.

## Run locally

Requires Node.js 24.7 or later in the 24.x series, or Node.js 26.x, and npm.

1. Run `npm ci`.
2. Copy [the environment template](apps/web/.env.example) to `apps/web/.env.local`. Set the project URL and publishable key.
3. Apply the SQL files in [supabase/migrations](supabase/migrations/) in filename order using the Supabase SQL Editor or your migration workflow.
4. Set `SECTALK_APP_URL` to your local app origin for local testing or the public HTTPS origin for a deployment. In Supabase Auth, enable email signup and **Confirm email**, configure custom SMTP, set Site URL to the same origin, and allow its exact `/auth/confirm` URL. Under **Email Templates**, paste [confirmation.html](supabase/templates/confirmation.html) into **Confirm signup** and [recovery.html](supabase/templates/recovery.html) into **Reset password**. The signup link opens `/auth/confirm` for email verification and displays the sign-in URL. The reset email provides a numeric code.
5. Run `npm run dev` and visit `http://localhost:3000`.

For a single SQL file, run `node scripts/build-supabase-schema.mjs sectalk-schema.sql` from the release checkout. Run it once against a fresh, initialized Supabase project with `psql -v ON_ERROR_STOP=1 -f sectalk-schema.sql`. Use the intended project's database connection through your normal private credential setup. Each migration and its Supabase history entry commit together. The generator reports the migration count and SHA-256. If installation stops partway, inspect its error and migration history before continuing. Use the repository's migration files for upgrades.

The browser uses the Supabase publishable key and the signed-in user's JWT. The hosted server needs its own server-only credentials for enabled operations such as signup admission and protected file delivery. A replacement Supabase project needs its own schema migration, email templates, SMTP settings and environment variables. Database state and login sessions stay with the old project. Revoke any shared secret keys for projects you retain.

Existing accounts created with passwordless sign-in can use **Forgot password** to set their first password. The Magic Link template applies to passwordless sign-in only. Supabase hosts auth templates independently from Vercel and the database migration.

Enable **Secure email change** and allow the app origin as an Auth redirect. Keep email autoconfirm disabled so GoTrue sends confirmation to both addresses. SecTalk waits 24 hours before releasing a confirmed-address change or authenticator reset. The existing numeric password reset remains available as soon as the OTP is verified.

SecTalk caps native sessions at 30 days after sign-in or 7 days without a refresh. For strict refresh-token reuse protection on self-hosted GoTrue, enable rotation and use the counter-based refresh-token algorithm. Keep the 10-second reuse allowance for concurrent refreshes. On managed Supabase, verify the equivalent policy and test that a stale ancestor revokes its latest descendant. Already issued JWTs can retain access until expiration on provider surfaces that do not recheck the session.

```dotenv
GOTRUE_SECURITY_REFRESH_TOKEN_ROTATION_ENABLED=true
GOTRUE_SECURITY_REFRESH_TOKEN_ALGORITHM_VERSION=2
GOTRUE_SECURITY_REFRESH_TOKEN_ALLOW_REUSE=false
GOTRUE_SECURITY_REFRESH_TOKEN_REUSE_INTERVAL=10
GOTRUE_SESSIONS_TIMEBOX=720h
GOTRUE_SESSIONS_INACTIVITY_TIMEOUT=168h
```

The device registry uses secure browser storage and requires the server-only `SECTALK_DEVICE_BUNDLE_SERVICE_KEY` to finish device enrollment after verifying the signing key. Managed status requires a trusted management integration calling the provider-only registry procedure. The registry publishes approved public keys for authorized direct contacts. End-to-end message encryption is a separate protocol.

Remote revoke ends the device's linked sessions immediately. A lock prevents the same registered browser from using or re-enrolling its keys until the account holder verifies their credentials. A key wipe waits for that browser to reach SecTalk and acknowledge deletion of its registered signing and agreement keys. A pending command can be cancelled before dispatch. Cancelling keeps any ended sessions signed out.

Login alerts use the browser family and network prefix already observed by GoTrue. The detector requires both signals to differ from active trusted sessions. Alerts expose only the sign-in time and review status. Account lockdown requires a PostgREST pre-request guard and the existing Auth SMTP setup. The migration stops if a different pre-request hook is configured. Preserve that hook and integrate a call to the lockdown guard when applying the migration.

The app password gateway returns the same failure for unknown, wrong, and unconfirmed credentials. To apply that behavior at the provider boundary, route public password sign-ins through the app and set `SECTALK_AUTH_PASSWORD_UPSTREAM` to a private Supabase-compatible gateway URL. Keep the native password grant available only to that gateway. If managed GoTrue exposes its native grant directly, its own error behavior still applies there. Configure the Supabase **Magic Link** template with [magic_link.html](supabase/templates/magic_link.html) for numeric step-up codes. SecTalk also accepts a verification link issued by the configured Auth provider.

Passkeys require a Supabase Auth version with native passkey routes and the `auth.webauthn_credentials` table. Enable passkeys in Auth, configure the relying-party ID and exact HTTPS app origin, and set `NEXT_PUBLIC_SECTALK_PASSKEYS_ENABLED=true` when building the app. Local WebAuthn QA uses the `localhost` relying party and `http://localhost:3489` origin. Users can manage passkeys in Profile → Security. Turning on passwordless-only ends sessions that started without a passkey and makes password-based recovery unavailable until the user restores password sign-in after a fresh passkey sign-in. [Supabase passkey setup](https://supabase.com/docs/guides/auth/passkeys)

For sign-in risk scoring, configure `SECTALK_AUTH_RISK_SERVICE_KEY` as a server-only Supabase service credential and `SECTALK_AUTH_RISK_IDENTIFIER_SECRET` as a separate random secret of at least 32 characters. These enable velocity and pseudonymous failed-attempt scoring for password grants handled by the app gateway. A browser unfamiliar to the account's trusted devices is also a signal. Exposing the native password grant directly lets those requests skip the gateway-specific signals. The native unfamiliar-browser-and-network step-up still applies on direct grants.

With those sign-in settings, the gateway also limits password requests before submitting credentials to Auth. It uses Vercel's ingress-provided client network when available and a shared budget when trusted client IP data is unavailable. Attachment routes use the current native session and, when available, its recorded network, bound device, and the user's authorized workspace. Elevated session risk tightens the account and device budgets. Counters use pseudonymous keys and expire automatically. The native Auth and database action limits continue to cover requests outside these routes.

Set the server-only `SECTALK_SIGNUP_ADMISSION_SERVICE_KEY` or reuse `SECTALK_AUTH_RISK_SERVICE_KEY` for the signup gateway. Configure the native Before User Created hook to run `public.st_v7_before_signup` on the public Auth ingress. For self-hosted GoTrue, enable `GOTRUE_HOOK_BEFORE_USER_CREATED_ENABLED` and set `GOTRUE_HOOK_BEFORE_USER_CREATED_URI=pg-functions://postgres/public/st_v7_before_signup`. The hook guards direct native signup and account creation by email OTP. Use `SECTALK_AUTH_SIGNUP_UPSTREAM` when confirmation and resend traffic needs a separate native Auth origin. Keep it on the same Auth database. [Supabase Before User Created hook](https://supabase.com/docs/guides/auth/auth-hooks/before-user-created-hook)

Signup applies the adaptive admission policy, checks the padded five-character Pwned Passwords range, and consumes an expiring, email-scoped permit. Supabase Auth receives an Argon2id verifier for a new unconfirmed account, then sends the verification email through its native mailer. Existing accounts keep their credentials. A signup blocked during delivery can use the existing resend flow. Password recovery continues through Supabase Auth with a numeric email code. Verify the retained credential format and the deployed confirmation URL on the release Auth configuration. [Pwned Passwords API](https://haveibeenpwned.com/API/v3#PwnedPasswords)

To use an independent signed IP reputation and location feed, set `SECTALK_AUTH_RISK_FEED_URL` to its HTTPS URL and `SECTALK_AUTH_RISK_FEED_PUBLIC_KEY` to its Ed25519 public key as base64 SPKI DER. The feed returns JSON with base64url `payload` and `signature` fields. Sign the decoded payload bytes, a UTF-8 JSON object with epoch-millisecond `issuedAt` and `expiresAt` timestamps (up to 48 hours apart), and an `entries` array. Each entry has `cidr`, `asn` (number or null), `reputation` (`normal`, `poor`, or `unknown`), booleans `tor` and `vpn`, and all four numeric location fields `latitude`, `longitude`, `radiusKm`, `confidence` (0–100), or null for all four. The response limit is 1 MiB and 5,000 entries. SecTalk matches the most specific subnet locally and sends no session IP or account identifier to the feed. Use an ingress which records the real client network in the native session. Geolocation counts only when both observations meet the confidence and accuracy limits, the prior observation belongs to a trusted device, and the elapsed time is within six hours. An unavailable or unmatched feed contributes no network score. Account owners can review indicators and end individual sessions from Devices and sessions.

## Staff access

Have the staff member verify an email code and create a SecTalk profile. Confirm the correct identity in Supabase Auth before running the following with a database operator account. Replace the UUID placeholder.

```sql
insert into sectalk_private.staff (user_id)
values ('<verified-auth-user-uuid>'::uuid)
on conflict do nothing;
```

The staff member can open **Safety center → Staff console** and enroll a TOTP authenticator. The database checks staff membership and MFA on every evidence or moderation request. To revoke eligibility, remove that row from `sectalk_private.staff`.

## Deploy on Vercel

After the scoped [v6 verification](docs/DEPLOYMENT_REPORT.md) and isolated backend setup, import [`vjay136/sectalk_v6`](https://github.com/vjay136/sectalk_v6) into a new project in `silent-soldier-vjay`. Use **Next.js**, set the web project's Root Directory to `apps/web`, and keep access to files outside the Root Directory enabled for the shared npm workspace and lockfile. Use the v6 Supabase project and the [web environment template](apps/web/.env.example). The Admin and Workers use separate Vercel projects.

Calls use Supabase for signaling and WebRTC for media. With no TURN configured, browsers attempt direct connections using STUN. Direct connections can disclose network information to the other participant and can fail across restrictive networks. Configure a Coturn deployment with a shared secret and quotas before a public release. Set `TURN_URLS` with the relay endpoints and `TURN_SHARED_SECRET` as a server-only secret. The ICE API issues short-lived credentials to authenticated users and enables relay-only mode when TURN is configured. Validate UDP and TLS relay paths on separate networks.

Calls → Network diagnostics runs browser-only probes when requested. Set `CALL_DIAGNOSTICS_TURN_URLS` and `CALL_DIAGNOSTICS_TURN_SECRET` for a dedicated relay with its own credential scope and allocation quotas. Configure `turn:` UDP and TCP endpoints and a `turns:` endpoint with a trusted certificate on port 443. Set `CALL_DIAGNOSTICS_BANDWIDTH=1` to enable the bounded data-channel estimate. `CALL_DIAGNOSTICS_STUN_URL` overrides the regular STUN endpoint for diagnostics.

For signed workspace audit exports, configure `SECTALK_AUDIT_SIGNING_PRIVATE_KEY` as base64url-encoded Ed25519 PKCS #8 DER. Distribute the trusted signer fingerprint through an independent channel and retain the public key for old exports when rotating keys. The public endpoint at `/api/audit/export` returns the SPKI key and SHA-256 fingerprint. Verify an export's `signature` over the exact UTF-8 `payload` string with the trusted key before using the enclosed entries.

## Verify

- `npm test` checks local scam and URL warning rules.
- `npm run typecheck && npm run build` checks the TypeScript and production build.
- `npm run verify:tenant-isolation` runs the tenant SQL and Edge suites on the disposable `v4-auth-qa` stack. Use a local v6 build with configured Storage, scanner and LiveKit test services. Supply the browser fixture app, URL, publishable key and service key via the `SECTALK_STORAGE_TEST_*` environment variables, plus the isolated webhook receiver and drain fixture settings used in `tests/workspace-integrations.e2e.mjs`.
- `/api/health` checks environment presence. Use the SQL verification script in a database SQL Editor to test consent, permissions and moderation. It rolls back its fixtures.
- Use two different accounts in isolated browser profiles to verify signup links, password login, recovery codes, request acceptance, live messages, incoming call notifications, mute and hang-up, two-way video, reconnection, block enforcement and report submission. Test on separate networks with relay enabled. Open the staff console with an independent staff account to verify role and MFA gates.

See [MASTER-PROMPT.md](MASTER-PROMPT.md) for the consolidated product specification and [RELEASE-v5.md](RELEASE-v5.md) for the current release scope.
## Workspace trials

Set `SECTALK_WORKSPACE_TRIALS=optional` to offer card-free 14-day Professional and Business workspace trials. Set it to `required` to verify a card with Stripe Checkout in setup mode. The required mode uses the configured Stripe credentials and the signed `checkout.session.completed` event on `/api/billing/webhook`. Stripe confirms the card without starting a paid subscription. The workspace's trial entitlement expires after 14 days and the previously applicable limits resume.
