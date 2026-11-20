# SecTalk by Eagle Security

SecTalk is a web messaging service built around consent to contact. Users create a password, verify their email with a confirmation link, and then sign in with email and password. Password recovery uses a numeric code. They can approve contacts, exchange live messages, make one-to-one audio and video calls, and choose whether to share a specific message with safety staff. Authorized staff use authenticator MFA to review evidence and record moderation decisions.

## Run locally

Requires Node.js 22 or 24 and npm.

1. Run `npm ci`.
2. Copy [the environment template](apps/web/.env.example) to `apps/web/.env.local`. Set the project URL and publishable key.
3. Apply the SQL files in [supabase/migrations](supabase/migrations/) in filename order using the Supabase SQL Editor or your migration workflow.
4. In Supabase Auth, enable email signup and **Confirm email**, configure custom SMTP, and set Site URL to the deployment origin without a trailing slash. Under **Email Templates**, paste [confirmation.html](supabase/templates/confirmation.html) into **Confirm signup** and [recovery.html](supabase/templates/recovery.html) into **Reset password**. The signup link opens `/auth/confirm` for email verification and displays the sign-in URL. The reset email provides a numeric code.
5. Run `npm run dev` and visit `http://localhost:3000`.

The browser uses the Supabase publishable key and the signed-in user's JWT. Neither Vercel nor the browser requires a Supabase secret key. A replacement Supabase project needs its own schema migration, OTP template, SMTP settings and environment variables. Database state and login sessions stay with the old project. Revoke the previously shared Supabase secret key or delete the disposable project when it is no longer needed.

Existing accounts created with passwordless sign-in can use **Forgot password** to set their first password. The Magic Link template applies to passwordless sign-in only. Supabase hosts auth templates independently from Vercel and the database migration.

## Staff access

Have the staff member verify an email code and create a SecTalk profile. Confirm the correct identity in Supabase Auth before running the following with a database operator account. Replace the UUID placeholder.

```sql
insert into sectalk_private.staff (user_id)
values ('<verified-auth-user-uuid>'::uuid)
on conflict do nothing;
```

The staff member can open **Safety center → Staff console** and enroll a TOTP authenticator. The database checks staff membership and MFA on every evidence or moderation request. To revoke eligibility, remove that row from `sectalk_private.staff`.

## Deploy on Vercel

Import `vjay136/sectalk_ver2`, select **Next.js**, and set the project's Root Directory to `apps/web`. Keep access to files outside the Root Directory enabled so Vercel can read the npm workspace and lockfile. Set the two public variables from [the template](apps/web/.env.example) before building. Use a separate Supabase project for preview environments holding test data.

Calls use Supabase for signaling and WebRTC for media. With no TURN configured, browsers attempt direct connections using STUN. Direct connections can disclose network information to the other participant and can fail across restrictive networks. Configure a Coturn deployment with a shared secret and quotas before a public release. Set `TURN_URLS` with the relay endpoints and `TURN_SHARED_SECRET` as a server-only secret. The ICE API issues short-lived credentials to authenticated users and enables relay-only mode when TURN is configured. Validate UDP and TLS relay paths on separate networks.

Calls → Network diagnostics runs browser-only probes when requested. Set `CALL_DIAGNOSTICS_TURN_URLS` and `CALL_DIAGNOSTICS_TURN_SECRET` for a dedicated relay with its own credential scope and allocation quotas. Configure `turn:` UDP and TCP endpoints and a `turns:` endpoint with a trusted certificate on port 443. Set `CALL_DIAGNOSTICS_BANDWIDTH=1` to enable the bounded data-channel estimate. `CALL_DIAGNOSTICS_STUN_URL` overrides the regular STUN endpoint for diagnostics.

For signed workspace audit exports, configure `SECTALK_AUDIT_SIGNING_PRIVATE_KEY` as base64url-encoded Ed25519 PKCS #8 DER. Distribute the trusted signer fingerprint through an independent channel and retain the public key for old exports when rotating keys. The public endpoint at `/api/audit/export` returns the SPKI key and SHA-256 fingerprint. Verify an export's `signature` over the exact UTF-8 `payload` string with the trusted key before using the enclosed entries.

## Verify

- `npm test` checks local scam and URL warning rules.
- `npm run typecheck && npm run build` checks the TypeScript and production build.
- `/api/health` checks environment presence. Use the SQL verification script in a database SQL Editor to test consent, permissions and moderation. It rolls back its fixtures.
- Use two different accounts in isolated browser profiles to verify signup links, password login, recovery codes, request acceptance, live messages, incoming call notifications, mute and hang-up, two-way video, reconnection, block enforcement and report submission. Test on separate networks with relay enabled. Open the staff console with an independent staff account to verify role and MFA gates.

See [MASTER-PROMPT.md](MASTER-PROMPT.md) for the consolidated product specification and [RELEASE-v5.md](RELEASE-v5.md) for the current release scope.
