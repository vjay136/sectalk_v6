# SecTalk by Eagle Security

SecTalk is a web messaging service built around consent to contact. Users sign in with email codes, approve new contacts, and then exchange live messages or start one-to-one audio and video calls. They can block contact, report abuse or fraud, and choose whether to share a specific message with safety staff. Authorized staff use authenticator MFA to review evidence and record moderation decisions.

## Run locally

Requires Node.js 22 or 24 and npm.

1. Run `npm ci`.
2. Copy [the environment template](apps/web/.env.example) to `apps/web/.env.local`. Set the project URL and publishable key.
3. Apply [the Supabase migration](supabase/migrations/202611200001_sectalk.sql) to the target project using the Supabase SQL Editor or your migration workflow.
4. Set the Supabase Auth **Magic Link** template to send the code from [this HTML template](supabase/templates/magic_link.html). Enable email signup. Configure custom SMTP for public email delivery. Set the Site URL and allowed redirects for your deployment.
5. Run `npm run dev` and visit `http://localhost:3000`.

The browser uses the Supabase publishable key and the signed-in user's JWT. Neither Vercel nor the browser requires a Supabase secret key. A replacement Supabase project needs its own schema migration, OTP template, SMTP settings and environment variables. Database state and login sessions stay with the old project. Revoke the previously shared Supabase secret key or delete the disposable project when it is no longer needed.

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

## Verify

- `npm test` checks local scam and URL warning rules.
- `npm run typecheck && npm run build` checks the TypeScript and production build.
- `/api/health` checks environment presence. Use the SQL verification script in a database SQL Editor to test consent, permissions and moderation. It rolls back its fixtures.
- Use two different accounts in isolated browser profiles to verify OTP, request acceptance, live messages, incoming call notifications, mute and hang-up, two-way video, reconnection, block enforcement and report submission. Test on separate networks with relay enabled. Open the staff console with an independent staff account to verify role and MFA gates.

See [features.md](features.md) for the architecture and delivery scope.
