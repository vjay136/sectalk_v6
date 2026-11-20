# SecTalk security policy

## Report a vulnerability

Open `/security` on the SecTalk deployment you are reporting. Use its private contact when available and coordinate disclosure with the maintainers before publishing sensitive details. If the private channel is unavailable, wait for a confirmed contact and keep report details out of public issues, pull requests, and discussions.

Include the affected deployment or version, the security impact, and a concise description based on accounts and environments you have explicit permission to use. Remove credentials, tokens, private messages, and personal information. Report harmful messages and user conduct through the app’s conversation reporting workflow.

## System and scope

SecTalk comprises a Next.js web app, Supabase Auth, Postgres, Storage and Realtime, with external media and billing integrations where configured. Treat signed-in users, browser requests, uploads, and provider callbacks as untrusted until the relevant server or database boundary validates them. Review both normal application entry points and the permissions exposed directly by Supabase.

## Security invariants

- Membership and permission checks must run before reading or mutating another account’s or workspace’s data.
- Supabase tables, RPCs, Realtime and Storage must enforce current access independently of the browser UI.
- Admin and moderator actions must check role, scope and required authentication assurance before changing account state or exposing report evidence.
- Authentication and account recovery must validate proof of account control, handle sessions safely and limit redirects to trusted destinations.
- Provider integrations must verify message authenticity or identity before trusting data or modifying application state.
- Secrets and private account data must stay out of public bundles, caches, logs and public readiness routes.

## Triage

Explain who could reach the affected code, the permissions required, whose data or account is affected, and whether the impact crosses accounts or workspaces. Prioritize account takeover, unauthorized moderation or payments, and unauthorized access to conversations, attachments, or report evidence. Get explicit authorization before testing a live service.

## Deployment setup

Set `SECTALK_APP_URL` to the deployment’s stable HTTPS origin. Set `SECTALK_SECURITY_CONTACT` to a verified, monitored `mailto:` address or HTTPS private reporting form. Set `SECTALK_SECURITY_CONTACT_EXPIRES` to a UTC timestamp such as `2027-03-01T00:00:00Z`, in the future and less than 365 days away. Reverify that the contact accepts reports before renewing the expiry. Once configured, confirm that `/.well-known/security.txt` and the visible contact on `/security` agree. A missing or expired configuration returns HTTP 503 for the machine-readable file.
