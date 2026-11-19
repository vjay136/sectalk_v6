# SecTalk 2.0.0

Version 2 is maintained on the GitHub branch release/v2.0.0 and deployed to the separate sectalk-v2 Vercel project. The original SecTalk project uses main. Both releases currently use the same Supabase project. The new migrations add tables and fields and preserve the original browser client's API.

## In this release

- Email confirmation accepts the Supabase signup callback and displays an acknowledgement with the sign-in URL. Invalid and expired links show recovery guidance.
- Direct chats support replies, search, edit history, reactions, pins, read receipts, typing indicators, unread markers, and mute for in-app notifications.
- One-to-one video calls support screen sharing on browsers with display capture. Microphone capture requests echo cancellation and noise suppression.
- Workspaces support member invitations and consent, owner and admin roles, realtime channels, tasks, notes, calendar events, announcements, and a role-scoped activity log.
- Billing displays Free, Basic, Professional, Business, and Enterprise limits. Configured Basic, Professional, and Business prices can use monthly and annual Stripe checkout. Signed webhooks update subscription state. Customers can use the Stripe billing portal. Checkout supports Stripe promotion codes.

## Supabase Auth

Set the project Site URL to the original application's origin and add the new application origin and its /auth/confirm path to the redirect allowlist. Preserve existing allowed redirect URLs. Request a fresh link if an earlier one points to localhost or has expired.

- Original Site URL is https://sectalk-ver2.vercel.app
- New deployment origin is https://sectalk-v2.vercel.app
- New confirmation callback is https://sectalk-v2.vercel.app/auth/confirm

With custom SMTP enabled, install the signup and recovery templates in supabase/templates. The signup template honors the allowed redirect and puts the token in the browser fragment. The recovery template sends a code. The new route also accepts a valid signup session returned by the standard Supabase confirmation link. Verify fresh signup and password recovery emails before inviting users.

## Database and billing

Apply the workspaces/billing and chat-controls migrations after the base schema and private Realtime migration. Run tests/v2-database.sql. It rolls back its fixtures.

Create Stripe recurring prices for paid self-service plans and set their IDs in the v2 Vercel project. Set STRIPE_SECRET_KEY, STRIPE_WEBHOOK_SECRET, SECTALK_APP_URL, and a new server-only SECTALK_BILLING_SUPABASE_KEY. Configure the Stripe endpoint /api/billing/webhook to receive customer.subscription.created, customer.subscription.updated, and customer.subscription.deleted. Set up the Stripe customer portal for the supported plans and cancellation policy.

Workspace limits are initial product defaults enforced in SQL. Currency, prices, trials, taxes, and invoices depend on Stripe configuration. Enterprise contract and seat billing require a separate rollout. Verify checkout, renewal, failed payment, cancellation, and retries in Stripe test mode before accepting payments. The app disables checkout until its provider is configured.

## Further work from the brief

- Identity and access. Passkeys, phone sign-in, social providers, enterprise SSO, device binding, login risk, and recovery codes require provider setup and identity testing.
- Privacy and safety. End-to-end encryption with device verification and recovery, anonymous or timed chat, a private vault and attachment scanning, AI-assisted moderation, QR inspection, and full SOC controls require security design, infrastructure, and independent review.
- Collaboration and calls. Group media, scheduled meeting rooms, waiting rooms, recording, captions, transcription, whiteboard, polls, call transfer, and call queues require a media and collaboration rollout. The current calendar tracks workspace events.
- Business operations. Razorpay, Cashfree, enterprise contracts, advanced invoicing, tax, refunds, compliance, incident response, load testing, and disaster recovery require integration and acceptance work.

Use test payments and test data until email delivery, billing, and call reliability have been verified in the intended deployment.
