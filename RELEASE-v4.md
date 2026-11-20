# SecTalk 4.0.0

## Features

- **Rooms** opens the workspace channel list directly. Channel creation requires a workspace owner or admin. Channels remain scoped to workspace membership.
- **Tasks** provides Open tasks, Assigned to me, and Completed. Owners, admins, and task creators can assign an existing workspace member. An assignee can update the checklist and complete the task through the Tasks tab. Assignment and checklist changes are recorded in workspace activity. The shared legacy board still uses its existing task completion rules.
- **Calendar** combines events, meeting times, and task deadlines in a workspace agenda. Use the subtabs to narrow the agenda. Workspace members can create events.
- **Signup** opens a verification screen before consuming the one-time link. The screen displays a sign-in link after successful verification. Password recovery accepts an emailed numeric code and returns to sign-in after the password update.

The previous deployments use the same Supabase project. V4 adds task assignment and checklist tables and a task RPC. Earlier deployment files and existing database contracts continue to serve earlier releases.

## Email configuration and verification

The v4 callback is `https://sectalk-v4.vercel.app/auth/confirm`. In hosted Supabase Auth, add that exact allowed redirect and retain other release redirects. Use the [confirmation](supabase/templates/confirmation.html) and [recovery](supabase/templates/recovery.html) templates with a transactional SMTP sender. Auth configuration is project-wide. A dedicated Supabase project can isolate its mail settings and user database from earlier releases. Email links sent before changing the settings retain their original destination.

To reproduce the browser test, use a local Supabase stack with Mailpit, enable email confirmations, serve the two templates, and use a six-digit email OTP. Set the allowed redirect to the local app origin plus `/auth/confirm`. Run the Next.js app with the local Supabase URL and publishable or anon key. Then run `node tests/auth-mail.e2e.mjs` with Playwright installed. The test defaults to app port 3484 and Mailpit port 55324. It verifies mail receipt, passive link loading, explicit verification, link replay rejection, recovery, and password replacement. The test only accepts loopback URLs.

## Open scope

See the [master specification](MASTER-PROMPT.md) for the complete backlog. Work remains on private room scopes, managed attachment sharing and scanning, reviewed E2EE and device lifecycle, enterprise SSO, expanded moderation and SOC, browser push, group media and recording, billing providers, and production infrastructure and load testing.
