# SecTalk 3.0.0

## Try the new workflows

The main navigation exposes Inbox, Calls, Workspaces, Meetings, Vault, Search, Notifications, Safety, Billing, and Profile. On phones, all sections are visible in a two-row navigation bar.

- **Meetings** lets workspace owners and admins schedule sessions, open the waiting room, admit or decline attendees, and end the session. Attendees can request entry and follow their admission status. For group audio, video, and screen sharing, configure LiveKit and validate both sides of a call before enabling access for customers.
- **Vault** encrypts a file and its filename in the browser with a passphrase before upload. Each user's objects are private. Files are up to 8 MiB and the uploader needs the original passphrase to recover them.
- **Search** finds matching direct messages, workspace channel posts, board entries, and meetings using the signed-in user's access. Open it from the sidebar or with Ctrl+K or Cmd+K.
- **Notifications** shows meeting schedules and admission decisions with individual and bulk read controls.
- **Profile** lets users share an online, away, or busy status with accepted contacts. The status expires when the app stops refreshing it. Offline hides availability from contacts.
- **Calls** filters call history into all calls, audio, or video. **Workspaces** exposes Channels, Board, People, and an Activity tab for owners and admins. **Billing** separates your subscription from plan comparison. **Safety** opens your own reports and offers a staff console to authorized accounts, with MFA required for case access.

## Deployment

Set the v3 production app URL and allow its exact `/auth/confirm` URL in Supabase Auth. Every deployment using the shared Supabase project needs its own allowed redirect. For automatic production email delivery, configure custom SMTP and apply the repo's confirmation and recovery templates. Test with fresh mail because existing links retain their original URL or may have expired.

Group media requires `LIVEKIT_URL`, `LIVEKIT_API_KEY`, and `LIVEKIT_API_SECRET`. Paid checkout and the customer portal require Stripe settings and webhook delivery. Use the environment template for server-only variables.

The [consolidated specification](MASTER-PROMPT.md) describes the broader product. Remaining work includes end-to-end encrypted messaging and its device lifecycle, enterprise identity, shared attachments and malware scanning, production AI and SOC integrations, meeting recording and transcription, push notifications, and enterprise reporting and infrastructure. Validate each of those workflows before marketing or enabling it.
