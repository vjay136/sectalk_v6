# SecTalk product and engineering specification

## Product vision and personas

Eagle Security builds SecTalk for people who need control over who can contact them, especially people facing harassment, impersonation or scams. The contact approval, report, and block workflows serve individuals and families first. Community and creator moderators need role-scoped queues and appeals. Small businesses need team spaces, task coordination and clear billing. Healthcare, school, finance and government users need tenant isolation, retention policy, vendor review and verified compliance controls. Enterprise and SOC staff need identity lifecycle management, auditability and case escalation. Measure contact acceptance, message delivery latency, call connection rate, reports acknowledged, repeat abuse and false-positive rates without collecting message bodies for analytics.

## Information architecture and UX

The public page introduces consent, messaging and calls, and provides signup, password sign-in and recovery. The authenticated workspace has labeled Inbox, Calls, Safety and Profile navigation, with contact requests inside Inbox. Desktop uses a rail, contact list and workspace panel. Mobile uses bottom navigation and a single active pane. The visual system pairs the Eagle Security artwork with navy, cyan for primary actions, amber for warnings and red for destructive actions. Interaction uses visible keyboard focus, labeled controls, native modal focus management and reduced-motion support. The briefs also call for light and high-contrast themes, accessible route-level navigation, a command palette, pricing, security, compliance, help and legal pages. Those need design and validation in later releases.

## Messaging, presence and search

- Use the exact handle for a contact request. Recipients can accept, decline, report or block. The database enforces acceptance before sending and blocks new messages in either direction.
- Messages are text only. Render as text and keep links non-interactive. Server timestamps and UUIDs provide ordering and idempotency. Fetch latest and earlier pages with a stable cursor. Private Supabase Broadcast sends refresh hints to each participant's account topic. Postgres Changes also deliver authorized rows. The client catches up on subscription readiness, reconnection, and tab visibility, with polling as a fallback.
- The messaging UI distinguishes delivery to the server from reading by the recipient. This release provides a send confirmation, contact search and connection status. Delivery receipts, read receipts, offline outbox persistence, per-contact presence, message search, edits, deletions, mentions and reactions are planned.
- Search indexes must observe membership and deletion. For E2EE conversations, index only authorized metadata on the server and build body search locally.

## Calls, meetings and WebRTC reliability

- A database call row transitions from ringing to active when the callee answers. Either participant can hang up. Blocking or a safety suspension closes affected calls. Offers, answers and ICE candidates stay scoped to call participants.
- Media starts only after a local call action. The client buffers early ICE candidates, deduplicates signals, includes a polling fallback and attempts an ICE restart on disconnect. Microphone muting, camera controls and preview are available. Configure TURN for restrictive networks and relay-only privacy. A call attempt expires if the other participant does not answer.
- Before broader rollout, validate NAT and transport fallbacks, mobile background behavior, resume, timeouts and congestion with a TURN-backed real-device test matrix. Replace persisted signaling with a bounded relay or enforce short retention and presence leases. Introduce an SFU for group meetings, screen sharing, waiting rooms, roles, liveness, reconnection, quality metrics, recording consent and transcription. Keep media off the Vercel server.

## Rooms, threads, files, tasks and notifications

The initial workspace supports direct conversations. Group rooms will require explicit invitations, tenant-scoped memberships and roles. Threads inherit parent authorization. Tasks will require assignment, due dates, completed events and auditable changes. Files and the vault require private object storage, quarantine, malware scanning, quotas, type validation, expiry and access logging. In-app Realtime events power the active inbox and incoming calls. Push, notification preferences, mutes, digests, calendar and offline email delivery need an idempotent queue with retry and dead-letter handling.

## Threat detection and reporting

Local deterministic indicators flag potentially risky payment requests, credential requests and unusual links. Indicators are advisory and do not fetch links or take action. Reports use explicit categories and share only the selected message and notes. Staff review the evidence and decide whether to close, dismiss or apply a reversible restriction. Future AI assistance should summarize or classify only submitted evidence with purpose and retention limits, optional redaction, evaluation by language, structured output, human approval and an appeals path. Never send routine private messages to an external model. A file or URL inspection service needs isolation, strict outbound network policy, content limits and a separate queue.

## Security and governance

Use email and password with a confirmation link for signup and a numeric code for password recovery, backed by custom SMTP. The confirmation page verifies the Supabase token and directs the user to sign in. Staff actions require an authorized account and an AAL2 JWT. RLS gates reads and narrowly scoped RPCs gate writes. Supabase can access stored message content by design. The initial release uses TLS and database access controls, with browser WebRTC transport encryption for media. Full message E2EE needs a reviewed protocol, device verification, multi-device key backup and rotation, and explicit evidence sharing. Passkeys, device trust, session policy, SSO and scoped organization RBAC remain future work. Browser storage holds the authenticated session. Production security work includes a nonce-based CSP, replay and abuse tests, appeal policy and a privacy/retention review.

## Data model and API contracts

The canonical DDL is in the timestamped Supabase migration. Public tables use the `st_` prefix and RLS. The private schema holds staff, suspensions, counters and audit entries. Chat pairs are unique. Reports capture evidence server-side after verifying that the message belongs to the reporting participant's conversation and was sent by the subject. Reports and audit events stay outside the Realtime publication. Counters are per authenticated actor and action. A failed transaction does not persist its counter increment.

| Interface | Contract |
| --- | --- |
| Account access | Supabase Auth `signUp` and `verifyOtp` with type `email`, `signInWithPassword`, and recovery with `resetPasswordForEmail` and `verifyOtp` with type `recovery` |
| Contacts | `st_request`, `st_respond`, `st_set_block` |
| Messages | `st_send` with client UUID and text, participant-only reads and Realtime events |
| Calls | `st_place_call`, `st_call_status`, `st_signal`; authenticated `GET /api/ice` |
| Safety | `st_report`, reporter-only status; MFA-gated `st_queue`, `st_case`, `st_moderate` |
| Operations | `GET /api/health` for environment configuration |

Keep database exceptions meaningful for clients and give clients stable error codes before publishing a versioned integration API. Add tenant and role boundaries before introducing workspace data. Define retention jobs for signaling, user data, messages, reports and audit records with retention holds and export processes. The current schema does not automatically purge or anonymize stored content.

## Admin and SOC

The safety console prioritizes open cases. Staff can view user-submitted evidence, change case status, apply or lift a 24-hour contact restriction and inspect the decision trail. A support operator provisions staff access. Team-specific queues, role separation, appeals, assignment, trend dashboards, evidence retention, devices, session risk, organization policy, feature flags, aggregate reporting and an incident runbook are future releases. Staff analytics should aggregate abuse trends without exposing unrelated conversations or making unsupported assertions about a person's identity or intent.

## Billing and analytics

Billing is planned across Free, Basic, Professional, Business and Enterprise. Validate tiers and quotas before adding checkout. Use signed and idempotent payment webhooks, entitlement reconciliation, prorations, seat management, invoices, retries, and gateway-provided tax and GST support. Plan trials, coupons, grace periods and invoice-based enterprise contracts. Report delivery latency, connection success, infrastructure saturation and moderation backlog with minimized metadata and explicit retention.

## DevOps, testing and roadmap

Vercel handles web routing and Next.js functions. Supabase manages Auth, Postgres and Realtime. TURN is a separate managed media relay. Introduce queues, cache, scoped search services, workers and load-balancing by measured bottleneck. Keep preview and production credentials scoped and separate. Run builds, typed checks, policy tests, multi-browser and multi-network call tests, accessibility checks, and load tests before release. Plan backup restoration tests, incident response and database/app rollback together.

1. **Initial build** — email verification, password recovery codes, direct Realtime messaging, one-to-one calls, consent, reporting, blocking and staff review.
2. **Pilot readiness** — custom SMTP, TURN, live two-account verification, monitoring, capacity limits, retention and abuse handling.
3. **Collaboration** — groups and tenant roles, files, search, tasks, notifications, E2EE and group calls.
4. **Enterprise** — billing, SSO, device trust, workspace governance, analytics, audited security controls and compliance review.

## Coding agent and generation rules

Use typed boundaries, real data and explicit authorization. Document operational dependencies and verification gaps. Keep policy enforcement in the backend and test participant, stranger and staff identities separately. Treat consent, data integrity, privacy and tenant boundaries as release criteria. Ship new surfaces only after their backend contracts and failure states work through normal user entry points.
