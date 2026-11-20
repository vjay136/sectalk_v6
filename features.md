# SecTalk feature registry

The 239 entries below define the target scope. The feature matrix records implementation and verification status. [Feature matrix](docs/FEATURE_MATRIX.md)

## Feature registry

- AUTH-01 Signup: email+password (argon2id), breached-password check (k-anonymity), email verification
- AUTH-02 Login with risk-based step-up and generic error messages (no user enumeration)
- AUTH-03 TOTP MFA enrollment/verification + one-time recovery codes (hashed)
- AUTH-04 Passkeys (WebAuthn): register, login, rename, remove, passwordless-only mode
- AUTH-05 SSO via OIDC and SAML (Enterprise): domain verification, JIT provisioning, enforce-SSO option
- AUTH-06 SCIM 2.0 user/group provisioning and deprovisioning (Enterprise)
- AUTH-07 Session management: list/revoke sessions, idle + absolute timeouts, refresh-token rotation with reuse detection
- AUTH-08 Device registry + trust levels (unknown, known, trusted, managed, blocked) + E2EE device key bundle
- AUTH-09 Zero-trust: per-request authorization, step-up auth for sensitive actions (billing, role change, export, key ops)
- AUTH-10 Session risk scoring (new device, impossible travel, ASN/Tor/VPN reputation, velocity, failed attempts)
- AUTH-11 Account recovery (recovery key, trusted-device approval, admin-assisted recovery with delay + notifications)
- AUTH-12 Password reset, email change, MFA reset with cooling-off period and alerts to all devices
- AUTH-13 Invitations/onboarding (email/link invites, expiry, single-use, domain restrictions, seat check)
- AUTH-14 Guest access (scoped to rooms/meetings, expiring, restricted capabilities)
- AUTH-15 Managed accounts for minors/students with guardian/teacher oversight
- AUTH-16 Login anomaly notifications and "this wasn't me" lockdown flow
- AUTH-17 Remote device revoke/lock/wipe-local-keys
- ORG-01 Tenant creation by type with onboarding wizard and default policy template
- ORG-02 Multi-org membership and org switcher (strict context separation)
- ORG-03 Member management: invite, suspend, restore, remove, role change, bulk CSV import
- ORG-04 Custom roles + permission editor (with ABAC conditions)
- ORG-05 Groups/teams/departments
- ORG-06 Org settings: branding, verified domains, default retention, data region
- ORG-07 Versioned policy engine UI with simulation (dry-run impact preview) and rollback
- ORG-08 Data residency region selection (Enterprise)
- ORG-09 Org data export and tenant offboarding/deletion (crypto-shredding of tenant key)
- ORG-10 Family dashboard (guardian controls, member devices, safe-sharing defaults)
- ORG-11 School controls (classes, teacher/student roles, external-contact restrictions, supervised rooms)
- ORG-12 Healthcare profile (PHI-safe defaults, break-glass access with justification + alert)
- ORG-13 Legal hold (scoped by user/room/date; overrides retention and deletion)
- ORG-14 Compliance profile templates (compliance-ready presets: healthcare, education, finance, GDPR-style)
- MSG-01 1:1 direct messages
- MSG-02 Group chats (size limits by plan/policy; add/remove members with key rotation)
- MSG-03 E2EE mode (per-conversation; per-device keys; sender keys for groups; rotate on membership change)
- MSG-04 Managed-encryption mode (server envelope encryption; searchable; compliance-exportable); mode set by policy at conversation creation, immutable afterwards, clearly labeled in UI
- MSG-05 Delivery states: queued, sent, delivered, read, failed (+retry action)
- MSG-06 Read receipts (policy-controlled per org/room/user)
- MSG-07 Typing indicators (rate-limited, policy-controlled)
- MSG-08 Edit with time window, edit history (policy), "edited" marker
- MSG-09 Delete: for me / for everyone / admin redaction; tombstones; audit-safe retention
- MSG-10 Reply quoting with redaction support
- MSG-11 Forwarding (policy-controlled; forwarded label; blocked in restricted rooms)
- MSG-12 Pinning (permission-controlled)
- MSG-13 Draft sync across devices (encrypted)
- MSG-14 Offline queue + resend with idempotency keys
- MSG-15 Ordering, dedupe, gap detection and gap fill (per-conversation sequence numbers)
- MSG-16 Disappearing messages (timers; enforced client+server; policy min/max)
- MSG-17 Rich text (sanitized markdown subset), safe link previews (server fetch with SSRF guard in managed mode; client-generated in E2EE mode, toggleable)
- MSG-18 Multi-device sync and new-device history policy (E2EE: history transfer only by approved device)
- MSG-19 Report/flag message (to moderators/SOC; includes user-consented plaintext disclosure for E2EE)
- MSG-20 Saved/starred messages
- MSG-21 Scheduled send
- MSG-22 Voice notes (record, encrypt, waveform, transcript opt-in)
- THR-01 Threads: create from message, replies, counts, follow/unfollow
- THR-02 AI thread summaries (opt-in, policy-gated, safe)
- THR-03 Reactions (emoji set policy, per-message limits)
- THR-04 Mentions: @user, @group, @channel, @here with permission checks and notification priority
- THR-05 Thread integrity after delete/redaction/edit (no drift, tombstone parents)
- ROOM-01 Room types: public-in-tenant, private, admin-only (metadata hidden), announcement-only, broadcast
- ROOM-02 Roles: owner, moderator, member, guest, read-only
- ROOM-03 Join/invite/request-to-join/approval; membership authoritative server-side
- ROOM-04 Per-room permission overrides (post, react, upload, mention-all, start-call)
- ROOM-05 Announcements and pinned content
- ROOM-06 Moderation: mute, timeout, remove, ban, slow-mode, lock room
- ROOM-07 Room tabs: Messages, Threads, Pins, Files, Tasks, Members, Calls, Settings, Audit (audit visible only with permission)
- ROOM-08 Room-level audit trail
- ROOM-09 Archive/restore/delete (retention- and legal-hold-aware)
- ROOM-10 In-tenant room directory respecting visibility rules
- ROOM-11 Room templates (class, incident, family, project)
- PRES-01 Online/away/busy/offline with rate-limited heartbeats
- PRES-02 Custom status + schedule/DND integration
- PRES-03 Presence privacy controls (user + org policy; invisible mode where policy allows)
- NOTIF-01 In-app notification center (read/unread, grouping)
- NOTIF-02 Web push (VAPID), privacy-preserving payloads (no plaintext for E2EE)
- NOTIF-03 Email notifications and digests
- NOTIF-04 Per-category preferences (DM, mention, thread, task, call, security, billing, admin)
- NOTIF-05 Mute, snooze, DND schedule per conversation/global
- NOTIF-06 Priority rules; critical security alerts bypass non-critical filters where policy permits
- NOTIF-07 Admin notification policies (mandatory categories, quiet-hour limits)
- NOTIF-08 Missed-call and mention digests
- NOTIF-09 Queue-based delivery with retry, dedupe, DLQ, per-channel fallback
- NOTIF-10 Notification audit/delivery status for admin-sent notices
- FILE-01 Resumable chunked upload (interruption-safe, checksum-verified, partial cleanup)
- FILE-02 Client-side encryption for E2EE conversations (key wrapped in message)
- FILE-03 File type allow/deny policy (MIME sniffing + extension + magic bytes)
- FILE-04 Size/storage limits by plan + policy
- FILE-05 Malware scanning (ClamAV-class + hash reputation) with quarantine and release workflow
- FILE-06 Safe preview (images re-encoded, PDFs rendered in sandbox/server-side raster, text sanitized); never execute active content
- FILE-07 Download via short-lived signed URL with per-request authorization and access log
- FILE-08 Expiring share links (password, max downloads, revoke, audit)
- FILE-09 Delete + retention + soft delete + purge job
- FILE-10 Access logs (view/download/share) visible to owner/admin per policy
- FILE-11 Duplicate detection by content hash (tenant-scoped only; never cross-tenant dedupe)
- FILE-12 Files library tab with filters, sort, bulk actions
- FILE-13 Legal hold on files
- FILE-14 AI file inspection integration (macro/script/phishing-doc heuristics)
- FILE-15 Storage classes: attachments, recordings, avatars, exports (separate buckets/prefixes, lifecycle rules)
- TASK-01 Create task from message (immutable source snapshot + live reference)
- TASK-02 Standalone task creation in room/DM scope
- TASK-03 Assignment (multi-assignee), watchers
- TASK-04 Status workflow (todo, in-progress, blocked, done, cancelled) with validated transitions
- TASK-05 Due dates, reminders, overdue state
- TASK-06 Priority + labels
- TASK-07 List, board (kanban), calendar views
- TASK-08 Completion events + notifications
- TASK-09 Task audit trail
- TASK-10 Integrity when source message is deleted/redacted
- SRCH-01 Permission-safe keyword search (messages, files, tasks, rooms, people) in managed mode via Postgres FTS (tsvector + trigram), ACL filtered in-query
- SRCH-02 Filters: room, sender, date range, type, status, has-file, mentions-me
- SRCH-03 Queue-driven indexing pipeline (idempotent; reindex; backfill)
- SRCH-04 E2EE: local encrypted client-side index (never uploaded in plaintext); server returns metadata-only results
- SRCH-05 Permission-safe snippets with highlight; redacted content never appears
- SRCH-06 Deletion/redaction/legal-hold propagation to the index
- SRCH-07 Global command palette (Cmd/Ctrl+K): navigate, search, actions
- SRCH-08 Saved searches
- SRCH-09 Separate audit-log search for authorized admins only
- CALL-01 1:1 voice calls
- CALL-02 1:1 video calls
- CALL-03 Group calls (mesh ≤4, SFU above; automatic topology switch)
- CALL-04 Scheduled meetings with ICS/calendar invite, recurrence, join links
- CALL-05 Instant meetings
- CALL-06 Lobby/waiting room (policy-enforced; admit/deny/admit-all)
- CALL-07 Host controls: mute/mute-all, remove, lock meeting, promote co-host, end for all, disable chat/screen-share
- CALL-08 Screen sharing (window/tab/screen, audio where supported, permission-loss handling, one presenter policy)
- CALL-09 Pre-join: device selection, mic/cam test, network test, background blur toggle
- CALL-10 In-call controls: mute, camera, in-call chat, participants panel, pin/spotlight
- CALL-11 Raise hand + reactions
- CALL-12 Network quality indicators + adaptive bitrate + graceful audio-only fallback
- CALL-13 Reconnect: ICE restart, TURN fallback, signaling resume, session recovery
- CALL-14 Recording (policy-gated, explicit consent banner to all, server-side egress to storage, access-controlled, failure-safe)
- CALL-15 Live captions and post-call transcription (consent, language options, speaker labels)
- CALL-16 AI meeting summary + action items (opt-in, policy-gated, safe, editable)
- CALL-17 Call history, missed calls, call-back
- CALL-18 Incoming call UX (ringing, accept/decline/busy, multi-device ring with first-accept-wins and cancelled-elsewhere)
- CALL-19 E2EE calls (SFrame/insertable streams) with verification code display
- CALL-20 QoS telemetry collection (privacy-preserving) feeding analytics
- CALL-21 Guest join via link (policy, lobby, captcha, expiring)
- CALL-22 Ephemeral TURN/STUN credential issuance (short TTL, per-session)
- CALL-23 Network diagnostics page (STUN/TURN reachability, UDP/TCP/TLS 443 relay test, bandwidth estimate)
- AI-01 Message risk scoring (0–100 + confidence + reasons)
- AI-02 Scam/phishing classification (taxonomy in Section 11)
- AI-03 URL inspection (normalization, redirect-chain resolution in sandboxed fetcher, homoglyph/punycode, reputation, newly-registered-domain, brand impersonation)
- AI-04 File inspection (type mismatch, macros, scripts, archives, embedded links, hash reputation)
- AI-05 Threat taxonomy + severity model
- AI-06 Threshold-driven policy actions (info hint, warn banner, defang links, blur/hold, quarantine, escalate)
- AI-07 Explainable, non-overclaiming user warning UI ("might be…", reasons, dismiss/report, never states certainty)
- AI-08 Sender behavior reputation (burst messaging, mass-invite, new-account-linking, prior flags) with time decay
- AI-09 Abuse review queue with human-in-the-loop decisions
- AI-10 False-positive reporting + feedback loop to rules/thresholds (never auto-trains on E2EE content)
- AI-11 Safe AI summaries with guardrails (prompt-injection isolation, schema-validated output, redaction of secrets/PII before model)
- AI-12 Model registry: versions, shadow mode, offline evaluation harness, rollback, drift metrics
- AI-13 E2EE-compatible: on-device heuristics + user-initiated report; no server plaintext access without explicit user consent
- AI-14 Tenant AI settings (enable/disable, thresholds within safe bounds, data-sharing consent, retention of AI artifacts)
- AI-15 Impersonation detection (display-name spoofing, executive/VIP impersonation lists, lookalike accounts)
- SEC-01 RBAC with permission catalog (Section 7.3)
- SEC-02 ABAC policy engine (attributes: device trust, risk score, network, time, data classification, tenant type) with explain() output
- SEC-03 Tenant isolation: RLS + query helpers + isolation test harness
- SEC-04 Key management: per-tenant KEKs, envelope DEKs, rotation, BYOK (Enterprise), crypto-shredding
- SEC-05 E2EE key bundles, device verification (safety numbers/QR), key-change warnings
- SEC-06 Tamper-evident audit log (hash chain + periodic anchoring + verifier job)
- SEC-07 Rate limiting (sliding window/token bucket; tenant+user+IP+device; risk-adaptive)
- SEC-08 Abuse prevention (spam heuristics, invite abuse, proof-of-work/captcha on risk, account velocity)
- SEC-09 Security headers, strict CSP with nonces, CSRF, CORS allowlist, cookie hardening (__Host-, HttpOnly, SameSite)
- SEC-10 Secure sharing controls (watermarks optional, no-forward, expiring, view-only)
- SEC-11 Secrets hygiene: log redaction, secret scanning, no secrets client-side
- SEC-12 Input validation, output encoding, SSRF protection, upload hardening, webhook signature verification
- SEC-13 Break-glass / JIT privileged access with approval, time-box, justification, customer notification
- SEC-14 security.txt, vulnerability disclosure policy, SECURITY.md
- SEC-15 Data classification labels (public/internal/confidential/restricted) enforced by policy
- SEC-16 DLP rules (PII/PHI/card/credential patterns) with warn/block/redact actions
- BILL-01 Plan catalog (Free, Pro, Team, Enterprise) as versioned data, multi-currency, grandfathering
- BILL-02 Checkout via Stripe and Razorpay (hosted/secure elements; no card data touches our servers)
- BILL-03 Trials (Pro 14d, Team 14d; one per tenant; card-optional config)
- BILL-04 Coupons/promo codes (percent/fixed, duration, redemption limits, plan scope, stacking rules)
- BILL-05 Tax: GST (India: GSTIN capture, CGST/SGST/IGST logic), VAT/sales-tax via tax adapter, tax-inclusive/exclusive display
- BILL-06 Invoices and receipts (PDF, sequential numbering, tax breakdown, download)
- BILL-07 Renewals + dunning (retry schedule, emails, grace period)
- BILL-08 Upgrade/downgrade with proration; scheduled downgrade at period end; atomic + audited
- BILL-09 Seat-based billing (add/remove seats, true-up, seat caps, auto-seat on invite with admin approval)
- BILL-10 Usage metering (recording minutes, transcription minutes, storage GB, AI scans overage) with idempotent usage events
- BILL-11 Entitlements engine (feature gates, limits) consumed by policy/UI/API; cached with version keys
- BILL-12 Idempotent, signature-verified payment webhooks with replay protection and reconciliation job
- BILL-13 Billing portal: payment methods, plan, invoices, tax IDs, cancel/reactivate
- BILL-14 Enterprise contracts: custom pricing, PO/manual invoicing, annual commits, order forms
- BILL-15 Grace period and degraded read-only mode on non-payment (no data loss; export always allowed)
- BILL-16 Refunds/credits/adjustments (billing_admin + step-up auth + audit)
- ADM-01 Overview dashboard (health, seats, alerts, adoption)
- ADM-02 Users: list/search/filter, profile, roles, suspend, force logout, reset MFA
- ADM-03 Devices: inventory, trust level, revoke, wipe keys, managed-device flag
- ADM-04 Sessions: active sessions, risk, revoke
- ADM-05 Rooms/Channels management: visibility, owners, archive, membership audit
- ADM-06 Policies: messaging, files, calls, AI, retention, sharing, DLP, external access (versioned, simulated)
- ADM-07 Audit log viewer: filters, tamper-verify status, export (signed)
- ADM-08 Retention and legal hold management
- ADM-09 Compliance exports / eDiscovery (scoped, approval-gated, logged, hashed bundles)
- ADM-10 Integrations: API keys, outbound webhooks (signed, retry, delivery log), SSO/SCIM setup
- ADM-11 Branding, verified domains, email templates
- ADM-12 Billing tab (plan, seats, invoices, payment) — billing_admin only
- ADM-13 Tenant feature flags (within entitlements)
- ADM-14 Org analytics (usage, adoption, call quality, security posture)
- SOC-01 Security Center overview (open incidents, risk trend, queue depth, MTTA/MTTR)
- SOC-02 Threat queue (AI-flagged items, filters by severity/confidence/type, bulk triage)
- SOC-03 Abuse queue (user reports, spam, harassment) with SLA timers
- SOC-04 Threat map (geo/ASN of suspicious logins and threat events; privacy-safe aggregation)
- SOC-05 Session risk console (high-risk sessions, impossible travel, step-up/terminate actions)
- SOC-06 Incident management (create, severity, status, assignees, timeline, linked entities, postmortem)
- SOC-07 Evidence vault (immutable snapshots, SHA-256, chain of custody, access log, legal-hold link)
- SOC-08 Escalation workflows (L1→L2→org admin→platform), SLA/ack timers, on-call routing
- SOC-09 SOC actions: quarantine message/file, suspend user, force logout, revoke device, block URL/domain, lock room — each with reason, approval rules for destructive actions, and audit
- SOC-10 Detection rule management (create/test/enable/shadow rules, versioned)
- SOC-11 SOC reporting (daily/weekly, exportable PDF/CSV)
- SOC-12 Case notes and collaboration (mentions, attachments to evidence)
- SOC-13 SIEM export (webhook, syslog/CEF, S3 batch) with signed payloads
- SOC-14 Playbooks (declarative, human-approved automations)
- PLT-01 Tenant operations (view metadata only; no content access without break-glass)
- PLT-02 Global feature flags and staged rollouts
- PLT-03 System health, queue depth, DLQ browser/replay, SLO dashboard
- PLT-04 Global abuse blocklists (domains, hashes, IP ranges)
- PLT-05 Break-glass approvals and review
- ANL-01 Operational metrics (latency, errors, saturation)
- ANL-02 Call quality analytics (join success, time-to-connect, TURN-relay %, ICE-restart rate, MOS proxy)
- ANL-03 Threat trend analytics
- ANL-04 Message delivery latency (p50/p95/p99)
- ANL-05 Product usage metrics (privacy-preserving, aggregate; never message content)
- ANL-06 Real-time dashboards (streaming aggregates)
- ANL-07 Scheduled reports (email/export)
- PLAT-01 Feature flag system (global/tenant/user, percentage rollout, kill switches)
- PLAT-02 Observability (OTel traces, metrics, structured logs with redaction, error tracking)
- PLAT-03 Queue framework (idempotent consumers, ordering keys, retries, DLQ, replay tooling)
- PLAT-04 Cache layer policy (keys namespaced by tenant+version; TTLs; no decrypted content)
- PLAT-05 Public REST API + API keys + signed outbound webhooks (Enterprise/Team)
- PLAT-06 i18n framework (en + one RTL locale scaffold working; ICU messages)
- PLAT-07 Accessibility (WCAG 2.2 AA, keyboard-complete, screen-reader tested)
- PLAT-08 PWA + responsive layouts + offline shell
- PLAT-09 Health/readiness/status endpoints + public status page
- PLAT-10 Backup/restore/DR scripts with restore-verification job
- PLAT-11 User settings: Profile, Security, Devices, Sessions, Notifications, Privacy, Appearance (light/dark/high-contrast/reduced-motion), Billing, Data export & account deletion
- PLAT-12 Onboarding, empty states, in-product help, keyboard shortcuts sheet
- PLAT-13 Marketing site: landing, pricing, security/trust page, legal (Terms, Privacy, DPA template), docs, status

## Foundation design notes


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
