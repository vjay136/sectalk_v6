# Workspace usage

Workspace owners can open **Billing → Workspace usage**. The page and authenticated PostgREST function show UTC calendar-month totals and the active workspace plan version. They expose aggregate units only. An ordinary workspace member cannot see billing totals. Producer events retain the plan and version in effect when they are committed.

- Recording minutes come from the verified LiveKit file result for completed, retained recordings. The ledger stores milliseconds and deduplicates by recording ID.
- Transcription minutes come from validated 16 kHz mono PCM accepted by the authorized meeting-caption worker. The ledger stores audio samples and deduplicates by the consumed caption lease. Personal voice notes have no workspace billing scope.
- Stored bytes come from Storage metadata for workspace files, room files, and meeting recordings. Database Cron takes one sample per UTC hour and stores byte-hours. Unsampled intervals contribute no byte-hours. The displayed plan storage allowance is the tenant entitlement. Existing file upload and reservation limits also apply to each file workflow.
- File inspection counts come from successfully returned AI-04 attachment scanner verdicts for authorized workspace and room uploads. The inspection worker uses deterministic local checks. The ledger allows one count per scope, file ID and content digest. Unavailable verdicts, local message warnings and personal attachments do not contribute.

To enable overage reporting, install the approved monthly file inspection allowance for each offered plan and version in the private `sectalk_private.st_v7_scan_allowances` table via deployment policy. SecTalk shows **Allowance pending** until a plan version has a configured value. The reported overage is the current UTC month's scans above the current workspace version's allowance. This change records usage and does not send invoice or metered billing events to Stripe.
