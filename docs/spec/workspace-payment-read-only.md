# Post-grace workspace read-only mode

SecTalk uses the owning payer’s linked subscription and the configured renewal grace deadline. An expired past-due or unpaid subscription makes that payer’s workspaces read-only. A canceled subscription is treated as non-payment only when Stripe explicitly reports payment failure. Voluntary cancellation and ordinary free workspaces keep their applicable free-plan behavior. Current provider recovery restores workspace writes automatically.

The database checks tenant scope on room and channel posts, task changes, new rooms and channels, file reservations and publication, invitations and membership expansion, team writes, new scheduled meetings and recordings, and meeting messages. The active workspace shows a read-only notice. File upload routes return HTTP 423 while read-only. Native write checks apply even if a client skips the notice.

Existing data, reads, downloads, and authorized audit/compliance exports remain available. Previously entitled enterprise workspaces can still download signed SIEM digests. Already queued SIEM jobs can settle, and new connector sends remain disabled while read-only. Security actions such as suspending access or applying message quarantine still work, as do account privacy and support flows, personal conversations and tasks, billing access, and the scheduled jobs that settle previously authorized work. Existing schedule and media safety controls remain usable. The billing state does not delete or shorten retention of workspace content.

Local verification uses signed Stripe fixture responses. Confirm the hosted provider subscription status and cancellation-reason mappings during deployment.
