# Enterprise data residency

Organization settings keeps the shared deployment's region preference separate from dedicated placement. Selecting a preference changes the saved preference. An Enterprise workspace owner can also request a specifically authorized dedicated target, with fresh native step-up to create or withdraw the request.

The private cell registry binds a target to a project reference. The workspace allowlist controls selection. The tenant receives the target label and region, alongside the request state. Project references, installation markers, verifier assignments, and audit rows are private.

The local acceptance flow uses a single disposable Supabase project tagged as a synthetic cell. The service writes and reads back a request-bound canary in the project's private export bucket and invokes the observation procedure with the installation marker. Observation requires the same registered project, authorized workspace and cell, plus canary metadata created after the request. An independently provisioned workspace reviewer with fresh TOTP can then confirm the observation. The interface labels the result **Synthetic target verified**. Rotating the installation marker, expiring the observation, or revoking the target invalidates that status.

## Read-only provider verification

For a deployment target, provision an immutable provider organization slug and exact region in the private provider binding for that cell. Provision the matching cell ID, project reference, and independent installation nonce on the dedicated target project. A workspace-scoped reviewer other than the requesting owner uses fresh native TOTP to call `POST /api/workspaces/residency/verify` with the request UUID.

The server uses `SECTALK_RESIDENCY_PROVIDER_READ_TOKEN` for the read-only Supabase project lookup. Use the minimum project-scoped permission. The returned ref, organization slug, exact region and healthy status must match. Separately, set `SECTALK_RESIDENCY_CONTROL_PROJECT_REF` and a server-only `SECTALK_RESIDENCY_TARGETS` object keyed by authorized project ref, with a `publishableKey` and `installationNonce`. The verifier calls the exact dedicated project's read-only installation RPC with the publishable key. The Management API token is used only on the Management API host. The source and target projects must differ. [Supabase project lookup](https://supabase.com/docs/reference/api/v1-get-project)

The target stays pending if configuration or either observation is unavailable. The verified target configuration lasts for 24 hours and invalidates if the requesting owner, reviewer grant, or target eligibility changes. Verification tests use scoped local fixtures and do not establish hosted geography.

## Workspace transfer preflight

The current runtime uses one Supabase Auth, PostgREST, Storage, and Realtime project per deployment. Keep the workspace on its existing deployment while reviewing the proposed transfer. A project-wide recovery archive covers the full shared database and Auth identities, so use it for whole-project recovery under that approval. [Supabase project migration](https://supabase.com/docs/guides/platform/migrating-within-supabase)

From a trusted operations host, connect a PostgreSQL client with the source project's approved read access and supply the exact workspace UUID. Use an encrypted connection and a protected libpq service and password file. Keep the report with the private migration record.

```sh
psql --no-psqlrc --no-align --tuples-only --dbname=service=sectalk_residency_source \
  --set=workspace_id=00000000-0000-0000-0000-000000000000 \
  --file=scripts/workspace-residency-preflight.sql
```

The read-only snapshot returns schema relation names and counts. It walks inbound workspace foreign keys, identifies workspace-like scope columns outside that graph, and shows foreign keys connecting the graph to other relations. It counts shared workspace identities and global direct and group chats that involve members. For workspace-file metadata it counts published, pending and retained entries, missing and mismatched objects, and unmatched keys for the exact workspace prefix. The Storage check compares database metadata. Verify live object bytes and digests using the applicable scoped transfer after the source is quiesced.

The result remains `scope_review_required` with `eligibleForAutomatedCutover: false` while a transfer needs its explicit data and routing plan. Before moving traffic, capture and review:

1. The approved source, exact destination project and region, matching schema and policies, verified installation binding, and region evidence for hosted backups, replicas, Storage, edge jobs and logs that carry workspace data.
2. A row-level ownership and dependency map for the target workspace. Review relationships reached through foreign keys, logical identifiers, and references within JSON or jobs. Account for shared Auth and recovery credentials, global conversations and device keys, billing, retained Safety records, and private object ownership. Route the shared identity dependencies through an approved design that preserves access to unrelated workspaces.
3. A write-freeze and rollback plan with scoped permissions for the transfer process. Compare bounded metadata and private byte digests on the destination. Verify authorized reads and writes, unrelated-account denial, independent approval and rollback on a separate candidate origin. Quiesce the approved data scope before the final comparison and the tenant-only routing change.

The native rollback test exercises source data from two disposable workspaces, deliberately overlapping identities, private Storage metadata discrepancies, and report redaction. Run `node tests/workspace-residency-preflight.e2e.mjs` with the repository's disposable v4 QA database running.

## Pause guarded source writes for the migration check

After an independently verified placement, the current owner opens **Organization settings → Enterprise data residency → Source workspace writes**, confirms the exact workspace ID and completes fresh authenticator verification. The selected workspace's guarded write paths enter a 30-minute pause. Reads, authorized exports, and safety actions stay available. The normal billing and offboarding restrictions still apply. The owner can choose **Resume workspace writes**. Withdrawing the verified residency request or reaching the expiry also clears the migration pause.

The native pause and write guards share a workspace-scoped transaction lock so admitted writes finish before the pause begins. The pause covers the existing guarded write paths, including new workspace messages, tasks and file publication. Review remaining retention, preservation, provider and background activity when performing the final comparison. Traffic routing and the hosted cutover remain separate release checks.

## Rehearse reaching the destination

Configure `SECTALK_RESIDENCY_ROUTING_ORIGINS` on the source as a server-side JSON object that maps the verified Supabase project reference to the exact destination app origin. Configure `SECTALK_APP_URL` as the source origin. Hosted mappings use HTTPS. Synthetic mappings use separate loopback ports.

While source writes are paused, the owner requests a **Workspace routing rehearsal** from Workspaces. An independently assigned residency reviewer with workspace access uses the same panel to approve that request. Each action requires fresh authenticator verification and exact workspace ID confirmation. The rehearsal lasts up to ten minutes and ends sooner if the source pause expires, the target verification is withdrawn, or the reviewer loses authority.

Active source members can choose **Open the destination workspace**. The source checks the route again and opens `/?workspace=WORKSPACE_ID` on the approved origin. Members sign in on the destination with its own account. The destination loads the workspace only after confirming active membership. Ending the rehearsal immediately removes the link and leaves the source pause under the owner's separate control. The rehearsal verifies the handoff and return path. Production write authority and routing cutover remain release checks.

## Hold guarded writes during a migration handoff

After imports and comparison, the destination owner opens **Workspaces → Migration write handoff**, confirms the workspace ID with fresh authenticator verification, and chooses **Put destination on standby**. The common workspace write guard blocks ordinary operations it covers, including posts, tasks and file publication. The standby proof binds the current approval, both paired project references, the exact workspace, and one handoff ID. It expires within five minutes.

The source owner uses the existing temporary pause against the independently reviewed destination. In **Migration write handoff**, they paste the standby proof and choose **Hold guarded source writes**. The durable hold survives expiry of the temporary pause. The destination remains in standby while the source hold is active.

For rollback, the destination owner chooses **Cancel destination handoff**, then provides the exact cancellation proof to the source owner. The source restores guarded write authority only after verifying that proof and the existing handoff ID. The cancelled destination stays guarded, and separate source restrictions continue to apply. Renew the exact paired migration credential through trusted operations if either proof expires. Production activation, full write coverage and live routing are tracked in the release gate.

## Activate guarded destination writes

Trusted installation operators record the exact independently reviewed migration plan and recovery evidence in `st_v8_residency_activation_admissions` on each installation. Match the workspace, approval, handoff ID, environment, manifest digest, plan digest, and recovery digest. The admission is scoped to the relevant project side and expires. Use the fixture environment only on disposable installations. Review the full dependency inventory, access boundaries, recoverable copy and routing plan before preparing a hosted admission.

While the source is durably held, the source reviewer accepts a fresh comparison from the standby destination with every approved record matched. In **Guarded destination activation**, the source owner generates a proof. SecTalk rechecks the source approval, record coverage, approved destination, reviewed comparison, and exact handoff. The destination owner supplies that short-lived proof, confirms the workspace ID, and completes native authenticator verification. The destination checks both admissions and recomputes its current comparison before opening guarded writes.

The source remains held after an activation. The destination's standby cancellation command cannot reopen source writes after activation. Any post-activation rollback requires an independent reconciliation of writes made at the destination. The production release still requires verified account and data coverage, hosted placement, live routing and provider recovery rehearsal.

## Publish the active member route

After native activation, the destination owner opens **Workspaces → Active workspace routing** and chooses **Create destination activation proof**. The proof binds the approved project pair, workspace, manifest, handoff, migration plan, recovery evidence and exact activation time. Use the proof within five minutes. On the source, the owner uses **Publish active workspace route** with that proof, the exact workspace ID and current authenticator verification. SecTalk rechecks the admitted source hold and independently verified destination before recording one publication event.

Authorized source members can then choose **Open the active workspace**. The source returns the explicitly mapped destination origin and workspace ID. Members authenticate separately at the destination. Publication survives the temporary pause and transfer-proof expiry. A retired destination or withdrawn placement authorization makes the link unavailable. Source writes remain held.

## Prepare for rollback after activation

In **Workspaces → Migration write handoff → Residency rollback preparation**, the destination owner can hold guarded destination writes. This records the exact handoff and drains previously admitted guarded transactions before applying the hold. Existing destination records remain readable by authorized members. A new activation proof is unavailable while the destination is held.

The source owner uses the same panel on the source to suspend its member link. Future routing requests fail closed and the link cannot be republished for that handoff. Each action requires the exact workspace ID, fresh authenticator verification and the local owner session. The two installations record their own audit events. Owners can apply these protective controls after transfer credentials expire.

These controls prepare both installations for reconciliation. Guarded source writes remain held while operators inventory destination changes and verify an independent recovery plan.

## Review destination changes against activation

SecTalk captures a private baseline in the same transaction that activates guarded destination writes. After the destination owner applies the rollback hold, **Workspaces → Destination rollback change review** can capture the exact changes. The comparison covers workspace channels, rooms, messages, tasks, file registrations and the workspace's private Storage object versions. The review displays record identifiers and before-and-after digests. It covers persisted changes and Storage metadata. File bytes and changes outside these record families require separate recovery evidence.

An assigned independent reviewer opens the same panel on the destination, checks the record revisions and confirms the digest with the exact workspace ID and a current authenticator session. Drift or a lost reviewer assignment requires a fresh review. Activations that predate the baseline and record families beyond the 500-record comparison limit require a separate inventory. Confirmation records the review and keeps both write holds in place.

The current transfer format requires unique IDs within each record type across the workspace. If two rooms contain a record of the same type with the same ID in the activation baseline or current census, the review requires a separate inventory and the write hold stays in place. A manifest with repeated type-and-ID pairs cannot be admitted or signed off at the source.

## Transfer the reviewed rollback manifest

Trusted installation operators provision a separate short-lived manifest admission in each Supabase project. Both admissions bind the exact handoff and the same approved recovery-plan digest, and each refers to its installation's Vault copy of a fresh random 32-byte transfer key. Retire these admissions and keys when the transfer is complete.

After independent destination review, the destination owner opens **Workspaces → Migration write handoff → Rollback recovery manifest** and downloads the signed JSON. It contains the exact workspace, projects, handoff, approved plan, review and record revisions. It excludes record bodies and file bytes. The source owner suspends member routing first, then attaches the file in the same panel within five minutes.

The source verifies the admission, signed contents and expiry before recording one receipt. A retry with the same verified packet returns the original receipt. The source stays read-only while operators collect and verify replay data and recovery files.

## Replay reviewed Board task completion changes

From **Workspaces → Board task rollback replay**, the destination owner can download a signed file for the exact reviewed task revisions that changed only in completion state. The source owner stages the file against the already verified rollback manifest. The original independent source reviewer can inspect the staged task IDs and desired states and apply the batch with fresh authenticator verification.

The source verifies each existing task against its original approved export while holding the workspace and preservation locks. A stale task or preservation hold prevents the batch from applying. Replay changes only the approved completion fields on existing tasks, records one audit event, and leaves both write holds in place. Other changed records and file bytes remain pending separate recovery.

The same flow supports reviewed tasks created after activation. For an owner-authored task, the source checks a keyed match between both owners' confirmed emails. An ordinary member uses **Workspaces → My Board task recovery** to approve on each installation with fresh verification. SecTalk checks the destination member's approval when signing the packet and checks the matching source approval at staging and again at replay. Withdrawal on the source before replay blocks the whole batch.

The signed file excludes email addresses. The reviewer can see the proposed title, details, due date and completion state. Replay verifies the exact destination revision, preserves the task ID and creation time, assigns the matched source author and rejects a conflicting ID.

## Replay reviewed standard channels and messages

In **Workspaces → Standard channel rollback replay**, the destination owner can download a signed file for reviewed, newly created workspace-wide standard channels and eligible messages sent after activation. A previously migrated standard channel can also receive eligible recovered messages when its exact import record and approved source history match. The issue step excludes reported and quarantined messages. An ordinary member uses **Workspaces → My chat message recovery** to approve on both installations. A Board task approval grants access only to Board recovery. The independent manifest retains outstanding record revisions.

The source owner stages the file against the verified manifest. SecTalk checks keyed identity matches and the exact destination revision of each channel and message. The independent source reviewer can inspect and apply the batch. A withdrawn source approval, existing ID, retained history, name conflict, preservation hold or managed-encryption policy can block it. Native channel and message checks still run during replay. Successful replay preserves the IDs and timestamps and assigns the matched source owner or member. Both installations remain write-held.

The destination claim preserves the built-in `general` channel's source ID when the approved archive contains supported messages for it. A destination ID collision aborts the entire claim. The resulting import receipt binds historical author restoration and eligible rollback messages to the same channel. A claim without approved `general` evidence receives a new default channel ID.

## Verify the held source

In **Workspaces → Source rollback verification**, the original source owner and independent reviewer can compare the signed destination manifest with applied recovery batches and the source database. The list shows record IDs and verification outcomes. It identifies reviewed records with no applied replay and source records that have changed since replay, including messages quarantined by a safety action. Reviewers can refresh after each batch. Source writes remain held pending a complete recovery and reactivation procedure.

When every change in the signed manifest matches, the source owner can use **Record source evidence** and the independent reviewer can use **Sign off on source evidence**. Both confirm the workspace ID and use a fresh authenticator verification. The digest binds the source results to the exact destination review, signed packet and recovery plan. A preservation hold blocks sign-off, and later source drift changes the current coverage status. The audit keeps the original receipt. This review applies to the manifest's covered records. Workspace routing and write authority remain held.

Recording evidence, signing off, and rechecking it during reactivation lock the restored room records and their verified parent messages before comparing them. If moderation is already changing a covered message, the review waits for that transaction. An independent moderation action can still change the record after sign-off, which requires fresh matching evidence before reactivation.

In **Rollback recovery manifest → Destination retirement**, the destination owner can retire guarded destination writes and download a signed receipt after the independent change review. The receipt identifies the exact handoff, reviewed snapshot and recovery plan. The destination keeps its write hold after the proof expires. A new proof requires the same current review and a valid recovery admission. A changed review blocks proof renewal while the durable retirement remains in effect.

After source sign-off, the source owner can choose **Refresh source reactivation status**, supply the signed retirement proof, and confirm the workspace ID. SecTalk checks native authenticator assurance, the exact signed handoff and the current source sign-off before releasing that handoff's source write hold. The old destination link stays unavailable. The retired destination stays read-only, and separate source restrictions such as offboarding or billing continue to apply.

## Recover reviewed workspace and room files

After independent destination review, the destination owner can open **View record revisions** to download an eligible workspace or room file uploaded after activation. SecTalk checks the current session, file egress policy, preservation holds, and the exact reviewed revisions of both the file registration and its private Storage object. It hashes the bytes and rechecks those revisions before signing the copy. The proof binds the handoff, review, verified owner identity and original room where applicable.

On the source, use **Stage reviewed file copy** before the five-minute proof expires. An independent reviewer approves the exact staging digest. The source owner can then restore the approved file. SecTalk scans the staged bytes and checks the live object after copying without overwrite. Room recovery publishes into the original paired room and requires its current access policy. The restored file registration and Storage revision appear as separate entries in source verification. Workspace writes on both installations stay held.

## Approved private-file transfer rehearsal

`scripts/workspace-residency-files.mjs` stages selected workspace files between separate loopback Supabase projects. The existing SecTalk file endpoint checks the source owner's fresh session, current egress permissions, separate reviewer consent and the exact approved bytes for each selected file. The rehearsal writes to the destination's private workspace bucket without overwriting, then reads the object back and verifies SHA-256. A retry reuses matching bytes and returns the same manifest digest. A conflict preserves the existing target object.

Set `SECTALK_RESIDENCY_SOURCE_APP`, `SECTALK_RESIDENCY_SOURCE_DATABASE`, `SECTALK_RESIDENCY_TARGET_DATABASE`, `SECTALK_RESIDENCY_SOURCE_SESSION`, and `SECTALK_RESIDENCY_TARGET_KEY` using protected local configuration. Supply the workspace UUID, approved export UUID, and one or more exact file UUIDs with `--workspace`, `--export` and repeated `--file` arguments. If a transfer stops partway through, identical target objects can be verified on retry. This stage copies private bytes. Row transfer, tenant routing and region cutover remain separate.

The optional two-project offboarding browser fixture sets the target database and private test key explicitly. It checks real source approval, exact bytes, duplicate retry, a conflicting target, public target denial and current scope denial.

## Approved record staging

`scripts/workspace-residency-content.mjs` reads each exact manifest page as the current, recently verified source workspace owner. The native page endpoint requires an independently approved export and verifies every pinned revision. The tool sends the complete ordered manifest to a separate, explicitly admitted target. The target checks its cell and installation nonce, recomputes every record hash and the entire PostgreSQL manifest hash, then writes atomically to private staging. Concurrent identical transfers produce one write and one verified reuse. Incomplete or altered batches confer no access to the archive.

Provision a destination `st_v8_residency_content_admissions` entry through trusted operations with the exact cell, source project, workspace, approval UUID, independently confirmed manifest digest, record count and expiry. Supply `--workspace`, `--approval` and `--cell` to the command. Set `SECTALK_RESIDENCY_SOURCE_DATABASE`, `SECTALK_RESIDENCY_SOURCE_PROJECT`, `SECTALK_RESIDENCY_SOURCE_PUBLIC_KEY`, `SECTALK_RESIDENCY_SOURCE_SESSION`, `SECTALK_RESIDENCY_TARGET_DATABASE`, `SECTALK_RESIDENCY_TARGET_KEY` and `SECTALK_RESIDENCY_INSTALLATION_NONCE` in protected local configuration. The tool prints only a count, digest and whether it staged or reused the archive. Restrict and retain the private staged archive under the approved rehearsal plan. Any retained target copy is subject to its own destination retention and access controls.

Hosted preparation also requires `SECTALK_RESIDENCY_TARGET_PROJECT`. Both HTTPS URLs must match the exact `PROJECT_REF.supabase.co` origins for the configured project references. The source receives its publishable key and the verified owner session. The destination receives only its own server credential. The hosted request contract is covered by a synthetic test. The hosted transfer rehearsal remains pending. [Supabase API keys](https://supabase.com/docs/guides/getting-started/api-keys)

`tests/workspace-residency-content.e2e.mjs` uses independent local projects at ports 56651 and 56801. It verifies real owner and reviewer TOTP, 26 records across two pages, unrelated workspace exclusion, wrong installation denial, duplicate concurrent calls, self-consistent tampering with the wrong overall digest, and source withdrawal.

## Import approved workspace tasks at the destination

After staging, a trusted destination operator records the exact installation nonce, source approval, current manifest digest, workspace UUID, display name, expiry and verified destination Auth account in the private `st_v8_residency_workspace_claims` table. The named owner sees **Approved destination workspace** in Workspaces. They verify a fresh authenticator code and type the approved UUID. The claim creates the workspace and normal owner membership under that ID and records one audit event. A collision preserves the existing workspace. Nonce rotation or expiry invalidates an unclaimed admission.

The owner opens **Workspaces → Organization settings → Enterprise data residency**, reviews the approved digest under the task or Board import, and confirms the exact destination ID with fresh native TOTP. The destination checks the claimed installation, the approved staged manifest, and each selected record hash. It keeps task and calendar event UUIDs, titles, details, scheduled times, and creation timestamps, as well as task completion state. The destination owner is recorded as the importer because the approved export excludes source user identities. The records appear on **Board**, and events also appear under **Calendar**. Calendar event changes after cutover remain outstanding in rollback review until separately recovered.

The entire approved workspace task subset commits with one provenance receipt. A conflicting UUID rolls back the entire batch and preserves the existing item. Repeating a completed import returns its original receipt. Account migration, other live-table imports, destination routing and hosted region evidence remain open. Set `SECTALK_RESIDENCY_TARGET_APP=http://127.0.0.1:3602` and the Playwright overrides to exercise the owner claim, Organization settings import and destination Board in Edge.

## Publish approved workspace files at the destination

Use `node scripts/workspace-residency-files.mjs --publish --workspace WORKSPACE_ID --export APPROVAL_ID --file FILE_ID`. Configure `SECTALK_RESIDENCY_SOURCE_APP`, `SECTALK_RESIDENCY_SOURCE_DATABASE`, `SECTALK_RESIDENCY_SOURCE_PUBLIC_KEY`, `SECTALK_RESIDENCY_SOURCE_SESSION`, `SECTALK_RESIDENCY_TARGET_APP` and `SECTALK_RESIDENCY_TARGET_SESSION` through protected configuration. Local rehearsal uses separate loopback ports. Both sessions require their own current owner and authenticator checks.

First stage a manifest containing the selected workspace files and claim the target workspace. The command reads the exact independently approved source bytes, then sends them through the destination’s normal file publication path. That path validates the staged approval and matching file ID, name, size and digest before reservation and before publication. The destination applies its own file policy, inspection and storage quota. The file keeps its UUID and name and uses the destination owner and publication time. The file is available on **Workspaces → Files**. The command reads back the published bytes and verifies the digest. Identical retries converge on the same file. A multi-file command can finish a prefix before a later file fails.

The two-project browser test exercises publication with an exact synthetic scanner fixture and reads the approved file through the destination UI. Hosted cutover and complete account and data migration remain open.

For a hosted rehearsal, use the exact HTTPS Supabase origins and both project references from record staging. Add `--cell CELL_ID`, the destination publishable key in `SECTALK_RESIDENCY_TARGET_PUBLIC_KEY`, the independently provisioned installation nonce, and `SECTALK_RESIDENCY_PUBLISH_ORIGINS`. Set the latter to a trusted JSON object keyed by the two project references, with each approved application origin as its value. The command checks the paired destination installation and its current file access before uploading any bytes and refuses redirects. The operator-provided origin mapping supplies the intended app identity. The hosted request flow is covered by synthetic tests.

## Seat an existing member on the destination

After the target is claimed, `node scripts/workspace-residency-member.mjs --workspace WORKSPACE_ID --approval APPROVAL_ID` can issue the normal destination invitation for a matched existing member. Configure `SECTALK_RESIDENCY_SOURCE_DATABASE`, `SECTALK_RESIDENCY_SOURCE_PROJECT`, `SECTALK_RESIDENCY_SOURCE_PUBLIC_KEY`, `SECTALK_RESIDENCY_SOURCE_MEMBER_SESSION`, `SECTALK_RESIDENCY_TARGET_DATABASE`, `SECTALK_RESIDENCY_TARGET_PUBLIC_KEY`, `SECTALK_RESIDENCY_TARGET_SESSION` for the destination owner, and `SECTALK_RESIDENCY_TARGET_MEMBER_SESSION` for the prospective member. Each session needs fresh native authenticator verification. For hosted workspace and room invitations and message restoration, supply `SECTALK_RESIDENCY_TARGET_PROJECT` as well and use each project's own publishable key. The commands reject mixed local and hosted origins.

The command verifies active ordinary source membership and compares challenge-bound digests of each account's confirmed email. It issues an invitation only for the matched destination account under the exact claimed workspace and approval. The destination repeats its identity check and uses the same invitation, block and entitlement rules as ordinary enrollment. The member decides whether to join in **Workspaces → Invitations**. Repeating the command before acceptance returns the existing pending invitation. Existing source access continues. This workflow provides membership transfer for ordinary members who already have both accounts. It does not transfer passwords, authenticators, owner or administrator roles, or complete tenant routing.

## Restore an approved message as its original author

After the standard channel import and the matched member's accepted invitation, trusted source and destination operators provision the same per-approval random 32-byte key in their private Supabase Vaults. In each project, the `st_v8_residency_history_links` record binds the workspace, approval, source and destination project references, local Vault ID, role of that installation and expiry. Use a dedicated key for each approval. [Supabase Vault](https://supabase.com/docs/guides/database/vault)

After the transfer ends and the link expires, a database operator can retire the local link with `sectalk_private.st_v8_retire_residency_history_link(workspace, approval, side, local_vault_id, operational_reference)`. Use the exact record in that installation and confirm that the Vault entry was dedicated to the link. Holds, active transfers or approvals, and a Vault entry referenced by comparison or rollback evidence block retirement. The operation removes the local registration and its Vault row in one transaction. An immutable receipt records the operator, reference and whether the Vault row was already absent without storing the Vault identifier or key. Retiring the corresponding link in the other installation requires a separate operation. Backup erasure requires independent evidence.

Run `node scripts/workspace-residency-member.mjs --workspace WORKSPACE_ID --approval APPROVAL_ID --channel CHANNEL_ID --post MESSAGE_ID` with the two verified member sessions using the same protected source and destination configuration as member enrollment. The source verifies exact native authorship, current owner and reviewer authority, matching approved bytes and the absence of a channel report before issuing a proof valid for at most five minutes. Invalidate the destination link to stop acceptance of pending proofs. The destination verifies the matching ordinary account, scoped approval, digest and current channel policy. Its normal post path preserves the verified destination author, original message ID, exact body and historical timestamp. A repeat of the exact authorized operation returns its earlier receipt. The command returns only the restored message ID and import time.

For a standard room, run `node scripts/workspace-residency-room-member.mjs --workspace WORKSPACE_ID --approval APPROVAL_ID --room ROOM_ID` after the ordinary workspace membership is accepted and the exact destination room is imported. The matched member accepts the invitation in **Rooms → Room directory**. Run `node scripts/workspace-residency-member.mjs --workspace WORKSPACE_ID --approval APPROVAL_ID --room ROOM_ID --post MESSAGE_ID` for each approved message. Restore the thread root before its replies. The destination checks the current room's policy and verifies that the restored root still matches the approved record before publishing any replies.

## Publish approved room files

Choose **Request content and room file approval** in the source export form, obtain independent approval, and stage the manifest. The exact destination room needs its own same-approval structure import receipt. Use `node scripts/workspace-residency-files.mjs --publish --workspace WORKSPACE_ID --export APPROVAL_ID --room ROOM_ID --file FILE_ID` with the protected source and destination sessions. The destination's native room-file upload checks fresh owner assurance, current room scope and approval before invoking the scanner, storage and protected download flow. The scanner and destination egress policy apply. The command verifies the readback digest. Room access controls determine who can see the published file in **Rooms → Files**.

When the same workspace has both file types, choose **Request content and both file scopes** once. The independent reviewer approves one manifest. Publish each file through its native workspace or room file endpoint using that same approval. Existing approvals retain the file scopes selected when they were created.

In **Workspace content export → Source migration coverage**, either approved participant can compare the current source against the six record types supported by the manifest. The check counts live records, current approvals, unapproved records and pinned revisions that changed or became unavailable. It returns aggregate counts without names, paths or record IDs. A capped record type shows lower-bound counts. Source identity mapping, managed encryption and other data dependencies still require their own transfer evidence.

## Compare the destination with the approved manifest

In **Organization settings → Enterprise data residency → Compare destination records**, the current destination owner uses fresh authenticator verification to check the admitted manifest. SecTalk recomputes its digest, checks current scoped records and their receipts, and shows missing, changed and unsupported records. It returns identifiers and statuses under the approved workspace without exposing titles, message text, account addresses or object locations. An expired approval is identified on the report.

For attachments, the comparison first checks publication metadata, the recorded digest or fingerprint, and expected Storage metadata. Choose **Verify file bytes** for each attachment awaiting that check. The protected file endpoint reads and hashes the current bytes, checks the approved record and verifies that the exact Storage revision stayed current during the read. The comparison marks that revision as matched. Replacement or a metadata revision change clears the match until another successful check. The comparison is a point-in-time destination check. Hosted placement, complete source coverage and tenant routing still need their separate verification.

The destination owner can choose **Create destination comparison receipt**. SecTalk repeats the live comparison and seals the approved manifest, source and destination project references, timestamp, expiry, and totals for the five comparison statuses. The receipt expires within five minutes. It uses the same per-approval private Vault pairing as the history transfer. Retire the pairing when the transfer ends.

The reviewer who approved the exact source export opens **Compliance exports → Workspace offboarding → Workspace content export → Destination comparison review** and pastes the receipt. Fresh authenticator verification is required to accept it. The source verifies the proof against its current approval and project pairing. Both approved source participants can see the captured totals and review time. The receipt preserves any missing, changed, unsupported, or unchecked records and records a point-in-time comparison before any production routing decision.
