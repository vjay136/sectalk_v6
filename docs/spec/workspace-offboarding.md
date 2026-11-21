# Workspace offboarding

The workspace owner opens **Workspaces → Organization settings → Workspace offboarding**, verifies a current native authenticator, and confirms the exact workspace ID. A separately provisioned, active workspace administrator reviews the request in **Compliance exports** and verifies a current authenticator. Provision reviewers for a specific workspace through the existing trusted operations process in the private `st_v8_offboarding_reviewers` table.

The request captures an immutable snapshot of workspace settings and inventory counts. The export includes a SHA-256 manifest and uses the same private encrypted artifact path as compliance exports. The current requesting owner may build and download the exact, approved inventory for 24 hours. Loss of either participant's required role revokes access. The manifest identifies the requesting owner and independent reviewer for accountability. The inventory omits message text, files, membership identities, global account records, and records from other workspaces.

After the download, the owner can stage the workspace as read-only while the approval remains current. Active workspace preservation holds block staging. The transition applies the existing workspace write guard and leaves the tenant's data, preservation records, member accounts, and other workspaces available to their existing authorized processes. Pending or approved requests may be withdrawn, revoking the prepared artifact. The read-only state is a preservation stage.

Read-only staging also revokes existing workspace API keys and SCIM credentials, disables outbound webhook endpoints, and cancels queued or leased deliveries in the same database transaction. The offboarding panel shows the time and count of each action. The retained receipt is immutable. Provisioning of replacement credentials is blocked for a staged workspace. Webhook requests already sent to a recipient remain subject to the recipient's own retention.

## Retire an already revoked API key

In **Retire revoked API keys**, download the exact metadata and workspace audit copy, then prepare it for independent review. The owner confirms the exact workspace and key IDs after approval. The downloaded copy excludes credential verification data and the key prefix.

SecTalk removes only the eligible revoked key's live registration. It retains the original workspace audit, the approved metadata receipt, and a one-way marker that prevents reuse. Current usage records, preservation holds, and unrelated dependencies block retirement. Staging remains responsible for revocation. This cleanup covers the live database registration.

## Retire an already revoked webhook

In **Retire revoked webhooks**, download the exact metadata and workspace audit copy for an eligible endpoint, then prepare it for independent review. After approval, the owner confirms the exact workspace and endpoint IDs. The copied and retained records exclude the destination and wrapped signing material.

Delivery records in any state, including jobs cancelled during staging, block retirement. Preservation holds and unrelated dependencies also block removal. SecTalk preserves the original workspace audit and prevents reuse of the removed endpoint ID. Delivery or retention data held by the receiving service remains outside this cleanup.

## Remove a declined direct invitation

In **Remove declined invitations**, download the exact invitation record and its original workspace audit, then prepare the removal plan for independent review. After approval, the owner confirms the exact workspace and invitation IDs. The copy includes scoped account identifiers and excludes emails and profile text.

This applies when the workspace owner sent the invitation, the recipient declined it, and the original invitation audit is verifiable. Pending and accepted invitations, active or historical membership, related directory or managed account records, and preservation holds block removal. The workflow retains the decline and audit evidence and preserves the workspace's existing restriction on sending another direct invitation to the same recipient.

## Remove an expired, unused invitation link

In **Remove expired invitation links**, download the exact expiry record and prepare it for independent review. Once approved, the owner confirms the workspace ID and the link's assigned record ID. The copy excludes the email address, token, and token verifier.

Only unused links issued by the workspace owner that have already expired qualify. Active and consumed links, preservation holds, and dependent records block removal. SecTalk retains the expiry record and uses a one-way marker to prevent reuse of the original token. The original workspace link issuance audit remains in place. Its legacy entries record issuance at workspace level.

## Remove an empty archived workspace group

In **Remove empty archived groups**, download the exact group, team, or department record and its original workspace audit. Prepare it for independent review and confirm the workspace and group IDs after approval.

Only entries created and archived by the workspace owner with no other group audit activity qualify. Memberships, SCIM mappings, school classes, custom-role revisions, other database dependencies, and preservation holds block removal. SecTalk retains the creation and archive audit and reserves the group's ID and name in its original workspace.

## Retain a withdrawn enterprise quote

In **Retain withdrawn enterprise quotes**, the owner downloads the exact original quote and billing events and prepares a detachment plan. The independent offboarding reviewer must also have commercial billing authorization for the workspace. After approval, the owner confirms the workspace and quote IDs to release the direct workspace reference.

The workflow covers withdrawn quotes that were never accepted and have exactly their original quote and withdrawal events. SecTalk retains the native quote, its original workspace attribution and terms, and both immutable events. Open, accepted, invoiced, and paid orders keep their restrictive workspace references. Preservation holds and lost reviewer authorization block detachment. The retained quote and events remain outside any verified deletion count.

## Retire a rejected seat change

In **Retire rejected seat changes**, download the exact redacted record of a finished owner-initiated rejection whose processing lease has expired. An independent reviewer with delegated workspace billing access approves the plan before the owner confirms the exact workspace and change IDs.

SecTalk preserves the original billing evidence in immutable custody and reserves the original change ID. The download excludes provider identifiers and lease material. The retained evidence excludes the obsolete lease token. Active, pending and settled jobs, current seat capacity, and records under preservation holds remain protected. The workflow does not change any provider subscription.

Permanent tenant deletion, physical Storage purge, and verifiable deletion of every tenant data key and backup are separate from this workflow.

## Separately approved content export

The organization offboarding panel also offers **Request separate content approval**. A native TOTP owner requests it, and a separately scoped administrator confirms up to 500 eligible records. The approved manifest records fixed positions and hashes. The current owner downloads pages of 25 records while both workspace roles and source access remain valid. Each page rechecks the pinned hashes and fails if a source changed. This approval covers standard workspace-wide channel posts, eligible non-forwarded posts and replies in public rooms with public or internal classification, workspace tasks, and ordinary tasks from those rooms. Room tasks linked to a source-message snapshot stay out of this export. The content approval leaves the inventory approval and read-only staging independent.

## Complete export contract

A complete archive needs a separate approval scope for records and file bytes. The existing approval authorizes the metadata inventory. An archive implementation needs bounded, immutable manifest pages that pin each selected record's exact revision and each file's size and content digest. The owner and independent reviewer must retain the required workspace role and source access when reading a page or downloading an object.

Room and channel records require their native membership, visibility and block checks. Tasks require access to their workspace or room scope. Workspace files and room files require the existing file access and egress checks and verified published bytes. The archive must preserve the consent and legal-hold requirements for managed-channel evidence. Participant-private conversations, E2EE group text and direct file objects remain outside the workspace archive.

The current compliance artifact limit is 1 MiB. A workspace file can be 4 MiB before encoding. Owners can request **content and workspace file approval** to include eligible published files from the standard workspace bucket. Each file record binds the publication timestamp, byte count and tenant-scoped SHA-256 fingerprint. Separate authenticated downloads apply the existing file access, egress, integrity and audit protections. They recheck the approval and both roles, compare the actual bytes to the approved digest, and deny platform-blocked or malware-listed content.

Standard room files have their own **content and room file approval**. Both approvers must have current native access to the source room. The scope covers published files in public or internal standard public rooms. In confidential standard private rooms, the requesting owner or independent reviewer must also be the file uploader. This prevents their approval from exporting another participant's upload. The manifest pins the source room, published revision, size and content SHA-256, and the authenticated room download rechecks these against Storage.

File scopes exclude active workspace holds, restricted egress, incomplete publication, managed rooms, private conversation attachments and quarantined content. File delivery remains separately authorized and bounded. Retries return the same approved revision or fail closed if its bytes, revision, policy or required access changed. Full workspace archival and verified permanent deletion remain partial.

## Review current Storage objects before deletion

After the workspace enters read-only offboarding, the existing owner and independent reviewer can open **Offboarding Storage review** in their offboarding panels. Both need fresh native TOTP and current workspace roles. The owner types the exact workspace ID and captures a bounded inventory. The reviewer checks the displayed counts and SHA-256, enters the workspace ID, and confirms the exact current inventory. The confirmation records the reviewer and time. The app rejects an active hold, an expired or changed inventory, an unresolved object, and a missing independent reviewer.

The review covers current objects in `sectalk-workspace-files` with that workspace's exact path prefix. It correlates regular files and scoped room files with Storage object IDs, provider versions, sizes, and update times. Pending uploads, missing published objects, mismatched metadata and untracked paths block confirmation. The app shows counts and a digest. A same-size object replacement invalidates the prior confirmation if its Storage revision changes. A capture remains current for up to 24 hours. Counts beyond the 500-record cap are a sample and cannot be confirmed.

This review is a prerequisite for arranging physical deletion. It covers current Storage metadata. Provider object history, independent backups, actual byte removal, and key-custody evidence require separate verification. Physical removal goes through the Storage API. [Supabase Storage deletion](https://supabase.com/docs/guides/storage/management/delete-objects)

After the independent Storage review, use **Verify and download** on an approved standard workspace file or an approved file in a standard public room classified public or internal. SecTalk reads the private bytes, verifies their SHA-256 and the exact reviewed Storage object revision, and issues an immutable copy receipt. The owner and reviewer can see separate counts for workspace and room file copies while the plan, roles, export permission, and object revision remain valid. The receipt records delivery of verified bytes. The workspace remains responsible for retaining its copy.

Physical version-conditional deletion remains pending. Supabase’s hosted Storage documentation excludes S3 bucket versioning and does not document a conditional DeleteObject guarantee. [Supabase S3 compatibility](https://supabase.com/docs/guides/storage/s3/compatibility)

## Clean up one absent file registration

Use **Room file registration cleanup** or **Workspace file registration cleanup** when a file has an exact verified copy receipt and its original Storage path is already missing. The reviewer submits the retained file for an in-memory SHA-256 check. The owner confirms the exact workspace and file IDs. Current staged authority, file access, original receipt and content approval, and absence from the Storage catalog are checked again.

The server also requires the authorized Storage object information call to report an explicit missing key. The transaction removes only the original PostgreSQL file registration, records the observation, and prevents reusing that registration identity. Workspace file cleanup also preserves existing history and access events and records when the registration was removed. The verified copy and its receipts remain in custody. This records point-in-time Storage path absence. Physical provider bytes and backup erasure remain unverified. [Supabase Storage object information](https://supabase.com/docs/reference/javascript/file-buckets-info)

## Permanently delete one approved workspace task

After staging, the current owner can select a task covered by the current separate content approval, download its exact copy, and prepare a deletion plan. The original independent reviewer can approve that plan in **Compliance exports**. The owner enters both IDs and acknowledges retention before running the final action. The server rechecks native authenticator assurance, roles, the live source and archive digests, custody metadata and preservation holds. A task with an assignment or checklist stays protected.

The transaction removes the selected live PostgreSQL task and its search document and records an immutable deletion receipt. The approved copy record establishes that SecTalk issued the matching bytes. The workspace retains responsibility for preserving its copy. Backup and physical Storage erasure remain outside this action.

## Permanently delete one approved workspace channel post

The **Permanent workspace channel post deletion** panel uses the same staged owner and independent reviewer workflow. The owner downloads a matching approved copy, then prepares a plan bound to the exact channel, post and live source revision. After independent approval, the owner confirms the workspace and post IDs and acknowledges retention before removing the live post and search entry.

Only unreported plaintext posts in standard, workspace-wide channels qualify. Quarantined posts, managed payloads, preserved versions and DLP receipts block deletion. The server rechecks current access, including required channel SSO, and locks the source before checking for new reports. Each completed transaction records one immutable deletion receipt.

## Remove an archived channel and its eligible messages

In **Remove archived channels**, download the exact channel copy and prepare it for independent review. The reviewer sees the channel ID, each approved message ID and version digest, and the SHA-256 digests of the copy, original archive event, and removal plan. After approval, the owner confirms the workspace and channel IDs and acknowledges retaining the copy.

An eligible channel belongs to the workspace owner, uses standard workspace-wide access, and has one verified archive event. It may be empty or contain up to 16 unquarantined messages written by that owner. General channels, channels with messages written by other members, and channels with reporting, moderation, preservation, or dependent records remain protected. SecTalk removes the live channel, the approved messages, and their search entries in one transaction. It retains the original archive event with the native audit trail and prevents reuse of the removed message IDs. The workspace creation audit remains available.

## Remove one empty archived room

In **Remove empty archived rooms**, download the exact room copy and prepare it for independent review. The reviewer checks the room ID and digests for the copy, retained records, and removal plan. The owner then confirms the workspace and room IDs and acknowledges retaining the copy.

This applies to standard public rooms created from the blank template with public or internal classification, one creator membership, and exactly the original creation and archive events. Other room records and preservation holds block removal. SecTalk retains the creator membership and both original audit events with their native audit trail, and reserves the removed room ID to prevent reuse.

## Permanently delete one approved room message

The **Permanent workspace room message deletion** panel follows the same copy, review and confirmation steps. The reviewer sees the room and message IDs and the exact deletion digest. The final action removes the selected live message and its search entry.

The panel covers unedited, unforwarded top-level messages in standard public rooms classified public or internal. Messages with replies, reports, pins, reactions, follows, notifications, read receipts, task links, preserved versions or other dependent records remain protected. Current room access and required SSO are checked again before deletion.

## Permanently delete an approved complete room thread

Use **Permanent room thread deletion** for an eligible root with all of its replies, up to 16 messages total. The owner downloads the approved copy for the complete thread. The independent reviewer inspects the message IDs and hashes in the manifest, and the owner confirms the workspace and root message IDs to delete.

Each message must be covered by the current content approval. Reports, preservation, and related records on any message block the entire deletion. The transaction removes the exact thread and its search entries together and retains an immutable deletion receipt.

## Permanently delete one approved room task

The **Permanent workspace room task deletion** panel covers open tasks in standard public rooms classified public or internal. Tasks with source links, assignees, watchers, notices or activity beyond the original creation event remain protected.

The approved copy includes the full task record and its original creation event with separate SHA-256 digests. After independent approval, the owner confirms the exact workspace and task IDs. The transaction retains the creation event in immutable custody, removes the live task and search entry, and records the deletion in the audit chain.

## Delete a batch of approved live records

Use **Batch source deletion** to combine two to four eligible workspace tasks, channel posts, room messages, or room tasks. Download each exact approved copy first. The owner prepares the list, the independent reviewer checks the displayed source IDs and digest, and the owner confirms the workspace and batch IDs before deletion.

The database applies every source's normal offboarding checks in one transaction. If any source changes or fails its checks, the transaction preserves every record in the batch. A source removed individually invalidates its batch. A completed batch records one immutable batch receipt alongside its individual deletion receipts.

## Reconcile the covered sources and receipts

Open **Source erasure reconciliation** after read-only staging to see the covered database record counts, actual scoped deletion receipts, and the current Storage metadata counts. The review covers residual workspace, room and channel records, reports and preservation records, managed payloads, meeting and recording records, tenant keys, and protected artifact references in its fixed registry. It returns counts and an exact digest.

The owner captures that digest and the independent reviewer confirms the same evidence within 30 minutes. The check rejects changes, including a Storage metadata revision change with the same object size. Each family has a 500-record limit. When a family exceeds that limit, its displayed count is a lower bound and the workspace cannot confirm the capture. The reviewer receipt records a point-in-time reconciliation. Physical provider bytes, backups, and full tenant erasure remain unverified.

The covered database counts include member-dependent impersonation watch entries, delegated billing accounts, group memberships, school rosters and custom role assignments. The digest binds the exact rows for the selected workspace. A role, tier or membership change makes a reviewed plan stale even when the count stays the same. Earlier reconciliation plans require a fresh capture and independent confirmation after this migration.

The census also covers regional rollback authorizations, admitted manifests, and Board, channel, room message and room task recovery batches left under the workspace’s handoff. Applying a staged batch invalidates the review even when the count stays the same. The review shows counts and a digest while keeping Vault references and recovery contents private.

The reconciliation includes regional rollback baselines, rollback reviews, source recovery evidence, and Board and channel author approvals. Changes such as revoking an author approval require a new capture and independent review. The output displays counts and a digest while keeping snapshots and author identifiers private.

The reconciliation separates complete thread and file registration removal receipts from verified file copies and independent recovery reviews. If a retired file path appears in Storage metadata again, the original cleanup receipt remains on record and the reconciliation becomes stale. The current metadata section counts reappearing workspace and room paths separately.

Archived channel, archived message, and archived room removals appear in **Verified scoped deletion receipts** after SecTalk checks the exact copy, independent approval, retained archive records, and matching native audit entries. Archive findings appear separately. A missing link or a removed message still present in live data or search blocks capture and confirmation. Once an archive finding has been observed, resolving it requires a fresh capture and independent review.

Open **Workspace record removal preflight** to see direct foreign-key references by data family and the effect removing the workspace row would have on them. The review includes membership, audit and preservation, integrations, policies, and billing records, including enterprise orders that restrict removal. Private row values stay in the database. Any change to an exact covered record makes the previous review stale even if the counts remain the same. Unreadable constraint shapes or bounded counts block capture and confirmation. Direct references, transitive and unlinked records, provider bytes, and backups each require their own disposition before full workspace erasure can be verified.

After the audit and offboarding records are in custody and the independent reviewer confirms the current reconciliation, the owner can run the **rollback-only removal rehearsal** from that preflight. Enter the exact workspace ID and a current authenticator code if prompted. The database verifies the exact approved plan, rejects unexpected dependencies, and rehearses removing only the workspace record, its empty default channel and the approvers’ membership and reviewer records. A successful rehearsal rolls back the full change and retains the first successful timestamp for that exact plan. The owner and independent reviewer can see the saved result while viewing the current plan. Provider and backup erasure require separate evidence.

The private native removal transaction uses the same scope and rechecks the current plan, holds, dependencies, and delete hooks under lock. Its separate approval binds the same reviewer and reconciliation after a successful rehearsal. The local database test verifies exact removal, preservation of audit and workflow custody, and idempotent receipt readback after the workspace row is gone. Application and service roles have no execute grant. Provider and backup erasure remain unverified until their own evidence is complete.

For a protected database recovery generation, use the separately reviewed manifest digest to check whether the exact workspace's key records remain recoverable. The check reports scope and counts without exposing wrapped keys. [Workspace key records in recovery archives](../BACKUP_KEY_EVIDENCE.md)
