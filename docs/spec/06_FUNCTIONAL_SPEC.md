# Implemented v6 candidate workflows

The [feature registry](../../features.md) defines the target scope. The [matrix](../FEATURE_MATRIX.md) records which workflows have full evidence.

## MSG-20 · Saved messages

The message actions menu saves a message to the current account. Inbox opens Saved messages. Users can move back to the conversation, page through older saves, or remove a save. The database checks current message visibility at insertion and on every read. Repeated save requests keep one row. Deleting for yourself hides the saved item for your account, and revoking the source hides it for both participants.

The view shows loading, empty and retry states. Saves do not publish a conversation event or notify the peer. RLS fixtures cover unrelated accounts, account ownership, deletion and revocation. The browser suite exercises saving, reloading from the API and removing a save.

## FILE-12 · Files library

Files opens separate Chat files and Private vault tabs. Chat files filters by name and direction, supports sorting and pagination, and lets the user open the source conversation. Select up to eight visible files within 20 MiB to download one ZIP. Each file download is authorized independently by Supabase Storage. Attachment bytes remain in the browser during ZIP assembly.

The app explains loading, empty and failed downloads. Filename handling removes separators before adding entries to the archive. Chat messages that were revoked or hidden disappear from the list on refresh. A file revoked before a fresh download is denied. The browser suite verifies filters and the ZIP contents. Storage tests cover unauthorized and revoked downloads.

## PLAT-09 · Service status

A caller requests `GET /api/ready` without a session. The server checks the app migration through an anonymous database RPC with a bounded timeout. It responds with 200 and `ready` when the database returns its boolean marker, or 503 and `not_ready` when configuration or the probe fails. The public `/status` page and `GET /api/status` show web reachability, database readiness and the time of the check. These routes return no account data or provider errors. The checks cover success, an unavailable service and malformed responses.

## ROOM-01, ROOM-02, ROOM-03, ROOM-05, ROOM-06, ROOM-08 and ROOM-10 · Rooms

Every room belongs to a workspace. Room owners and moderators can manage entry and action controls. Workspace members see the workspace-wide, announcement and broadcast directory and join before reading posts. Private room metadata is visible to current members and recipients of active invitations. A private-room request code lets a workspace member ask for approval. Admin-only metadata and posts require a current workspace owner or admin role. Broadcast subscribers have read-only access. A guest can read and post in an available room according to its type and restrictions, and sees only their own roster entry.

Room threads attach to a top-level message in the same room. Clients send stable IDs and retries keep one post. Moderators can pin, publish announcements, limit posting, and review room audit events. Membership changes, pins and settings appear on the room audit tab. The room directory and detail data refresh on reconnection and poll as a fallback. Room post inserts also trigger a Realtime refresh.

The browser flow verifies creation, joining, synchronized posts and the role-gated Audit tab. The SQL fixture covers tenant and membership isolation, invitations, approval, announcement and broadcast write restrictions, pins, threads, and moderation. Approval and moderation apply at the database boundary, including requests sent outside the UI.

## TASK-01 through TASK-10 · Scoped tasks

Open Tasks in a room or Chat tasks in an accepted direct conversation. Create a standalone task or use Create task from message to attach a source. The Source tab shows the original text alongside the current message. Removing access to the message hides both copies while preserving the task and its audit history.

Use List, Board, or Calendar to review work. Calendar offers an agenda and a month grid. Users can filter by assignment or tasks they watch, and can choose a priority, labels, and a due date. The assignment menu limits recipients to eligible participants. Only the watcher can see their own watch setting. The server validates status transitions, including who can reopen a completed or cancelled task.

The Audit tab shows task changes to authorized participants. The Task updates tab in Notifications collects completion and deadline notices for eligible recipients and lets them mark each notice read. A scheduled job processes active deadlines and deduplicates each recipient’s reminder. Authorization is checked again when users read tasks, sources, audit events, and notices.

## THR-01 · Reply counts and thread follows

A room participant opens a thread from a room message and reads its replies or posts a reply when their role allows it. The room feed shows the number of replies that the caller can read. Following a root message adds it to the participant's Followed threads list. Unfollowing removes that preference. Row-level security keeps follows private and rejects references to an inaccessible room or a reply. Two browser sessions verify that reply counts and content synchronize while following remains private.

## SRCH-08 · Saved searches

An authenticated user saves a query and search category, opens it from the Saved searches tab, and may remove it. Saving the same trimmed query and category is idempotent. Saved queries are readable only by the owner. Running a saved search executes the current search query and permissions. It does not store a copy of the results.

## SRCH-05 and SRCH-07 · Command palette and search snippets

Press Ctrl+K or Command+K from the signed-in workspace, or open the palette from Search. Filter navigation and action shortcuts by typing, use the arrow keys to focus a command, and press Enter to run it. Submitting the search field runs the entered terms through Global Search. Escape returns focus to the opener.

Supabase checks each source table’s read permissions before returning search results. Direct-message snippets exclude revoked messages and messages hidden by the caller. Snippets show the match in context and the app renders the match as highlighted text. An open search refreshes direct-message results on changes and reconnect.

## PLAT-08 · Offline shell

The app manifest declares a standalone start URL and 192 and 512 pixel icons. The service worker keeps a single public offline document in its cache. A same-origin navigation falls back to that document when the network fails. The document links back to the app so users can retry once connected. Authenticated HTML, API responses, attachment bytes, and message content are excluded from the cache.

## CALL-06 · Meeting lobby

Workspace members request admission before joining media. The active host can admit or decline a waiting participant or choose Admit all eligible attendees. Bulk admission fills available seats in request order, up to the 12-person meeting limit including the host. It checks current membership, account status and blocks. Individual and bulk decisions update attendance, record an audit entry and notify each affected attendee privately. The media-token route checks that the attendee is admitted, the meeting is live and the host and attendee remain eligible.

## CALL-17 · Call history and callback

Calls shows the latest 40 participant-visible calls, with filters for missed incoming calls, audio and video. An unanswered call becomes Missed for the recipient after its ring window expires. The server records declines and caller cancellations while ringing. Older records whose outcome was not captured display Ended. The Call back action uses the missed call’s audio or video mode and goes through the same consent, participant availability and block checks as a new call.

## MSG-21 · Scheduled direct messages

In an accepted direct chat, enter a text draft and open Scheduled messages in the composer. Choose a future local date and time within 30 days. Upcoming shows the caller’s queued messages and lets them cancel. History records sent, cancelled and failed entries without retaining a second copy of the text. Recipients see the message in the normal chat after delivery. The dispatcher rechecks contact access at delivery time and uses the schedule ID as the message ID to prevent duplicate sends.

## MSG-10 · Direct-message quotes

Reply stores a reference to the original message. The server resolves the quote from the current source and clips the preview to 240 characters. It excludes messages the current reader has hidden and messages revoked for everyone. Once a source is unavailable, the chat displays a placeholder and keeps the reply text. The server also rejects new replies to an unavailable source.

## CALL-05 · Instant meetings

A workspace owner or admin can use Meet now to open a meeting immediately. The server creates the live meeting and admits the host in the same transaction. Existing lobby permissions govern member entry, and other members receive a private meeting-started notice.

## ROOM-11 and MSG-12 · Room templates and pins

Workspace owners and admins can create from Class, Incident, Family or Project. Class and Family default to private, Incident uses an admin-only room, and Project offers public-within-workspace or private visibility. Class starts with a 15-second posting interval. Each template pins a starter guide. Accepted direct contacts can pin a visible message and either contact can unpin it. Room pins require a room manager. Revoking a direct message clears its pin.

## PRES-01 · Contact availability

Choose Online, Away, Busy or Offline in Profile Availability. Accepted contacts can see an opted-in state while its heartbeat remains current. Heartbeats are rate-limited. Expiry and a block both remove live availability from the contact’s view.

## PLAT-12 · In-product help

New accounts set up a profile and discovery preferences before entering the Inbox. The empty Inbox links to Getting started. The same Help section is available from Profile and the command palette, with shortcuts for finding people, using safety controls and retrieving saved messages.

## SRCH-09 · Workspace audit search

An active workspace owner or admin can open Audit logs from Search. Select a workspace, search by event, room name, actor ID or target ID, and filter by source and dates. Room events require the caller’s existing room audit permission. The query returns up to 100 events and runs against audit records separately from message search.
