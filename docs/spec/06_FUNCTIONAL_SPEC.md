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

## THR-01 · Reply counts and thread follows

A room participant opens a thread from a room message and reads its replies or posts a reply when their role allows it. The room feed shows the number of replies that the caller can read. Following a root message adds it to the participant's Followed threads list. Unfollowing removes that preference. Row-level security keeps follows private and rejects references to an inaccessible room or a reply. Two browser sessions verify that reply counts and content synchronize while following remains private.

## SRCH-08 · Saved searches

An authenticated user saves a query and search category, opens it from the Saved searches tab, and may remove it. Saving the same trimmed query and category is idempotent. Saved queries are readable only by the owner. Running a saved search executes the current search query and permissions. It does not store a copy of the results.

## PLAT-08 · Offline shell

The app manifest declares a standalone start URL and 192 and 512 pixel icons. The service worker keeps a single public offline document in its cache. A same-origin navigation falls back to that document when the network fails. The document links back to the app so users can retry once connected. Authenticated HTML, API responses, attachment bytes, and message content are excluded from the cache.
