# Implemented v6 candidate workflows

The [feature registry](../../features.md) defines the target scope. The [matrix](../FEATURE_MATRIX.md) records which workflows have full evidence.

## MSG-20 · Saved messages

The message actions menu saves a message to the current account. Inbox opens Saved messages. Users can move back to the conversation, page through older saves, or remove a save. The database checks current message visibility at insertion and on every read. Repeated save requests keep one row. Deleting for yourself hides the saved item for your account, and revoking the source hides it for both participants.

The view shows loading, empty and retry states. Saves do not publish a conversation event or notify the peer. RLS fixtures cover unrelated accounts, account ownership, deletion and revocation. The browser suite exercises saving, reloading from the API and removing a save.

## FILE-12 · Files library

Files opens separate Chat files and Private vault tabs. Chat files filters by name and direction, supports sorting and pagination, and lets the user open the source conversation. Select up to eight visible files within 20 MiB to download one ZIP. Each file download is authorized independently by Supabase Storage. Attachment bytes remain in the browser during ZIP assembly.

The app explains loading, empty and failed downloads. Filename handling removes separators before adding entries to the archive. Chat messages that were revoked or hidden disappear from the list on refresh. A file revoked before a fresh download is denied. The browser suite verifies filters and the ZIP contents. Storage tests cover unauthorized and revoked downloads.

## PLAT-09 · Readiness slice

A caller requests `GET /api/ready` without a session. The server checks the app migration through an anonymous database RPC with a bounded timeout. It responds with 200 and `ready` when the database returns its boolean marker, or 503 and `not_ready` when configuration or the probe fails. It does not return account data or provider errors. The checks cover success, an unavailable service and malformed responses. A public status page is still open.
