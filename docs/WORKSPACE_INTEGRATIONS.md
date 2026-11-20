# Workspace integrations

Team and Enterprise owners open **Workspaces → Integrations** and verify their authenticator. API keys and webhook secrets appear once after creation. Owners can revoke credentials from the same screen. A change of owner, loss of plan eligibility, or account restriction stops access.

## REST API

Authenticate with `Authorization: Bearer <workspace API key>`.

| Method and path | Scope | Response |
| --- | --- | --- |
| `GET /api/v1/workspace` | `workspace:read` | Workspace ID, name and creation time |
| `GET /api/v1/rooms` | `rooms:read` | Discoverable room IDs, names and creation times |

`/api/v1/rooms` accepts `limit` between 1 and 100 and an optional `after` cursor from the preceding result. The default is 25. Room visibility, credential expiry and plan eligibility are checked on every request. Each key allows up to 120 requests per minute.

## Signed outbound webhooks

Choose `room.created` for discoverable rooms and `membership.changed` for changes to the workspace roster. Events include workspace or room IDs and exclude participant identities and conversation content. Destinations use publicly reachable HTTPS. Every delivery resolves and checks the endpoint and sends to the verified address without following redirects.

Verify `webhook-signature` using the original request body and the `webhook-id` and `webhook-timestamp` headers. Enforce a timestamp window and use the event ID to ignore duplicates after retry. [Standard Webhooks specification](https://github.com/standard-webhooks/standard-webhooks/blob/main/spec/standard-webhooks.md)

The worker retries temporary failures up to five attempts, with exponential delay. Recent delivery state and HTTP status appear in the owner’s webhook history. Deploy a private scheduler that POSTs to `/api/integrations/webhooks/drain` using the configured bearer credential. Set `SECTALK_INTEGRATIONS_SUPABASE_KEY`, the 32-byte hexadecimal `SECTALK_WEBHOOK_ENCRYPTION_KEY`, and a high-entropy `SECTALK_WEBHOOK_DRAIN_SECRET` as server-only variables.
