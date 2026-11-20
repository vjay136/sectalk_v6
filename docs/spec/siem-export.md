# SIEM digest delivery

An enterprise workspace owner with a recent native authenticator verification can open **SIEM exports** from Profile → Permission catalog after selecting their workspace. Pick a completed UTC hour within the past seven days. The workspace and hour identify one immutable batch. The digest contains workspace and batch IDs, the UTC start of the hour, and counts for a fixed set of member security changes, DLP policy updates, audit export requests, and integration key changes. It omits actor and target IDs, workspace names, messages, evidence, and event metadata.

## Configure

Set these variables in the application server's private environment.

- `SECTALK_SIEM_SIGNING_KEY` holds a base64url-encoded PKCS#8 DER Ed25519 private key. Distribute the associated SPKI public key to recipients independently. Keep a stable key for queued deliveries and retain previous public keys if changing the signing key.
- `SECTALK_SIEM_DRAIN_SECRET` is a dedicated bearer secret of at least 32 bytes. `SECTALK_SIEM_SERVICE_KEY` is the server-side Supabase service credential. Configure a private scheduler to POST to `/api/siem/drain` with this bearer every minute. Each pass handles at most one delivery per configured workspace and channel.
- `SECTALK_SIEM_CONNECTORS` is a JSON array of up to 12 deployment-owned destinations with at most one per workspace and channel. Pass credentials from the deployment secret store. The app never sends these values to the browser.
  - Webhook fields are `workspace`, `channel: "webhook"`, `url` and `secret` (32-byte base64url key). HTTPS resolves to a public address, uses TLS hostname validation and rejects redirects. Verify the standard webhook HMAC headers and deduplicate by `webhook-id`.
  - Syslog fields are `workspace`, `channel: "syslog"` and `host`. TCP port 6514 requires public DNS with TLS certificate validation. The RFC 5424 record uses RFC 5425 octet-counting and carries a CEF record. Decode the base64url envelope from `cs1` and deduplicate by `externalId`. Sent indicates the verified TLS socket accepted the frame. Syslog provides no durable receiver acknowledgement.
  - S3 fields are `workspace`, `channel: "s3"`, `bucket`, `region`, `accessKeyId`, `secretAccessKey` and optional `sessionToken`. Use a regional AWS S3 bucket with credentials scoped to `PutObject` and `GetObject` on `sectalk-siem/<workspace>/*`. SigV4 signs the actual request. Conditional writes prevent replacement, and existing objects count as delivered only when the recorded digest matches. Keep bucket public access disabled.

Every transport uses the same JSON envelope. Verify the Ed25519 signature over the exact UTF-8 bytes of the `payload` string before parsing that string. Verify `sha256` against those bytes, match `key_id` to the SHA-256 fingerprint of the pinned DER SPKI key, and check the intended workspace before consuming the data. Batch IDs are stable across channel retries. Webhook and syslog recipients should retain their deduplication record for at least 24 hours.

Jobs retry a bounded number of times with backoff and are not sent once marked completed. A crashed worker can cause a repeated webhook or syslog delivery. Queued jobs expire after 24 hours and batch records expire after eight days. Delivery to a hosted AWS account or a deployed SIEM collector requires independent deployment verification.
