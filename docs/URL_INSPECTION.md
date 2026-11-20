# URL inspection

The Safety inspector sends a URL only after the signed-in user submits it. It removes the query and fragment before contacting the worker. Results contain inert text and HTTP status codes. The worker does not download response bodies, send credentials to destinations, or run page code.

## Run the separate worker

Use a Node.js 26 runtime for the worker and give it a separate, restricted service identity. Run it on the same host as the web app. Configure its network policy to permit its DNS resolver and outbound HTTPS only. The worker listens on loopback. The app sends requests to the exact loopback `/inspect` endpoint.

Set `SECTALK_URL_INSPECTION_PORT`, `SECTALK_URL_INSPECTION_WORKER_TOKEN`, and `SECTALK_URL_INSPECTION_ALLOWED_HOSTS` for the worker. The allowlist contains exact ASCII hostnames separated by commas. Set `SECTALK_URL_INSPECTION_WORKER_URL` and the same token for the app. Start with an empty allowlist until the operator has approved destinations.

```sh
node --permission --allow-net \
  --allow-fs-read=./package.json --allow-fs-read=./apps/web --allow-fs-read=./scripts \
  --allow-fs-read=/etc/sectalk/url-feed.json --allow-fs-read=/etc/sectalk/url-feed.pub   scripts/url-inspection-worker.mjs
```

The worker checks every redirect independently. It requires HTTPS, verifies all returned DNS addresses are public, pins one address for the request, and verifies TLS against the original hostname. It sends HEAD requests and stops after three redirects.

## Configure a verified feed

Set `SECTALK_URL_REPUTATION_FILE` and `SECTALK_URL_REPUTATION_PUBLIC_KEY_FILE` to the local manifest and the provider's pinned Ed25519 public key in PEM format. The outer JSON object contains `payload`, a JSON string, and `signature`, the unpadded base64url signature over the exact UTF-8 payload bytes.

```json
{
  "source": "Operator-approved feed",
  "issued": "2026-11-20T00:00:00Z",
  "expires": "2026-11-27T00:00:00Z",
  "domains": [
    {
      "domain": "sample.example.org",
      "reputation": "risk-listed",
      "registered": "2026-11-19"
    }
  ]
}
```

Supported reputation values are `risk-listed` and `observed`. Use `null` when the feed has no registration date. A signed manifest can be valid for up to 30 days. Restart the worker when replacing the manifest or pinned key. Missing, expired, or invalid signatures yield unavailable data. An unlisted domain has no known result from the configured feed.
