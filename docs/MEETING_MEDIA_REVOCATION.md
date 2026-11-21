# Self-hosted LiveKit signaling admission

SecTalk disconnects an active participant when a moderator removes them, and deletes the provider room when a moderator ends the meeting. The application refuses to mint new credentials after removal or ending.

LiveKit Cloud and an unmodified self-hosted LiveKit deployment differ in how they handle old credentials. For stock self-hosted LiveKit, a previously issued or refreshed credential may remain valid at the provider. [LiveKit token lifecycle and revocation](https://docs.livekit.io/frontends/reference/tokens-grants/#token-lifecycle)

## Deploy the SecTalk gateway

Build `services/livekit-signaling` and run it behind the public TLS terminator. It handles only the two pinned LiveKit v1.13.11 signaling paths and their validation requests. Keep the underlying LiveKit signaling listener private. Publish its configured ICE or TURN ports separately. [LiveKit port requirements](https://docs.livekit.io/transport/self-hosting/ports-firewall/)

| Process | Configuration |
| --- | --- |
| SecTalk web | Set `LIVEKIT_URL` to the public gateway WSS origin, `LIVEKIT_INTERNAL_URL` to the private LiveKit control API origin, and the existing LiveKit signing key and secret. Set server-only `LIVEKIT_SIGNAL_AUTH_SECRET` to a random secret of at least 32 characters. Set `LIVEKIT_SIGNAL_SERVICE_KEY` to this project's server-only Supabase service credential. |
| Gateway | Set `LIVEKIT_SIGNAL_UPSTREAM` to the private LiveKit HTTP origin, `LIVEKIT_SIGNAL_AUTH_URL` to the app's exact `/api/internal/livekit-admission` endpoint, and the same `LIVEKIT_SIGNAL_AUTH_SECRET` as the app. The app and gateway communicate over a private network or TLS. |
| LiveKit and media workers | Run the pinned provider on a private signaling/control network. Keep captions and Egress workers on trusted internal connections. Egress storage and webhook configuration work through the existing worker endpoints. |

Expose only the gateway through the public media hostname. Firewall the provider's signaling and RoomService TCP port from untrusted clients, including alternate hostnames or load balancer addresses. Do not publish LiveKit's signaling port directly in Docker. Exclude signaling query strings and admission bodies from reverse-proxy access logs. They contain provider credentials.

The gateway verifies the provider-issued JWT against current SecTalk state before forwarding a new signaling connection and checks again before releasing the WebSocket upgrade. It denies new signaling after a member is removed, a meeting ends, or a guest approval or link expires or is revoked. Protected meetings and group SFU calls retain their roster and generation checks. Dedicated network checks continue to use hidden, non-publishing grants. Provider control and recording workers connect privately. A failed admission check stops the join.

New managed and protected meeting grants for signed-in members carry a random binding in a read-only participant attribute. The binding refers to the exact native Auth session, member and meeting. On each signaling admission, SecTalk rechecks that session and the current workspace media SSO policy. Disabling the bound identity provider or revoking the native session denies new signaling with that grant. Pre-update member grants without a binding are denied while the workspace requires media SSO. Managed guest links still use their separate approval checks. The binding is an opaque identifier for the admission record. [Attribute handling in the pinned LiveKit refresh implementation](https://github.com/livekit/livekit/blob/v1.13.11/pkg/service/roommanager.go#L1085-L1112)

The gateway requests a review of connected managed and protected meeting members shortly after startup and 20 seconds after each review finishes. The app checks each bound participant against the current native admission rules and uses the private RoomService API to disconnect a revoked participant. Each session has a distinct provider identity, so a disconnect targets the session that failed the check. Guest links and group calls keep their own admission and moderation paths. A failed dependency reports a review failure and the gateway retries on its next cycle. Verify closed ingress, approved joins, denial of old credentials, and the active-disconnection interval on the deployment before enabling it.

The disposable v1.13.11 fixture uses loopback-only control and media ports. Its Edge tests cover native moderation and guest credential rejection after removal or revocation, encrypted protected audio and video, and group audio and video handoff between mesh and SFU, including rollback. The rollback SQL covers current admission and namespace boundaries. The gateway test also checks revocation between the initial request and delivery of the provider's WebSocket upgrade. Recording control retains the private native endpoint. A recording capture was not part of the gateway acceptance run.
