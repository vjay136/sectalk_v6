# Meeting media token revocation

**Open for self-hosted LiveKit.**

SecTalk disconnects a removed participant through LiveKit and deletes the media room when a moderator ends the meeting. The application denies fresh media tokens after either action. The disposable browser tests verified client disconnection and denial of fresh tokens.

Self-hosted LiveKit can still accept a valid token issued before removal or before a moderator revoked media permissions. SecTalk initially issues a two-minute join token. LiveKit can refresh tokens during a connected session with a longer expiry, including when permissions change. Provider-side rejection of every previously issued credential remains open. LiveKit Cloud has a separate revocation mechanism that requires provider-specific verification. [LiveKit token lifecycle and revocation](https://docs.livekit.io/frontends/reference/tokens-grants/#token-lifecycle)
