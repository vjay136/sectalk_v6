# Protected call and meeting media

Compare the verification code with every participant through a separate trusted channel before confirming it. The code binds the ephemeral keys to the call or meeting and its participants. Authentication limits access to the enrolled browser endpoint. Comparing the code also checks the public keys returned through signaling.

Protected direct calls use P-256 ECDH and HKDF to derive a separate AES-256-GCM key for each direction. The browser attaches native `RTCRtpScriptTransform` to Opus audio and VP8 camera streams. SecTalk's versioned frame format authenticates the codec header and encrypts the frame body. Screen sharing is unavailable in this mode.

Protected meetings lock the two to eight currently admitted accounts into one roster. The host browser generates an ephemeral media key and sends an AES-GCM-encrypted copy to each member using a pairwise ECDH key. Each browser receives only its own encrypted copy. Changing admission closes the protected media session. Use a new meeting for a different roster.

LiveKit receives the media token, encrypted frames, and normal signaling metadata. The browser-side LiveKit SDK handles media encryption with its AES-GCM encoded-frame format. Local Edge testing used its native browser `createEncodedStreams` path. This framing has no verified RFC 9605 SFrame interoperability, and the tested Edge version did not expose native SFrame transforms. [LiveKit encryption](https://docs.livekit.io/transport/encryption/) · [WebRTC Encoded Transform](https://www.w3.org/TR/webrtc-encoded-transform/)

Protected meeting media uses a separate LiveKit room. Use managed mode for server-side recording, captions, chat, screen sharing, or guests. Protected setup requires the server-side `PROTECTED_MEETING_SERVICE_KEY` alongside the existing LiveKit configuration. The key agreement and all verification codes remain in the browsers.
