export type RelayKind = 'udp' | 'tcp' | 'tls'
export type DiagnosticConfiguration = {
  stun: RTCIceServer | null
  relays: Partial<Record<RelayKind, RTCIceServer>>
  bandwidth: boolean
}

export const relayKinds = ['udp', 'tcp', 'tls'] as const
export type DiagnosticStatus = 'not_configured' | 'unconfirmed' | 'allocated' | 'passed'
export type DiagnosticResult = {
  stun: DiagnosticStatus
  relays: Record<RelayKind, DiagnosticStatus>
  bandwidth: { transport: RelayKind; mbps: number } | 'unavailable' | 'not_configured'
}

function bounded<T>(signal: AbortSignal, ms: number, fallback: T, start: (done: (value: T) => void) => void): Promise<T> {
  return new Promise(resolve => {
    if (signal.aborted) return resolve(fallback)
    const timeout = window.setTimeout(stop, ms)
    function done(value: T) {
      window.clearTimeout(timeout)
      signal.removeEventListener('abort', stop)
      resolve(value)
    }
    function stop() { done(fallback) }
    signal.addEventListener('abort', stop, { once: true })
    try { start(done) } catch { stop() }
  })
}

async function checkStun(peer: RTCPeerConnection, signal: AbortSignal): Promise<DiagnosticStatus> {
  return bounded<DiagnosticStatus>(signal, 5000, 'unconfirmed', done => {
    peer.onicecandidate = event => {
      if (event.candidate?.type === 'srflx') done('passed')
      if (!event.candidate) done('unconfirmed')
    }
    peer.createDataChannel('network-check')
    void peer.createOffer().then(offer => peer.setLocalDescription(offer)).catch(() => done('unconfirmed'))
  })
}

type ConnectedRelay = { sending: RTCDataChannel; receiving: RTCDataChannel }

async function checkRelay(origin: RTCPeerConnection, target: RTCPeerConnection, signal: AbortSignal) {
  let allocated = false
  let remoteChannel: RTCDataChannel | undefined
  const sending = origin.createDataChannel('network-check')
  const connected = await bounded<ConnectedRelay | null>(signal, 10_000, null, done => {
    const candidatesForOrigin: RTCIceCandidate[] = []
    const candidatesForTarget: RTCIceCandidate[] = []

    function forward(candidate: RTCIceCandidate | null, remote: RTCPeerConnection, pending: RTCIceCandidate[]) {
      if (!candidate || signal.aborted) return
      allocated ||= candidate.type === 'relay'
      if (!remote.remoteDescription) pending.push(candidate)
      else void remote.addIceCandidate(candidate).catch(() => {})
    }
    origin.onicecandidate = event => forward(event.candidate, target, candidatesForTarget)
    target.onicecandidate = event => forward(event.candidate, origin, candidatesForOrigin)
    target.ondatachannel = event => {
      remoteChannel = event.channel
      event.channel.onmessage = message => {
        if (message.data === 'probe') event.channel.send('ack')
      }
    }
    sending.onopen = () => sending.send('probe')
    sending.onmessage = event => {
      if (event.data === 'ack' && remoteChannel) done({ sending, receiving: remoteChannel })
    }
    sending.onerror = () => done(null)

    async function negotiate() {
      const offer = await origin.createOffer()
      await origin.setLocalDescription(offer)
      await target.setRemoteDescription(offer)
      await Promise.allSettled(candidatesForTarget.splice(0).map(candidate => target.addIceCandidate(candidate)))
      const answer = await target.createAnswer()
      await target.setLocalDescription(answer)
      await origin.setRemoteDescription(answer)
      await Promise.allSettled(candidatesForOrigin.splice(0).map(candidate => origin.addIceCandidate(candidate)))
    }
    void negotiate().catch(() => done(null))
  })
  return { status: connected ? 'passed' : allocated ? 'allocated' : 'unconfirmed', connected } as const
}

const testBytes = 256 * 1024
const chunkBytes = 16 * 1024

async function measureBandwidth(channels: ConnectedRelay, signal: AbortSignal) {
  const { sending, receiving } = channels
  receiving.binaryType = 'arraybuffer'
  return bounded<number | null>(signal, 5000, null, done => {
    let delivered = 0
    receiving.onmessage = event => {
      if (!(event.data instanceof ArrayBuffer)) return
      delivered += event.data.byteLength
      if (delivered === testBytes) receiving.send('bandwidth-ack')
    }
    const chunk = new Uint8Array(chunkBytes)
    const started = performance.now()
    sending.onmessage = event => {
      if (event.data === 'bandwidth-ack') {
        const duration = performance.now() - started
        if (duration > 0) done(Math.round((testBytes * 8 / duration / 1000) * 10) / 10)
      }
    }
    for (let sent = 0; sent < testBytes; sent += chunk.length) sending.send(chunk)
  })
}

export async function runNetworkDiagnostics(config: DiagnosticConfiguration, signal: AbortSignal): Promise<DiagnosticResult> {
  const connections = new Set<RTCPeerConnection>()
  function peer(iceServer: RTCIceServer, relay = false) {
    const connection = new RTCPeerConnection({ iceServers: [iceServer], iceTransportPolicy: relay ? 'relay' : 'all' })
    connections.add(connection)
    return connection
  }

  try {
    const checks = relayKinds.map(async kind => {
      const server = config.relays[kind]
      if (!server) return { kind, status: 'not_configured', connected: null } as const
      try {
        return { kind, ...await checkRelay(peer(server, true), peer(server, true), signal) }
      } catch {
        return { kind, status: 'unconfirmed', connected: null } as const
      }
    })
    const [stun, relays] = await Promise.all([
      config.stun ? checkStun(peer(config.stun), signal) : Promise.resolve('not_configured' as const),
      Promise.all(checks),
    ])
    const result: DiagnosticResult = {
      stun, relays: { udp: 'not_configured', tcp: 'not_configured', tls: 'not_configured' },
      bandwidth: config.bandwidth ? 'unavailable' : 'not_configured',
    }
    for (const { kind, status } of relays) result.relays[kind] = status
    const relay = relays.find(value => value.connected)
    if (config.bandwidth && relay?.connected && !signal.aborted) {
      const mbps = await measureBandwidth(relay.connected, signal)
      if (mbps !== null) result.bandwidth = { transport: relay.kind, mbps }
    }
    return result
  } finally {
    for (const connection of connections) connection.close()
  }
}
