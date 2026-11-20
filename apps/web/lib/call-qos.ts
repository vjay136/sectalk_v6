import { db } from './data'

type Sample =
  | { metric: 'join'; bucket: 'started' | 'connected' }
  | { metric: 'setup'; bucket: 'fast' | 'moderate' | 'slow' | 'failed' }
  | { metric: 'relay'; bucket: 'relayed' | 'non_relayed' }
  | { metric: 'ice_restart'; bucket: 'not_requested' | 'requested' }
  | { metric: 'recovery'; bucket: 'recovered' | 'failed' }
  | { metric: 'mos'; bucket: 'below_2' | '2_to_3' | '3_to_4' | '4_or_more' }

type IceRoute = Extract<Sample, { metric: 'relay' }>['bucket']

function selectedIceRoute(stats: RTCStatsReport): IceRoute | undefined {
  const selected = new Set<string>()
  const nominated: string[] = []
  stats.forEach(item => {
    if (item.type === 'transport' && item.selectedCandidatePairId) selected.add(item.selectedCandidatePairId)
    if (item.type === 'candidate-pair' && item.state === 'succeeded' && (item.selected || item.nominated)) nominated.push(item.id)
  })
  if (!selected.size && nominated.length === 1) selected.add(nominated[0])
  if (!selected.size) return

  let allNonRelayed = true
  const nonRelayed = ['host', 'srflx', 'prflx']
  for (const id of selected) {
    const pair = stats.get(id)
    const local = stats.get(pair?.localCandidateId)?.candidateType
    const remote = stats.get(pair?.remoteCandidateId)?.candidateType
    if (local === 'relay' || remote === 'relay') return 'relayed'
    if (!nonRelayed.includes(local) || !nonRelayed.includes(remote)) allNonRelayed = false
  }
  return allNonRelayed ? 'non_relayed' : undefined
}

function audioMos(stats: RTCStatsReport) {
  let score: number | undefined
  let packets = 0
  stats.forEach(item => {
    if (item.type !== 'inbound-rtp' || item.kind !== 'audio' || item.packetsReceived < 20 || item.packetsReceived <= packets) return
    const transport = stats.get(item.transportId)
    const pair = transport?.selectedCandidatePairId && stats.get(transport.selectedCandidatePairId)
    const rtt = pair?.currentRoundTripTime
    if (!Number.isFinite(rtt) || rtt < 0 || !Number.isFinite(item.jitter) || item.jitter < 0 ||
        !Number.isFinite(item.packetsLost) || !Number.isFinite(item.packetsReceived)) return
    const lost = Math.max(0, item.packetsLost)
    const loss = 100 * lost / (item.packetsReceived + lost)
    const delay = 500 * rtt + 2000 * item.jitter + 10
    const r = Math.max(0, Math.min(100, 93.2 - 0.024 * delay - 0.11 * Math.max(0, delay - 177.3) - 2.5 * loss))
    score = Math.max(1, Math.min(4.5, 1 + 0.035 * r + 0.000007 * r * (r - 60) * (100 - r)))
    packets = item.packetsReceived
  })
  return score
}

export function createCallQos(mode: 'direct' | 'meeting', resource: string, device: string | null = null, observesIceRestart = false) {
  const start = performance.now()
  const reported = new Set<string>()
  let connected = false
  let recovering = false

  function report(sample: Sample) {
    const key = sample.metric === 'join' || sample.metric === 'ice_restart' ? sample.metric + ':' + sample.bucket : sample.metric
    if (!db || reported.has(key)) return
    reported.add(key)
    void db.rpc('st_v6_report_call_qos', {
      p_mode: mode, p_resource: resource, p_device: device,
      p_metric: sample.metric, p_bucket: sample.bucket,
    }).then(() => {}, () => {})
  }

  return {
    started() { report({ metric: 'join', bucket: 'started' }) },
    connected() {
      if (!connected) {
        connected = true
        report({ metric: 'join', bucket: 'connected' })
        if (observesIceRestart) report({ metric: 'ice_restart', bucket: 'not_requested' })
        const elapsed = performance.now() - start
        report({ metric: 'setup', bucket: elapsed < 2000 ? 'fast' : elapsed < 5000 ? 'moderate' : 'slow' })
      } else if (recovering) {
        recovering = false
        report({ metric: 'recovery', bucket: 'recovered' })
      }
    },
    iceRestart() {
      if (connected && observesIceRestart) report({ metric: 'ice_restart', bucket: 'requested' })
    },
    reconnecting() {
      if (connected) recovering = true
    },
    failed() {
      if (!connected) report({ metric: 'setup', bucket: 'failed' })
      else if (recovering) report({ metric: 'recovery', bucket: 'failed' })
    },
    route(...reports: (RTCStatsReport | undefined)[]) {
      if (reported.has('relay')) return true
      const routes = reports.flatMap(stats => stats ? [selectedIceRoute(stats)] : [])
      const route = routes.includes('relayed') ? 'relayed' : routes.find(value => value === 'non_relayed')
      if (route) report({ metric: 'relay', bucket: route })
      return route !== undefined
    },
    mos(...reports: (RTCStatsReport | undefined)[]) {
      if (reported.has('mos')) return true
      const score = reports.flatMap(stats => stats ? [audioMos(stats)] : []).find(value => value !== undefined)
      if (score === undefined) return false
      report({ metric: 'mos', bucket: score < 2 ? 'below_2' : score < 3 ? '2_to_3' : score < 4 ? '3_to_4' : '4_or_more' })
      return true
    },
  }
}
