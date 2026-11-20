import { randomBytes } from 'node:crypto'
import { setTimeout as delay } from 'node:timers/promises'

const scope = { name: 'sectalk.server' }
const bounds = [5, 10, 25, 50, 100, 250, 500, 1000, 2500, 5000, 10000]
const resource = { attributes: [attribute('service.name', 'sectalk-web'), attribute('service.instance.id', randomBytes(12).toString('hex'))] }
const maximumBatchSize = 128
let pending: { samples: Observation[]; done: Promise<void> } | null = null
let exportInProgress = false

export type Operation = 'file_upload' | 'file_publish' | 'file_download_grant' | 'file_download' |
  'call_ice' | 'meeting_token' | 'billing_action' | 'billing_webhook' | 'health_read' | 'next_request'

type Observation = { operation: Operation; status: number; start: bigint; duration: number; unexpected?: boolean }
let previousMetricBoundary: bigint | null = null

function attribute(key: string, value: string | number) {
  return { key, value: typeof value === 'number' ? { intValue: String(value) } : { stringValue: value } }
}

function endpoint() {
  const raw = process.env.SECTALK_OTLP_ENDPOINT
  if (!raw) return null
  try {
    const url = new URL(raw)
    if (url.username || url.password || url.search || url.hash) return null
    if (url.protocol !== 'https:' && !(url.protocol === 'http:' && url.hostname === '127.0.0.1')) return null
    url.pathname = url.pathname.replace(/\/+$/, '') + '/'
    return url
  } catch { return null }
}

export function telemetryEnabled() {
  return Boolean(endpoint())
}

function endOf(sample: Observation) {
  return sample.start + BigInt(Math.round(sample.duration * 1_000_000))
}

function signals(samples: Observation[]) {
  const start = previousMetricBoundary ?? samples.reduce((earliest, sample) => sample.start < earliest ? sample.start : earliest, samples[0].start)
  const currentTime = BigInt(Date.now()) * 1_000_000n
  const end = currentTime > start ? currentTime : start + 1n
  previousMetricBoundary = end
  const spans = []
  const logRecords = []
  const groups = new Map<string, { operation: Operation; statusClass: number; values: number[] }>()
  for (const sample of samples) {
    const traceId = randomBytes(16).toString('hex')
    const spanId = randomBytes(8).toString('hex')
    const statusClass = Math.floor(sample.status / 100)
    const errorType = sample.unexpected ? 'unhandled' : 'http_' + statusClass + 'xx'
    const failed = sample.status >= 500
    const attributes = [attribute('sectalk.operation', sample.operation), attribute('http.response.status_code', sample.status)]
    if (failed) attributes.push(attribute('error.type', errorType))
    spans.push({
      traceId, spanId, name: sample.operation, kind: 2,
      startTimeUnixNano: sample.start.toString(), endTimeUnixNano: endOf(sample).toString(),
      attributes, ...(failed ? { status: { code: 2 } } : {}),
    })
    if (failed) logRecords.push({
      traceId, spanId, timeUnixNano: endOf(sample).toString(), severityNumber: 17, severityText: 'ERROR',
      body: { stringValue: 'SecTalk server request error' },
      attributes: [...attributes, attribute('sectalk.error.fingerprint', sample.operation + ':' + errorType)],
    })
    const key = sample.operation + ':' + statusClass
    const group = groups.get(key) ?? { operation: sample.operation, statusClass, values: [] }
    group.values.push(sample.duration)
    groups.set(key, group)
  }
  const dataPoints = [...groups.values()].map(group => {
    const bucketCounts = Array<number>(bounds.length + 1).fill(0)
    for (const duration of group.values) {
      const bucket = bounds.findIndex(bound => duration <= bound)
      bucketCounts[bucket < 0 ? bounds.length : bucket]++
    }
    return {
      attributes: [attribute('sectalk.operation', group.operation), attribute('sectalk.status_class', group.statusClass)],
      startTimeUnixNano: start.toString(), timeUnixNano: end.toString(),
      count: String(group.values.length), sum: group.values.reduce((total, value) => total + value, 0),
      explicitBounds: bounds, bucketCounts: bucketCounts.map(String),
    }
  })
  const metrics = [{ name: 'sectalk.server.request.duration', unit: 'ms', histogram: { aggregationTemporality: 1, dataPoints } }]
  return [
    ['traces', { resourceSpans: [{ resource, scopeSpans: [{ scope, spans }] }] }] as const,
    ['metrics', { resourceMetrics: [{ resource, scopeMetrics: [{ scope, metrics }] }] }] as const,
    ...(logRecords.length ? [['logs', { resourceLogs: [{ resource, scopeLogs: [{ scope, logRecords }] }] }] as const] : []),
  ]
}

async function publish(url: URL, samples: Observation[]) {
  const headers = new Headers({ 'Content-Type': 'application/json' })
  const token = process.env.SECTALK_OTLP_BEARER_TOKEN
  if (token) headers.set('Authorization', 'Bearer ' + token)
  await Promise.allSettled(signals(samples).map(async ([type, body]) => {
    const response = await fetch(new URL('v1/' + type, url), {
      method: 'POST', headers, body: JSON.stringify(body), redirect: 'error', cache: 'no-store',
      signal: AbortSignal.timeout(1800),
    })
    await response.body?.cancel()
  }))
}

export async function recordTelemetry(sample: Observation) {
  const url = endpoint()
  if (!url || exportInProgress) return
  if (!pending) {
    const samples: Observation[] = []
    const done = delay(100).then(async () => {
      pending = null
      exportInProgress = true
      try { await publish(url, samples) } catch { /* Export must never affect the app. */ }
      finally { exportInProgress = false }
    })
    pending = { samples, done }
  }
  if (pending.samples.length < maximumBatchSize) pending.samples.push(sample)
  return pending.done
}
