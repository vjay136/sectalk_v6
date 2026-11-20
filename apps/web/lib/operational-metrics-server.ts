import { setTimeout as delay } from 'node:timers/promises'
import { createClient } from '@supabase/supabase-js'
import { after } from 'next/server'
import { recordTelemetry, telemetryEnabled, type Operation } from './telemetry-server'

type DatabaseOperation = Exclude<Operation, 'health_read' | 'next_request'>
type Sample = { operation: DatabaseOperation; duration_ms: number; status: number; in_flight: number }
type Credentials = { url: string; key: string }

const maximumBatchSize = 128
let inFlight = 0
let pendingBatch: { samples: Sample[]; done: Promise<void> } | null = null

async function writeBatch({ url, key }: Credentials, samples: Sample[]) {
  try {
    const client = createClient(url, key, { auth: { persistSession: false, autoRefreshToken: false } })
    await client.rpc('st_v6_record_operational_metrics', { p_samples: samples }).abortSignal(AbortSignal.timeout(2000))
  } catch {
    // Recording is best-effort. Never log request details or fail a user operation.
  }
}

function enqueue(credentials: Credentials, sample: Sample) {
  if (!pendingBatch) {
    const samples: Sample[] = []
    const done = delay(100).then(() => {
      pendingBatch = null
      return writeBatch(credentials, samples)
    })
    pendingBatch = { samples, done }
  }
  if (pendingBatch.samples.length < maximumBatchSize) pendingBatch.samples.push(sample)
  return pendingBatch.done
}

export async function withOperationalMetrics(operation: Exclude<Operation, 'next_request'>, handle: () => Promise<Response>) {
  const url = process.env.NEXT_PUBLIC_SUPABASE_URL
  const key = process.env.SECTALK_METRICS_SERVER_KEY
  const observe = telemetryEnabled()
  if (!observe && (!url || !key || operation === 'health_read')) return handle()
  const start = observe ? BigInt(Date.now()) * 1_000_000n : 0n
  const started = performance.now()
  const concurrency = Math.min(++inFlight, 10000)
  let status = 500
  let unexpected = true
  try {
    const response = await handle()
    status = response.status
    unexpected = false
    return response
  } finally {
    inFlight--
    const duration = Math.min(performance.now() - started, 60000)
    if (url && key && operation !== 'health_read') {
      after(() => enqueue({ url, key }, { operation, status, in_flight: concurrency, duration_ms: Math.round(duration) }))
    }
    if (observe && !unexpected) after(() => recordTelemetry({ operation, status, start, duration }))
  }
}
