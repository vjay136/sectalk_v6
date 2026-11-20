import { setTimeout as delay } from 'node:timers/promises'
import { createClient } from '@supabase/supabase-js'
import { after } from 'next/server'

type Operation = 'file_upload' | 'file_publish' | 'file_download_grant' | 'file_download' |
  'call_ice' | 'meeting_token' | 'billing_action' | 'billing_webhook'

type Sample = { operation: Operation; duration_ms: number; status: number; in_flight: number }
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

export async function withOperationalMetrics(operation: Operation, handle: () => Promise<Response>) {
  const url = process.env.NEXT_PUBLIC_SUPABASE_URL
  const key = process.env.SECTALK_METRICS_SERVER_KEY
  if (!url || !key) return handle()
  const started = performance.now()
  const concurrency = Math.min(++inFlight, 10000)
  let status = 500
  try {
    const response = await handle()
    status = response.status
    return response
  } finally {
    inFlight--
    const sample = { operation, status, in_flight: concurrency,
      duration_ms: Math.min(Math.round(performance.now() - started), 60000) }
    after(() => enqueue({ url, key }, sample))
  }
}
