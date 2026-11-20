import type { Instrumentation } from 'next'

export const onRequestError: Instrumentation.onRequestError = async () => {
  if (process.env.NEXT_RUNTIME !== 'nodejs') return
  const { recordTelemetry } = await import('./lib/telemetry-server')
  await recordTelemetry({ operation: 'next_request', status: 500, start: BigInt(Date.now()) * 1_000_000n, duration: 0, unexpected: true })
}
