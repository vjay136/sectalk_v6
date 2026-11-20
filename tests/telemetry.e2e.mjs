import assert from 'node:assert/strict'
import { execFileSync, spawnSync } from 'node:child_process'
import { randomUUID } from 'node:crypto'
import { setTimeout } from 'node:timers/promises'

const app = new URL(process.env.SECTALK_TELEMETRY_TEST_APP)
assert.equal(app.hostname, '127.0.0.1')
assert.equal(process.env.SECTALK_TELEMETRY_TEST_COLLECTOR, 'sectalk-otel-qa')
const container = process.env.SECTALK_TELEMETRY_TEST_COLLECTOR
const canary = 'private-telemetry-canary-' + randomUUID()
const all = []
for (const [path, method, status] of [
  ['/api/health', 'GET', 200],
  ['/api/ice', 'GET', 400],
  ['/api/meetings/token', 'POST', 503],
]) {
  all.push(fetch(new URL(path + '?user=' + canary, app), { method,
    headers: { Authorization: 'Bearer ' + canary, 'X-Canary': canary, 'Content-Type': 'application/json' },
    ...(method === 'POST' ? { body: JSON.stringify({ secret: canary }) } : {}),
  }).then(response => assert.equal(response.status, status, path)))
}
await Promise.all(all)

let output = ''
for (let attempt = 0; attempt < 30; attempt++) {
  const logs = spawnSync('docker', ['logs', container], { encoding: 'utf8' })
  assert.equal(logs.status, 0, logs.stderr)
  output = logs.stdout + logs.stderr
  if (output.includes('sectalk.server.request.duration') && output.includes('meeting_token:http_5xx')) break
  await setTimeout(250)
}
assert.match(output, /Name\s*:\s*health_read/, 'Collector did not decode the health trace')
assert.match(output, /Name\s*:\s*call_ice/, 'Collector did not decode the denied call trace')
assert.match(output, /Name\s*:\s*meeting_token/, 'Collector did not decode the unavailable meeting trace')
assert.ok(output.includes('sectalk.server.request.duration'), 'Collector did not decode the request histogram')
assert.ok(output.includes('meeting_token:http_5xx'), 'Collector did not decode the grouped error')
assert.ok(!output.includes(canary), 'An unapproved input appeared in the exported signals')
const meeting = output.split(/Span #[0-9]+/).find(block => /Name\s*:\s*meeting_token/.test(block))
const trace = meeting?.match(/Trace ID\s*:\s*([a-f0-9]{32})/i)?.[1]
assert.ok(trace, 'Missing meeting trace identifier')
assert.ok((output.match(new RegExp('Trace ID[\\s:]+' + trace, 'gi')) ?? []).length >= 2,
  'Error log and request span should share a correlation identifier')

execFileSync('docker', ['pause', container], { stdio: 'ignore' })
try {
  const response = await fetch(new URL('/api/health', app), { signal: AbortSignal.timeout(8000) })
  assert.equal(response.status, 200)
} finally {
  execFileSync('docker', ['unpause', container], { stdio: 'ignore' })
}
console.log('Passed OTLP trace, metric and error decoding, redaction canary and collector disruption.')
