import assert from 'node:assert/strict'
import { readFile } from 'node:fs/promises'
import test from 'node:test'

test('standalone worker serves only its protected job API', async () => {
  const origin = process.env.SECTALK_WORKER_TEST_URL
  const rotationSecret = process.env.CRON_SECRET
  const rewrapSecret = process.env.SECTALK_DEK_REWRAP_SECRET
  assert.ok(origin && ['127.0.0.1', 'localhost'].includes(new URL(origin).hostname), 'Use an isolated local worker and empty job queue')
  assert.ok(rotationSecret && rewrapSecret, 'Configure synthetic job secrets')
  const rotation = '/api/tenant-keys/rotate-due'
  const rewrap = '/api/tenant-keys/rewrap'
  const request = (path, init) => fetch(new URL(path, origin), init)
  const bearer = secret => ({ authorization: `Bearer ${secret}` })

  const health = await request('/api/health')
  assert.equal(health.status, 200)
  assert.equal(health.headers.get('cache-control'), 'no-store')
  assert.deepEqual(await health.json(), { status: 'ok', service: 'sectalk-workers' })
  for (const path of ['/', '/login', '/api/workspace-files', '/api/unknown-job']) {
    assert.equal((await request(path)).status, 404, path)
  }
  assert.equal((await request(rotation, { method: 'HEAD', headers: bearer(rotationSecret) })).status, 404)
  assert.equal((await request(rotation, { method: 'POST', headers: bearer(rotationSecret) })).status, 404)
  assert.equal((await request(rewrap, { headers: bearer(rewrapSecret) })).status, 404)
  assert.equal((await request(rotation)).status, 401)
  assert.equal((await request(rotation, { headers: bearer(rewrapSecret) })).status, 401)
  assert.equal((await request(rewrap, { method: 'POST', headers: bearer(rotationSecret) })).status, 401)
  for (const path of ['/api/exports/purge', '/api/files/purge', '/api/group-files/purge']) {
    assert.equal((await request(path, { method: 'POST' })).status, 401, path)
  }

  const rotated = await request(rotation, { headers: bearer(rotationSecret) })
  assert.equal(rotated.status, 200)
  assert.deepEqual(await rotated.json(), { processed: 0, activated: 0, failed: 0 })
  for (const kind of ['channel', 'room']) {
    const rewrapped = await request(rewrap, {
      method: 'POST',
      headers: { ...bearer(rewrapSecret), 'content-type': 'application/json' },
      body: JSON.stringify({ workspace: '00000000-0000-0000-0000-000000000000', kind }),
    })
    assert.equal(rewrapped.status, 200)
    assert.deepEqual(await rewrapped.json(), { processed: 0, rewrapped: 0, failed: 0 })
  }

  const config = async app => JSON.parse(await readFile(new URL(`../apps/${app}/vercel.json`, import.meta.url), 'utf8'))
  assert.equal((await config('workers')).crons.filter(cron => cron.path === rotation).length, 1)
  assert.ok(!(await config('web')).crons?.some(cron => cron.path === rotation))
})
