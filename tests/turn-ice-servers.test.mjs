import assert from 'node:assert/strict'
import { createHmac } from 'node:crypto'
import test from 'node:test'
import { callIceServers } from '../apps/web/lib/turn-ice-servers.ts'

const scope = 'group-call:fixture'
const turnix = { TURNIX_API_TOKEN: 'mock-provider-token' }
const coturn = { TURN_URLS: 'turn:turn.example.invalid:3478', TURN_SHARED_SECRET: 'coturn-fixture-token' }
const turn = 'turn:us-west.turnix.io:3478?transport=udp'
const turns = 'turns:us-west.turnix.io:443?transport=tcp'

test('ICE supports STUN-only operation and preserves the bounded per-call Coturn signature', async () => {
  const expires = Date.now() + 25000
  assert.deepEqual(await callIceServers(expires, scope, {}), {
    iceServers: [{ urls: 'stun:stun.l.google.com:19302' }], iceTransportPolicy: 'all', ttlSeconds: null,
  })
  const result = await callIceServers(expires, scope, coturn)
  const relay = result.iceServers[1]
  assert.equal(result.iceTransportPolicy, 'relay')
  assert.ok(result.ttlSeconds >= 24 && result.ttlSeconds <= 25)
  const [expiry, principal] = relay.username.split(':')
  assert.equal(Number(expiry), Math.floor(expires / 1000))
  assert.equal(principal, createHmac('sha256', coturn.TURN_SHARED_SECRET).update(scope).digest('hex').slice(0, 32))
  assert.equal(relay.credential, createHmac('sha1', coturn.TURN_SHARED_SECRET).update(relay.username).digest('base64'))
})

test('Turnix receives a bounded lease request and only vetted relay credentials reach the client', async () => {
  let requestedTtl
  const result = await callIceServers(Date.now() + 25000, scope, turnix, async (url, options) => {
    assert.equal(url, 'https://turnix.io/api/v1/credentials/ice')
    assert.equal(options.method, 'POST')
    assert.equal(options.redirect, 'error')
    assert.equal(options.cache, 'no-store')
    assert.ok(options.signal instanceof AbortSignal)
    assert.deepEqual(options.headers, {
      Authorization: 'Bearer ' + turnix.TURNIX_API_TOKEN, 'Content-Type': 'application/json',
    })
    requestedTtl = JSON.parse(options.body).ttl
    assert.ok(requestedTtl >= 20 && requestedTtl <= 22)
    assert.deepEqual(JSON.parse(options.body), { ttl: requestedTtl })
    return Response.json({ iceServers: [
      { urls: ['stun:stun.turnix.io:3478'] },
      { urls: [turn, turns, turn, 'turn:us-west.turnix.io:53', 'turn:us-west.turnix.io.attacker.invalid:3478',
        'turns:us-west.turnix.io:443?transport=udp', 'turn:us-west.turnix.io:99999', 'turn:127.0.0.1:3478'],
      username: 'ephemeral-participant', credential: 'ephemeral-secret', extra: turnix.TURNIX_API_TOKEN },
      { urls: [turn], username: 'ignored', credential: turnix.TURNIX_API_TOKEN },
    ], expiresAt: new Date(Date.now() + requestedTtl * 1000).toISOString() })
  })
  assert.equal(result.iceTransportPolicy, 'relay')
  assert.ok(result.ttlSeconds > 0 && result.ttlSeconds <= requestedTtl)
  assert.deepEqual(result.iceServers[1], {
    urls: [turn, turns], username: 'ephemeral-participant', credential: 'ephemeral-secret',
  })
  assert.equal(result.iceServers.length, 2)
  assert.equal(JSON.stringify(result).includes(turnix.TURNIX_API_TOKEN), false)
})

test('ICE fails closed for ambiguous provider configuration and malformed or unavailable relay responses', async () => {
  const expires = Date.now() + 900000
  const forbiddenRequest = () => assert.fail('Invalid configuration must not contact the provider')
  await assert.rejects(callIceServers(expires, scope, { ...turnix, ...coturn }, forbiddenRequest), /one TURN provider/)
  await assert.rejects(callIceServers(expires, scope, { TURNIX_API_TOKEN: 'bad\rtoken' }, forbiddenRequest), /Turnix configuration/)
  await assert.rejects(callIceServers(expires, scope, { ...coturn, TURN_URLS: 'turn:other.invalid/path' }, forbiddenRequest), /Coturn configuration/)
  await assert.rejects(callIceServers(Date.now() - 1000, scope, turnix, forbiddenRequest), /Invalid call ICE configuration/)
  await assert.rejects(callIceServers(expires, scope, turnix, (url, options) => {
    assert.equal(JSON.parse(options.body).ttl, 297)
    return new Response(null, { status: 429 })
  }), /TURN provider unavailable/)
  await assert.rejects(callIceServers(expires, scope, turnix, () =>
    Response.json({ iceServers: [{ urls: 'turn:invalid.test:3478', username: 'participant', credential: 'password' }],
      expiresAt: new Date(Date.now() + 60000).toISOString() })),
  /no usable relays/)
  await assert.rejects(callIceServers(expires, scope, turnix, () =>
    Response.json({ iceServers: [{ urls: turn, username: 'participant', credential: 'password' }],
      expiresAt: new Date(Date.now() + 900000).toISOString() })),
  /Invalid TURN provider expiry/)
})
