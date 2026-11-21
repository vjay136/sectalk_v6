import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import { spawn } from 'node:child_process'
import { createServer } from 'node:http'
import { fileURLToPath } from 'node:url'
import { test } from 'node:test'

const fixtureToken = 'fixture.header.signature'
const secret = 'local-signaling-gateway-test-credential'
const service = fileURLToPath(new URL('../services/livekit-signaling/server.mjs', import.meta.url))

async function listen(server) {
  await new Promise((resolve, reject) => {
    server.once('error', reject)
    server.listen(0, '127.0.0.1', resolve)
  })
  return server.address().port
}
const close = server => new Promise(resolve => server.close(resolve))

test('signaling closes a provider upgrade when admission changes while the connection is being created', async t => {
  let checked = 0
  const {promise: review, resolve: reviewed}=Promise.withResolvers()
  const auth = createServer((request, response) => {
    assert.equal(request.headers.authorization, 'Bearer ' + secret)
    assert.equal(request.url, '/api/internal/livekit-admission')
    request.setEncoding('utf8')
    let token = ''
    request.on('data', chunk => { token += chunk })
    request.on('end', () => {
      if(request.method==='PUT'){
        assert.equal(token,'')
        response.writeHead(204).end()
        reviewed()
        return
      }
      assert.equal(request.method,'POST')
      assert.equal(token, fixtureToken)
      response.writeHead(++checked === 1 ? 204 : 403).end()
    })
  })
  const provider = createServer()
  const disconnected = new Promise(resolve => {
    provider.once('upgrade', (request, socket) => {
      assert.equal(new URL(request.url, 'http://localhost').searchParams.get('access_token'), fixtureToken)
      const accept = createHash('sha1').update(request.headers['sec-websocket-key'] +
        '258EAFA5-E914-47DA-95CA-C5AB0DC85B11').digest('base64')
      socket.on('end', () => { socket.destroy(); resolve() })
      socket.write('HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n' +
        'Sec-WebSocket-Accept: ' + accept + '\r\n\r\n')
    })
  })
  const authPort = await listen(auth)
  const providerPort = await listen(provider)
  const reserved = createServer()
  const gatewayPort = await listen(reserved)
  await close(reserved)
  const worker = spawn(process.execPath, [service], { stdio: 'ignore', env: { ...process.env,
    BIND_HOST: '127.0.0.1', PORT: String(gatewayPort), LIVEKIT_SIGNAL_AUTH_SECRET: secret,
    LIVEKIT_SIGNAL_AUTH_URL: 'http://127.0.0.1:' + authPort + '/api/internal/livekit-admission',
    LIVEKIT_SIGNAL_UPSTREAM: 'http://127.0.0.1:' + providerPort,
  } })
  t.after(() => { worker.kill(); auth.closeAllConnections(); auth.close(); provider.close() })
  const base = 'http://127.0.0.1:' + gatewayPort
  let ready = false
  for (let retry = 0; retry < 25 && !ready; retry++) {
    ready = (await fetch(base + '/twirp/livekit.RoomService/ListRooms').catch(() => null))?.status === 404
    if (!ready) await new Promise(resolve => setTimeout(resolve, 100))
  }
  assert.equal(ready, true)
  const accepted = await new Promise((resolve, reject) => {
    const socket = new WebSocket(base.replace('http:', 'ws:') + '/rtc?access_token=' + fixtureToken)
    const timeout = setTimeout(() => reject(new Error('Gateway did not resolve the upgrade')), 3000)
    socket.addEventListener('error', () => { clearTimeout(timeout); resolve(false) }, { once: true })
    socket.addEventListener('open', () => { clearTimeout(timeout); socket.close(); resolve(true) }, { once: true })
  })
  assert.equal(accepted, false)
  assert.equal(checked, 2)
  await disconnected
  const reviewTimeout=AbortSignal.timeout(3000)
  await Promise.race([review,new Promise((_,reject)=>reviewTimeout.addEventListener('abort',()=>reject(new Error('Gateway did not request participant review')),{once:true}))])
})
