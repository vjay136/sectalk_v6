import assert from 'node:assert/strict'
import { createServer, request } from 'node:http'
import { generateKeyPairSync, sign } from 'node:crypto'
import { startUrlInspectionWorker } from '../scripts/url-inspection-worker.mjs'
import { verifiedUrlReputation } from '../apps/web/lib/url-reputation-feed.mjs'

assert.ok(process.permission && !process.permission.has('child') && !process.permission.has('fs.write'))
const token = process.env.SECTALK_URL_INSPECTION_WORKER_TOKEN
assert.match(token, /^[A-Za-z0-9_-]{24,128}$/)
const first = 'approved-a.example.invalid'
const final = 'approved-b.example.invalid'
const allowed = new Set([first, final])
const hits = []
const destination = createServer((incoming, outgoing) => {
  const send = (code, headers = {}, body = '') => { outgoing.writeHead(code, headers); outgoing.end(body) }
  if (incoming.url === '/hits' && incoming.headers.authorization === 'Bearer ' + token) {
    send(200, { 'Content-Type': 'application/json' }, JSON.stringify(hits)); return
  }
  hits.push({ url: incoming.url, method: incoming.method, host: incoming.headers.host,
    credentials: Boolean(incoming.headers.authorization || incoming.headers.cookie || incoming.headers.referer) })
  if (incoming.headers.host === first && incoming.url === '/start') {
    send(302, { Location: 'https://' + final + '/landing?skipped=fixture-token#skipped' }); return
  }
  if (incoming.headers.host === first && incoming.url === '/outside') {
    send(307, { Location: 'https://unapproved.example.invalid/ignored' }); return
  }
  if (incoming.headers.host === final && incoming.url === '/landing') { send(204); return }
  send(404)
})
await new Promise((resolve, reject) => destination.listen(3530, '127.0.0.1', resolve).once('error', reject))

const now = Date.now()
const { publicKey, privateKey } = generateKeyPairSync('ed25519')
const payload = JSON.stringify({ source: 'Verified synthetic feed', issued: new Date(now - 60000).toISOString(),
  expires: new Date(now + 86400000).toISOString(),
  domains: [{ domain: final, reputation: 'risk-listed', registered: new Date(now - 86400000).toISOString().slice(0,10) }],
})
const signature = sign(null, Buffer.from(payload), privateKey).toString('base64url')
const feed = verifiedUrlReputation(JSON.stringify({ payload, signature }), publicKey.export({ format: 'pem', type: 'spki' }), now)
assert.ok(feed)
const transport = {
  resolve: async host => allowed.has(host) ? 'fixture' : null,
  head: (url, address, signal) => new Promise((resolve, reject) => {
    assert.equal(address, 'fixture')
    const outgoing = request({ hostname:'127.0.0.1',port:3530,path:url.pathname,method:'HEAD',agent:false,
      headers:{Host:url.hostname},signal }, response => {
        const result = { status:response.statusCode,location:response.headers.location }
        response.destroy()
        resolve(result)
      })
    outgoing.on('error',reject)
    outgoing.end()
  }),
}
startUrlInspectionWorker({ token, port:3531, allowed, feed, transport })
