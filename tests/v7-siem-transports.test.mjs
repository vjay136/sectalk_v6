import assert from 'node:assert/strict'
import {execFileSync} from 'node:child_process'
import {createHash, createHmac, generateKeyPairSync, verify} from 'node:crypto'
import {existsSync, mkdtempSync, readFileSync, rmSync, rmdirSync} from 'node:fs'
import {createServer} from 'node:http'
import {tmpdir} from 'node:os'
import {join} from 'node:path'
import {createServer as createTls} from 'node:tls'
import ts from 'typescript'

const opened = []
async function listen(server) {
  opened.push(server)
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve))
  return server.address().port
}

const hmac = (key, value) => createHmac('sha256', key).update(value).digest()
const hash = value => createHash('sha256').update(value).digest('hex')
const emailSafe = 'A'.repeat(40)
const webhookKey = Buffer.alloc(32, 91)
const workspace = 'aa231300-0000-4000-8000-000000000041'
const batch = {id: 'aa231300-0000-4000-8000-000000000044', workspace, period: '2026-11-20T10:00:00Z',
  counts: {member_suspended: 1, data_loss_policy_updated: 2}}

const certificates = mkdtempSync(join(tmpdir(), 'sectalk-siem-'))
const keyFile = join(certificates, 'key.pem')
const certificateFile = join(certificates, 'cert.pem')
try {
  const {privateKey, publicKey} = generateKeyPairSync('ed25519')
  const gitOpenSsl = process.platform==='win32'&&process.env.ProgramFiles
    ? join(process.env.ProgramFiles, 'Git', 'usr', 'bin', 'openssl.exe') : ''
  const openssl = process.env.SECTALK_TEST_OPENSSL || (gitOpenSsl && existsSync(gitOpenSsl) ? gitOpenSsl : 'openssl')
  execFileSync(openssl, ['req', '-x509', '-newkey', 'rsa:2048', '-nodes',
    '-keyout', keyFile, '-out', certificateFile, '-days', '1', '-subj', '/CN=localhost',
    '-addext', 'subjectAltName=DNS:localhost'], {stdio: 'ignore'})
  const certificate = readFileSync(certificateFile, 'utf8')
  const collectors = []
  let webhookStatus = 429
  let s3Stored
  async function capture(request, response) {
    let body = ''
    for await (const chunk of request) body += chunk
    try {
      if (request.url === '/siem') {
        assert.equal(request.headers['webhook-id'], batch.id)
        const mac = hmac(webhookKey, batch.id + '.' + request.headers['webhook-timestamp'] + '.' + body).toString('base64')
        assert.equal(request.headers['webhook-signature'], 'v1,' + mac)
        collectors.push(body)
        response.writeHead(webhookStatus).end()
        return
      }
      assert.equal(request.url, '/sectalk-siem/' + workspace + '/' + batch.id + '.json')
      const authorization = request.headers.authorization
      const [, scope, headerList, signature] = /^AWS4-HMAC-SHA256 Credential=[A-Z]+\/([^,]+), SignedHeaders=([^,]+), Signature=([a-f\d]+)$/.exec(authorization)
      const [day, region] = scope.split('/')
      const key = hmac(hmac(hmac(hmac('AWS4' + emailSafe, day), region), 's3'), 'aws4_request')
      assert.equal(request.headers['x-amz-content-sha256'], hash(body))
      const headerBlock = headerList.split(';').map(name => name + ':' + request.headers[name] + '\n').join('')
      const canonical = [request.method, request.url, '', headerBlock, headerList, hash(body)].join('\n')
      assert.equal(signature, hmac(key, ['AWS4-HMAC-SHA256', request.headers['x-amz-date'], scope, hash(canonical)].join('\n')).toString('hex'))
      if (request.method === 'HEAD') {
        response.writeHead(200, {'x-amz-meta-sha256': s3Stored}).end()
        return
      }
      assert.equal(request.headers['if-none-match'], '*')
      if (s3Stored) { response.writeHead(412).end(); return }
      assert.equal(request.headers['x-amz-meta-sha256'], hash(body))
      s3Stored = hash(body)
      collectors.push(body)
      response.writeHead(200).end()
    } catch (error) {
      response.writeHead(500).end()
      collectors.push(error)
    }
  }
  const port = await listen(createServer((request, response) => void capture(request, response)))
  let syslogFrame
  const receivedFrame = new Promise(resolve => { syslogFrame = resolve })
  const tlsPort = await listen(createTls({key: readFileSync(keyFile), cert: certificate}, socket => {
    let frame = ''
    socket.on('data', chunk => frame += chunk)
    socket.on('end', () => syslogFrame(frame))
  }))
  const origin = 'http://127.0.0.1:' + port
  process.env.SECTALK_APP_URL = origin
  process.env.SECTALK_TEST_WEBHOOK_ORIGIN = origin
  process.env.SECTALK_SIEM_TEST_S3_ORIGIN = origin
  process.env.SECTALK_SIEM_TEST_SYSLOG_PORT = String(tlsPort)
  process.env.SECTALK_SIEM_TEST_SYSLOG_CA = certificate
  process.env.SECTALK_SIEM_SIGNING_KEY = privateKey.export({type:'pkcs8',format:'der'}).toString('base64url')
  process.env.SECTALK_SIEM_CONNECTORS = JSON.stringify([
    {workspace, channel:'webhook', url: origin + '/siem', secret: webhookKey.toString('base64url')},
    {workspace, channel:'syslog', host:'localhost'},
    {workspace, channel:'s3', bucket:'local-siem-fixture', region:'us-east-1', accessKeyId:'FIXTUREKEYFORLOCAL', secretAccessKey:emailSafe},
  ])

  const compile = file => ts.transpileModule(readFileSync(new URL('../apps/web/lib/' + file + '.ts', import.meta.url), 'utf8'),
    {compilerOptions:{module:ts.ModuleKind.ESNext, target:ts.ScriptTarget.ES2022}}).outputText
  const dataUri = source => 'data:text/javascript;base64,' + Buffer.from(source).toString('base64')
  const module = await import(dataUri(compile('siem-export-server').replace('./webhook-transport', dataUri(compile('webhook-transport')))))
  const [webhook, syslog, s3] = module.siemConnectors()
  const body = module.siemEnvelope(batch)
  assert.equal(body, module.siemEnvelope(batch))
  const envelope = JSON.parse(body)
  assert.equal(envelope.key_id, hash(publicKey.export({type:'spki',format:'der'})))
  assert.equal(envelope.sha256, hash(envelope.payload))
  assert(verify(null, Buffer.from(envelope.payload), publicKey, Buffer.from(envelope.signature, 'base64url')))
  assert(!verify(null, Buffer.from(envelope.payload + ' '), publicKey, Buffer.from(envelope.signature, 'base64url')))
  assert.throws(() => module.siemEnvelope({...batch, counts:{private_message:1}}))
  assert.equal(await module.deliverSiem(webhook, {...batch,workspace:batch.id}, body), 'failed')
  assert.equal(await module.deliverSiem(webhook, batch, body), 'retry')
  webhookStatus = 204
  assert.equal(await module.deliverSiem(webhook, batch, body), 'sent')
  assert.equal(await module.deliverSiem(s3, batch, body), 'sent')
  assert.equal(await module.deliverSiem(s3, batch, body), 'sent')
  s3Stored = hash('conflicting object')
  assert.equal(await module.deliverSiem(s3, batch, body), 'failed')
  assert.equal(await module.deliverSiem(syslog, batch, body), 'sent')
  const frame = await Promise.race([receivedFrame, new Promise((_, reject) => {
    const timer = setTimeout(() => reject(new Error('Syslog frame was not collected')), 5000)
    timer.unref()
  })])
  const divider = frame.indexOf(' ')
  assert.equal(Number(frame.slice(0, divider)), Buffer.byteLength(frame.slice(divider + 1)))
  assert.match(frame, /CEF:0\|Eagle Security\|SecTalk\|1\|security_digest\|/)
  assert.equal(Buffer.from(frame.split(' cs1=')[1], 'base64url').toString(), body)
  assert.deepEqual(collectors, [body, body, body])
  console.log('SIEM signed export, webhook retry, TLS CEF framing, and S3 conditional replay passed')
} finally {
  for (const server of opened) {
    server.closeAllConnections?.()
    await new Promise(resolve => server.close(resolve))
  }
  rmSync(keyFile,{force:true})
  rmSync(certificateFile,{force:true})
  rmdirSync(certificates)
}
