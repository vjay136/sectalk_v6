import { createHash, createHmac, createPrivateKey, createPublicKey, sign } from 'node:crypto'
import { connect } from 'node:tls'
import { resolveWebhook, sendWebhook, webhookUrl } from './webhook-transport'

export const siemUuid = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i
const categories = new Set(['member_suspended', 'member_removed', 'administrator_granted', 'data_loss_policy_updated',
  'audit_export_requested', 'integration_key_created', 'integration_key_revoked'])

export type Batch = {id: string; workspace: string; period: string; counts: Record<string, number>; lease: string}
type Result = 'sent' | 'retry' | 'failed'
type Connector = {workspace: string} & (
  {channel: 'webhook'; url: URL; secret: Buffer}
  | {channel: 'syslog'; host: string; port: number; ca?: string}
  | {channel: 's3'; bucket: string; region: string; accessKeyId: string; secretAccessKey: string; sessionToken?: string}
)

function sha256(value: string | Buffer) {
  return createHash('sha256').update(value).digest('hex')
}

function hmac(key: string | Buffer, value: string) {
  return createHmac('sha256', key).update(value).digest()
}

function loopbackApp() {
  try { return new URL(process.env.SECTALK_APP_URL ?? '').hostname === '127.0.0.1' }
  catch { return false }
}

export function signingKey() {
  const value = process.env.SECTALK_SIEM_SIGNING_KEY ?? ''
  if (!/^[\w-]{60,100}$/.test(value)) throw new Error('Missing SIEM signing key')
  const key = createPrivateKey({key: Buffer.from(value, 'base64url'), format: 'der', type: 'pkcs8'})
  if (key.asymmetricKeyType !== 'ed25519') throw new Error('Invalid SIEM signing key')
  return key
}

export function siemEnvelope(batch: Batch, key = signingKey()) {
  if (!siemUuid.test(batch.id) || !siemUuid.test(batch.workspace)) throw new Error('Invalid SIEM batch')
  const entries = Object.entries(batch.counts).sort(([first], [second]) => first.localeCompare(second, 'en'))
  if (entries.some(([name, count]) => !categories.has(name) || !Number.isSafeInteger(count) || count < 1)) {
    throw new Error('Invalid SIEM category')
  }
  const payload = JSON.stringify({format: 'sectalk-siem-v1', id: batch.id, workspace: batch.workspace,
    period: new Date(batch.period).toISOString(), counts: Object.fromEntries(entries)})
  const publicKey = createPublicKey(key).export({format: 'der', type: 'spki'})
  return JSON.stringify({algorithm: 'Ed25519', key_id: sha256(publicKey), sha256: sha256(payload), payload,
    signature: sign(null, Buffer.from(payload), key).toString('base64url')})
}

export function siemConnectors(): Connector[] {
  const value = process.env.SECTALK_SIEM_CONNECTORS || '[]'
  if (value.length > 32000) throw new Error('Invalid SIEM configuration')
  const entries: unknown = JSON.parse(value)
  if (!Array.isArray(entries) || entries.length > 12) throw new Error('Invalid SIEM configuration')
  const scopes = new Set<string>()
  return entries.map((row: Record<string, unknown>): Connector => {
    if (!row || typeof row.workspace !== 'string' || !siemUuid.test(row.workspace)) throw new Error('Invalid SIEM workspace')
    const workspace = row.workspace.toLowerCase()
    const scope = workspace + '/' + row.channel
    if (scopes.has(scope)) throw new Error('Duplicate SIEM connector')
    scopes.add(scope)
    const channel = row.channel
    if (channel === 'webhook') {
      const url = webhookUrl(row.url)
      if (url && typeof row.secret === 'string' && /^[\w-]{43}$/.test(row.secret))
        return {workspace, channel, url, secret: Buffer.from(row.secret, 'base64url')}
    }
    if (channel === 'syslog' && typeof row.host === 'string') {
      const localPort = Number(process.env.SECTALK_SIEM_TEST_SYSLOG_PORT)
      if (row.host === 'localhost' && loopbackApp() && Number.isInteger(localPort) && localPort > 0 && localPort <= 65535
        && process.env.SECTALK_SIEM_TEST_SYSLOG_CA) {
        return {workspace, channel, host: row.host, port: localPort, ca: process.env.SECTALK_SIEM_TEST_SYSLOG_CA}
      }
      if (/^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/.test(row.host) && row.host.length <= 253)
        return {workspace, channel, host: row.host, port: 6514}
    }
    if (channel === 's3' && typeof row.bucket === 'string' && /^[a-z0-9][a-z0-9-]{1,61}[a-z0-9]$/.test(row.bucket)
      && typeof row.region === 'string' && /^[a-z]{2}(?:-[a-z]+){1,3}-[1-9]\d?$/.test(row.region)
      && typeof row.accessKeyId === 'string' && /^[A-Z0-9]{16,32}$/.test(row.accessKeyId)
      && typeof row.secretAccessKey === 'string' && /^[A-Za-z0-9+/=]{40}$/.test(row.secretAccessKey)
      && (row.sessionToken === undefined || (typeof row.sessionToken === 'string' && /^[\x21-\x7e]{1,4096}$/.test(row.sessionToken)))) {
      return {workspace, channel, bucket: row.bucket, region: row.region, accessKeyId: row.accessKeyId,
        secretAccessKey: row.secretAccessKey, sessionToken: row.sessionToken}
    }
    throw new Error('Invalid SIEM connector')
  })
}

function result(status: number): Result {
  if (status >= 200 && status < 300) return 'sent'
  return status === 408 || status === 429 || status >= 500 ? 'retry' : 'failed'
}

async function sendSyslog(connector: Extract<Connector, {channel: 'syslog'}>, batch: Batch, body: string) {
  const address = connector.ca ? '127.0.0.1' : await resolveWebhook(new URL('https://' + connector.host))
  const content = '<134>1 ' + new Date(batch.period).toISOString() + ' sectalk sectalk - SIEM - CEF:0|Eagle Security|SecTalk|1'
    + '|security_digest|Workspace security digest|3|externalId=' + batch.id + ' cs1Label=SignedEnvelope cs1='
    + Buffer.from(body).toString('base64url')
  await new Promise<void>((resolve, reject) => {
    const socket = connect({host: address, port: connector.port, servername: connector.host,
      rejectUnauthorized: true, minVersion: 'TLSv1.2', ca: connector.ca})
    const timer = setTimeout(() => socket.destroy(new Error('SIEM timeout')), 6000)
    socket.once('error', reject)
    socket.once('close', () => { clearTimeout(timer); reject(new Error('SIEM transport closed')) })
    socket.once('secureConnect', () => socket.end(Buffer.byteLength(content) + ' ' + content, resolve))
  })
  return 'sent' as const
}

function s3Origin(connector: Extract<Connector, {channel: 's3'}>) {
  const test = process.env.SECTALK_SIEM_TEST_S3_ORIGIN
  if (test && loopbackApp() && /^http:\/\/127\.0\.0\.1:\d{1,5}$/.test(test)) return test
  return 'https://' + connector.bucket + '.s3.' + connector.region + '.amazonaws.com'
}

async function sendS3(connector: Extract<Connector, {channel: 's3'}>, batch: Batch, body: string) {
  const path = '/sectalk-siem/' + batch.workspace + '/' + batch.id + '.json'
  const url = new URL(path, s3Origin(connector))
  const digest = sha256(body)
  const time = new Date().toISOString().replace(/[-:]|\.\d{3}/g, '')
  const date = time.slice(0, 8)
  const scope = [date, connector.region, 's3', 'aws4_request'].join('/')
  const key = hmac(hmac(hmac(hmac('AWS4' + connector.secretAccessKey, date), connector.region), 's3'), 'aws4_request')
  async function call(method: 'PUT' | 'HEAD') {
    const headers: Record<string, string> = {host: url.host, 'x-amz-date': time,
      'x-amz-content-sha256': method === 'PUT' ? digest : sha256('')}
    if (connector.sessionToken) headers['x-amz-security-token'] = connector.sessionToken
    if (method === 'PUT') {
      headers['if-none-match'] = '*'
      headers['content-type'] = 'application/json'
      headers['x-amz-meta-sha256'] = digest
    }
    const names = Object.keys(headers).sort()
    const canonical = [method, path, '', names.map(name => name + ':' + headers[name] + '\n').join(''),
      names.join(';'), headers['x-amz-content-sha256']].join('\n')
    const signature = hmac(key, ['AWS4-HMAC-SHA256', time, scope, sha256(canonical)].join('\n')).toString('hex')
    headers.authorization = 'AWS4-HMAC-SHA256 Credential=' + connector.accessKeyId + '/' + scope
      + ', SignedHeaders=' + names.join(';') + ', Signature=' + signature
    const response = await fetch(url, {method, headers, body: method === 'PUT' ? body : undefined,
      redirect: 'error', signal: AbortSignal.timeout(6000)})
    await response.body?.cancel()
    return response
  }
  const response = await call('PUT')
  if (response.status === 409) return 'retry'
  if (response.status !== 412) return result(response.status)
  const existing = await call('HEAD')
  if (!existing.ok) return result(existing.status)
  return existing.headers.get('x-amz-meta-sha256') === digest ? 'sent' : 'failed'
}

export async function deliverSiem(connector: Connector, batch: Batch, body: string): Promise<Result> {
  if (connector.workspace !== batch.workspace) return 'failed'
  if (connector.channel === 'syslog') return sendSyslog(connector, batch, body)
  if (connector.channel === 's3') return sendS3(connector, batch, body)
  return result(await sendWebhook(connector.url, await resolveWebhook(connector.url), connector.secret, batch.id, body))
}
