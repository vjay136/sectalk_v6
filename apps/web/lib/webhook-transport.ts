import { createCipheriv, createDecipheriv, createHmac, randomBytes } from 'node:crypto'
import { lookup } from 'node:dns/promises'
import { request as httpRequest } from 'node:http'
import { request as httpsRequest } from 'node:https'
import { BlockList, isIP } from 'node:net'

const blocked = new BlockList()
for (const [address, prefix] of [
  ['0.0.0.0', 8], ['10.0.0.0', 8], ['100.64.0.0', 10], ['127.0.0.0', 8], ['169.254.0.0', 16],
  ['172.16.0.0', 12], ['192.0.0.0', 24], ['192.0.2.0', 24], ['192.88.99.0', 24], ['192.168.0.0', 16],
  ['198.18.0.0', 15], ['198.51.100.0', 24], ['203.0.113.0', 24], ['224.0.0.0', 4], ['240.0.0.0', 4],
] as const) blocked.addSubnet(address, prefix, 'ipv4')
for (const [address, prefix] of [
  ['2001::', 23], ['2001:db8::', 32], ['2002::', 16], ['3fff::', 20],
] as const) blocked.addSubnet(address, prefix, 'ipv6')
const globalIPv6 = new BlockList()
globalIPv6.addSubnet('2000::', 3, 'ipv6')

export function publicWebhookAddress(address: string) {
  const family = isIP(address)
  if (family === 4) return !blocked.check(address, 'ipv4')
  return family === 6 && globalIPv6.check(address, 'ipv6') && !blocked.check(address, 'ipv6')
}

function localFixture(url: URL) {
  try {
    return url.protocol === 'http:' && url.hostname === '127.0.0.1'
      && new URL(process.env.SECTALK_APP_URL ?? '').hostname === '127.0.0.1'
      && url.origin === process.env.SECTALK_TEST_WEBHOOK_ORIGIN
  } catch { return false }
}

export function webhookUrl(value: unknown) {
  if (typeof value !== 'string' || value.length > 480) return null
  try {
    const url = new URL(value)
    if (url.username || url.password || url.search || url.hash) return null
    if (localFixture(url)) return url
    if (url.protocol !== 'https:' || url.port || !url.hostname.includes('.') || url.hostname.endsWith('.')
      || isIP(url.hostname) || url.hostname === 'localhost' || url.hostname.endsWith('.local')) return null
    return url
  } catch { return null }
}

export async function resolveWebhook(url: URL) {
  if (localFixture(url)) return '127.0.0.1'
  const addresses = await Promise.race([
    lookup(url.hostname, { all: true }),
    new Promise<never>((_, reject) => {
      const timer = setTimeout(() => reject(new Error('DNS resolution timed out')), 2500)
      timer.unref()
    }),
  ])
  if (addresses.length === 0 || addresses.some(entry => !publicWebhookAddress(entry.address))) {
    throw new Error('Use a publicly reachable HTTPS webhook endpoint')
  }
  return addresses.find(entry => entry.family === 4)?.address ?? addresses[0].address
}

function wrappingKey() {
  const key = process.env.SECTALK_WEBHOOK_ENCRYPTION_KEY ?? ''
  if (!/^[a-f0-9]{64}$/i.test(key)) throw new Error('Webhook signing is unavailable.')
  return Buffer.from(key, 'hex')
}

export function sealWebhookSecret(secret: Buffer, workspace: string, endpoint: string) {
  const nonce = randomBytes(12)
  const cipher = createCipheriv('aes-256-gcm', wrappingKey(), nonce).setAAD(Buffer.from(workspace + ':' + endpoint))
  const encrypted = Buffer.concat([cipher.update(secret), cipher.final()])
  return Buffer.concat([nonce, cipher.getAuthTag(), encrypted]).toString('base64url')
}

export function openWebhookSecret(value: string, workspace: string, endpoint: string) {
  const bytes = Buffer.from(value, 'base64url')
  if (bytes.length !== 60) throw new Error('Webhook signing key is unavailable.')
  const decipher = createDecipheriv('aes-256-gcm', wrappingKey(), bytes.subarray(0, 12))
    .setAAD(Buffer.from(workspace + ':' + endpoint)).setAuthTag(bytes.subarray(12, 28))
  return Buffer.concat([decipher.update(bytes.subarray(28)), decipher.final()])
}

export function webhookHeaders(key: Buffer, event: string, body: string, timestamp = Math.floor(Date.now() / 1000)) {
  const signature = createHmac('sha256', key).update(event + '.' + timestamp + '.' + body).digest('base64')
  return { 'webhook-id': event, 'webhook-timestamp': String(timestamp), 'webhook-signature': 'v1,' + signature }
}

export function sendWebhook(url: URL, address: string, secret: Buffer, event: string, body: string) {
  if (!(localFixture(url) && address === '127.0.0.1') && !publicWebhookAddress(address)) {
    throw new Error('Webhook destination is blocked.')
  }
  const send = localFixture(url) ? httpRequest : httpsRequest
  return new Promise<number>((resolve, reject) => {
    const request = send({
      hostname: address, port: url.port || 443, path: url.pathname, method: 'POST', agent: false,
      ...(url.protocol === 'https:' ? { servername: url.hostname, rejectUnauthorized: true } : {}),
      headers: { Host: url.host, 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(body),
        ...webhookHeaders(secret, event, body) },
      signal: AbortSignal.timeout(6000),
    }, response => {
      const status = response.statusCode ?? 500
      response.destroy()
      resolve(status)
    })
    request.on('error', reject)
    request.end(body)
  })
}
