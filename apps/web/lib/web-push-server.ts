import { createECDH, timingSafeEqual } from 'node:crypto'
import { createClient } from '@supabase/supabase-js'
import { sendNotification } from 'web-push'
import { supabaseApiFetch } from './supabase-api-fetch.mjs'

export const pushHeaders = { 'Cache-Control': 'private, no-store', 'X-Content-Type-Options': 'nosniff' }
const clientOptions = { auth: { persistSession: false, autoRefreshToken: false } }
const keyPattern = /^[A-Za-z0-9_-]+$/
const bodyLimit = 4096
const pushPayload = JSON.stringify({ v: 1 })

export function pushConfiguration() {
  const url = process.env.NEXT_PUBLIC_SUPABASE_URL
  const browserKey = process.env.NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY
  const serviceKey = process.env.SECTALK_PUSH_SERVICE_KEY
  const publicKey = process.env.SECTALK_VAPID_PUBLIC_KEY
  const privateKey = process.env.SECTALK_VAPID_PRIVATE_KEY
  const subject = process.env.SECTALK_VAPID_SUBJECT
  const dispatchSecret = process.env.SECTALK_PUSH_DISPATCH_SECRET
  if (!url || !browserKey || !serviceKey || !publicKey || !privateKey || !subject || !dispatchSecret
    || Buffer.byteLength(dispatchSecret) < 32
    || !/^(mailto:[^\s@]+@[^\s@]+|https:\/\/[^\s]+)$/.test(subject)) return null
  try {
    if (!keyPattern.test(publicKey) || !keyPattern.test(privateKey)) return null
    const ecdh = createECDH('prime256v1')
    ecdh.setPrivateKey(Buffer.from(privateKey, 'base64url'))
    if (ecdh.getPublicKey().toString('base64url') !== publicKey) return null
  } catch { return null }
  return {
    url, browserKey, vapid: { subject, publicKey, privateKey }, dispatchSecret,
    service: createClient(url, serviceKey, { ...clientOptions, global: { fetch: supabaseApiFetch(serviceKey) } }),
  }
}
type PushConfiguration = NonNullable<ReturnType<typeof pushConfiguration>>

export async function authenticatePush(request: Request, configuration: PushConfiguration, removing = false) {
  const token = request.headers.get('Authorization')?.match(/^Bearer (\S+)$/i)?.[1]
  if (!token) return null
  const client = createClient(configuration.url, configuration.browserKey, {
    ...clientOptions, global: { fetch: supabaseApiFetch(configuration.browserKey) },
  })
  const [verified, user] = await Promise.all([client.auth.getClaims(token), client.auth.getUser(token)])
  const claims = verified.data?.claims
  if (verified.error || user.error || !claims || user.data.user?.id !== claims.sub
    || typeof claims.session_id !== 'string') return null
  if (!removing && user.data.user.factors?.some(factor => factor.status === 'verified') && claims.aal !== 'aal2') return null
  return { p_actor: claims.sub, p_session: claims.session_id }
}

export function pushEndpoint(input: unknown) {
  if (typeof input !== 'string' || input.length > 2048) return null
  try {
    const endpoint = new URL(input)
    if (endpoint.protocol !== 'https:' || endpoint.port || endpoint.username || endpoint.password || endpoint.hash) return null
    const host = endpoint.hostname
    const path = endpoint.pathname
    const allowed = (host === 'fcm.googleapis.com' && /^\/(?:fcm\/send|wp)\/.+/.test(path))
      || (host === 'updates.push.services.mozilla.com' && path.startsWith('/wpush/'))
      || (host === 'web.push.apple.com' && path.length > 1)
      || (/^[a-z0-9-]+\.notify\.windows\.com$/.test(host) && path.length > 1)
    return allowed ? endpoint.href : null
  } catch { return null }
}

export async function pushInput(request: Request) {
  if (!request.body) return null
  const reader = request.body.getReader()
  const chunks: Uint8Array[] = []
  let length = 0
  try {
    for (;;) {
      const { done, value } = await reader.read()
      if (done) break
      length += value.byteLength
      if (length > bodyLimit) {
        await reader.cancel()
        return null
      }
      chunks.push(value)
    }
    return JSON.parse(Buffer.concat(chunks).toString('utf8'))
  } catch { return null }
  finally { reader.releaseLock() }
}

export function pushSubscription(input: {endpoint?: unknown; keys?: {p256dh?: unknown; auth?: unknown}} | null) {
  const endpoint = pushEndpoint(input?.endpoint)
  const { p256dh, auth } = input?.keys ?? {}
  if (!endpoint || typeof p256dh !== 'string' || typeof auth !== 'string'
    || p256dh.length !== 87 || auth.length !== 22 || !keyPattern.test(p256dh) || !keyPattern.test(auth)) return null
  try {
    const point = Buffer.from(p256dh, 'base64url')
    if (point.length !== 65 || point[0] !== 4 || Buffer.from(auth, 'base64url').length !== 16) return null
    const ecdh = createECDH('prime256v1')
    ecdh.generateKeys()
    ecdh.computeSecret(point)
    return { endpoint, keys: { p256dh, auth } }
  } catch { return null }
}

export function dispatchAuthorized(request: Request, secret: string) {
  const provided = Buffer.from(request.headers.get('Authorization') ?? '')
  const expected = Buffer.from('Bearer ' + secret)
  return provided.length === expected.length && timingSafeEqual(provided, expected)
}

type Result = 'sent' | 'gone' | 'retry' | 'rejected' | 'discard'
export async function sendWebPush(
  input: Parameters<typeof pushSubscription>[0], ttl: number, vapid: PushConfiguration['vapid'],
  incomingCall = false,
): Promise<Result> {
  const subscription = pushSubscription(input)
  if (!subscription || ttl <= 0) return 'discard'
  const duration = incomingCall ? Math.min(30, ttl) : ttl
  const payload = incomingCall
    ? JSON.stringify({ v: 2, kind: 'incoming-call', expiresAt: Date.now() + duration * 1000 })
    : pushPayload
  try {
    await sendNotification(subscription, payload, {
      vapidDetails: vapid, contentEncoding: 'aes128gcm', TTL: duration, timeout: 5000,
      topic: incomingCall ? 'sectalk-call' : 'sectalk-update',
      urgency: incomingCall ? 'high' : 'normal',
    })
    return 'sent'
  } catch (error) {
    const status = (error as { statusCode?: number }).statusCode
    if (status === 404 || status === 410) return 'gone'
    return status === undefined || status === 429 || status >= 500 ? 'retry' : 'rejected'
  }
}
