import {createHmac, createPublicKey, verify} from 'node:crypto'
import {BlockList, isIP} from 'node:net'
import {createClient} from '@supabase/supabase-js'

type Network = {
  asn: number | null
  reputation: 'normal' | 'poor' | 'unknown'
  tor: boolean
  vpn: boolean
  latitude: number | null
  longitude: number | null
  radiusKm: number | null
  confidence: number | null
}
type Range = {prefix: number; family: 'ipv4' | 'ipv6'; block: BlockList; network: Network}
const maxBytes = 1024 * 1024
const hour = 3600000
let cache: {config: string; until: number; entries: Range[]} | undefined
let pending: {config: string; result: Promise<Range[]>} | undefined

function boundedNumber(value: unknown, min: number, max: number): value is number {
  return typeof value === 'number' && Number.isFinite(value) && value >= min && value <= max
}

function parseRange(row: Record<string, unknown>): Range {
  const {cidr, asn, reputation, tor, vpn, latitude, longitude, radiusKm, confidence} = row
  if (typeof cidr !== 'string' || (asn !== null && (!boundedNumber(asn, 1, 4294967295) || !Number.isInteger(asn))) ||
    (reputation !== 'normal' && reputation !== 'poor' && reputation !== 'unknown') ||
    typeof tor !== 'boolean' || typeof vpn !== 'boolean') throw new Error('Invalid network reputation entry')
  if (latitude !== null || longitude !== null || radiusKm !== null || confidence !== null) {
    if (!boundedNumber(latitude, -90, 90) || !boundedNumber(longitude, -180, 180) ||
      !boundedNumber(radiusKm, 0, 20000) || !boundedNumber(confidence, 0, 100)) {
      throw new Error('Invalid network location entry')
    }
  }
  const [address, bits, ...rest] = cidr.split('/')
  const version = isIP(address)
  const prefix = Number(bits)
  if (rest.length || !/^\d{1,3}$/.test(bits) || !version || prefix > (version === 4 ? 32 : 128)) {
    throw new Error('Invalid risk feed subnet')
  }
  const family = version === 4 ? 'ipv4' : 'ipv6'
  const block = new BlockList()
  block.addSubnet(address, prefix, family)
  const network = {asn, reputation, tor, vpn, latitude, longitude, radiusKm, confidence} as Network
  return {prefix, family, block, network}
}

async function readBounded(response: Response) {
  if (!response.ok || !response.body || Number(response.headers.get('content-length')) > maxBytes) throw new Error('Risk feed unavailable')
  const reader = response.body.getReader()
  const chunks: Buffer[] = []
  let size = 0
  try {
    while (true) {
      const chunk = await reader.read()
      if (chunk.done) return Buffer.concat(chunks, size).toString('utf8')
      size += chunk.value.length
      if (size > maxBytes) throw new Error('Risk feed too large')
      chunks.push(Buffer.from(chunk.value))
    }
  } finally {
    await reader.cancel().catch(() => {})
  }
}

async function download(url: URL, key: string) {
  const response = await fetch(url, {redirect: 'error', cache: 'no-store', signal: AbortSignal.timeout(2000)})
  const {payload, signature} = JSON.parse(await readBounded(response))
  if (typeof payload !== 'string' || typeof signature !== 'string' ||
    !/^[\w-]+$/.test(payload) || !/^[\w-]{86}$/.test(signature)) throw new Error('Invalid risk feed envelope')
  const bytes = Buffer.from(payload, 'base64url')
  const publicKey = createPublicKey({key: Buffer.from(key, 'base64'), format: 'der', type: 'spki'})
  if (publicKey.asymmetricKeyType !== 'ed25519' || !verify(null, bytes, publicKey, Buffer.from(signature, 'base64url'))) {
    throw new Error('Invalid risk feed signature')
  }
  const {issuedAt, expiresAt, entries} = JSON.parse(bytes.toString('utf8'))
  const now = Date.now()
  if (!boundedNumber(issuedAt, now - 48 * hour, now + 60000) ||
    !boundedNumber(expiresAt, now + 1, issuedAt + 48 * hour) ||
    !Array.isArray(entries) || entries.length > 5000) throw new Error('Invalid or expired risk feed')
  return {until: Math.min(expiresAt, now + 5 * 60000), entries: entries.map(parseRange).sort((a, b) => b.prefix - a.prefix)}
}

export async function signedNetworkRisk(ip: string): Promise<Network | null> {
  const location = process.env.SECTALK_AUTH_RISK_FEED_URL
  const key = process.env.SECTALK_AUTH_RISK_FEED_PUBLIC_KEY
  const version = isIP(ip)
  if (!location || !key || !version) return null
  try {
    const url = new URL(location)
    const localQa = process.env.NODE_ENV !== 'production' && url.protocol === 'http:' && url.hostname === '127.0.0.1'
    if ((url.protocol !== 'https:' && !localQa) || url.username || url.password) return null
    const config = location + ':' + key
    if (!cache || cache.config !== config || cache.until <= Date.now()) {
      if (pending?.config !== config) {
        const result = download(url, key).then(data => {
          cache = {...data, config}
          return data.entries
        }).catch(() => {
          cache = {config, until: Date.now() + 15000, entries: []}
          return []
        }).finally(() => {
          if (pending?.config === config) pending = undefined
        })
        pending = {config, result}
      }
      await pending.result
    }
    const family = version === 4 ? 'ipv4' : 'ipv6'
    return cache?.config === config && cache.until > Date.now()
      ? cache.entries.find(item => item.family === family && item.block.check(ip, family))?.network ?? null
      : null
  } catch {
    return null
  }
}

export function sessionRiskGateway(url: string, email: string) {
  const serviceKey = process.env.SECTALK_AUTH_RISK_SERVICE_KEY
  const secret = process.env.SECTALK_AUTH_RISK_IDENTIFIER_SECRET
  if (!serviceKey && !secret) return null
  if (!serviceKey || !secret || secret.length < 32) throw new Error('Incomplete session risk configuration')
  // Use the Project API origin for trusted service RPCs, even if password calls use an Auth ingress.
  const dbUrl = process.env.NEXT_PUBLIC_SUPABASE_URL || url
  const db = createClient(dbUrl, serviceKey, {auth: {persistSession: false, autoRefreshToken: false}})
  const hash = createHmac('sha256', secret).update('sectalk-password-risk:' + email.toLowerCase()).digest('hex')
  return {
    async failure() {
      await db.rpc('st_v7_record_password_failure', {p_identifier: hash}).abortSignal(AbortSignal.timeout(250))
    },
    async assess(actor: string, accessToken: string) {
      const p_session = JSON.parse(Buffer.from(accessToken.split('.')[1], 'base64url').toString('utf8')).session_id
      if (typeof p_session !== 'string') throw new Error('Missing native session')
      const scope = {p_actor: actor, p_session}
      const providerConfigured = process.env.SECTALK_AUTH_RISK_FEED_URL && process.env.SECTALK_AUTH_RISK_FEED_PUBLIC_KEY
      let network: Network | null = null
      if (providerConfigured) {
        const ip = await db.rpc('st_v7_risk_session_network', scope).abortSignal(AbortSignal.timeout(2500))
        if (ip.error) throw new Error('Could not resolve the native session network')
        if (typeof ip.data === 'string') network = await signedNetworkRisk(ip.data)
      }
      const result = await db.rpc('st_v7_score_password_session', {...scope, p_identifier: hash, p_network: network}).abortSignal(AbortSignal.timeout(3500))
      if (result.error) throw new Error('Could not assess native session')
    },
  }
}
