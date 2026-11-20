import { createClient } from '@supabase/supabase-js'
import { base64urlToBinary, binaryToBase64url, deviceBundleContract } from '../../../../../lib/device-bundle'
import { readBoundedText } from '../../../../../lib/request-body'
import { reputationLinkTranscript, type ReputationLinkProof } from '../../../../../lib/reputation-link-proof'

export const runtime = 'nodejs'
const status = (code: number) => new Response(null, { status: code, headers: { 'Cache-Control': 'private, no-store', Vary: 'Authorization' } })
const auth = { persistSession: false, autoRefreshToken: false }
const signing = { name: 'ECDSA', namedCurve: 'P-256' }
async function verifier(publicKey: string) {
  const bytes = base64urlToBinary(publicKey)
  if (bytes.byteLength !== 65 || binaryToBase64url(bytes.buffer) !== publicKey) throw new Error('Invalid public key')
  return crypto.subtle.importKey('raw', bytes, signing, false, ['verify'])
}

export async function POST(request: Request) {
  const { NEXT_PUBLIC_SUPABASE_URL: url, NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY: key, SECTALK_DEVICE_BUNDLE_SERVICE_KEY: service } = process.env
  if (!url || !key || !service) return status(503)
  const bearer = request.headers.get('Authorization')
  if (!bearer?.startsWith('Bearer ')) return status(401)
  const scoped = createClient(url, key, { auth, global: { headers: { Authorization: bearer } } })
  const user = await scoped.auth.getUser(bearer.slice(7))
  if (user.error || !user.data.user) return status(401)
  try {
    const raw = await readBoundedText(request, 768)
    if (!raw) return status(400)
    const { challenge, identity, installation } = JSON.parse(raw) ?? {}
    if (typeof challenge !== 'string' || !deviceBundleContract.uuid.test(challenge) ||
        typeof identity !== 'string' || !deviceBundleContract.signature.test(identity) ||
        typeof installation !== 'string' || !deviceBundleContract.signature.test(installation)) return status(400)
    const result = await scoped.rpc('st_v7_manage_browser_reputation_link', { p_action: 'proof', p_challenge: challenge })
    const proof = result.data as ReputationLinkProof | null
    if (result.error || !proof || proof.owner !== user.data.user.id) return status(403)
    const message = reputationLinkTranscript(proof)
    const algorithm = { name: 'ECDSA', hash: 'SHA-256' }
    const [accountValid, aliasValid] = await Promise.all([
      verifier(proof.signing).then(publicKey => crypto.subtle.verify(algorithm, publicKey, base64urlToBinary(identity), message)),
      verifier(proof.alias).then(publicKey => crypto.subtle.verify(algorithm, publicKey, base64urlToBinary(installation), message)),
    ])
    if (!accountValid || !aliasValid) return status(403)
    const finished = await createClient(url, service, { auth }).rpc('st_v7_finish_browser_reputation_link', {
      p_challenge: proof.challenge, p_actor: proof.owner, p_session: proof.session,
    })
    return status(finished.error ? 503 : finished.data ? 204 : 409)
  } catch {
    return status(400)
  }
}
