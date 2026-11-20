import { createHash } from 'node:crypto'
import { createClient } from '@supabase/supabase-js'

export const integrationHeaders = { 'Cache-Control': 'private, no-store' }
export const uuidPattern = /^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/i

const auth = { persistSession: false, autoRefreshToken: false, detectSessionInUrl: false }
const url = process.env.NEXT_PUBLIC_SUPABASE_URL
const publishable = process.env.NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY
const secret = process.env.SECTALK_INTEGRATIONS_SUPABASE_KEY
export const integrationsWriter = url && secret ? createClient(url, secret, { auth }) : null
export const apiKeyHash = (key: string) => createHash('sha256').update(key, 'utf8').digest('hex')

export async function integrationIdentity(request: Request) {
  const token = request.headers.get('Authorization')?.match(/^Bearer (\S+)$/i)?.[1]
  if (!url || !publishable || !token) return null
  const client = createClient(url, publishable, { auth, global: { headers: { Authorization: 'Bearer ' + token } } })
  const { error, data } = await client.auth.getUser(token)
  return !error && data.user ? client : null
}

export function integrationFailure(status: number, message: string) {
  return Response.json({ error: message }, {
    status, headers: { ...integrationHeaders, ...(status === 429 ? { 'Retry-After': '60' } : {}) },
  })
}
