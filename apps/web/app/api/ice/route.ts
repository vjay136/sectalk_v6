import { createHmac } from 'node:crypto'
import { createClient } from '@supabase/supabase-js'

export async function GET(request: Request) {
  const headers = { 'Cache-Control': 'no-store' }
  const url = process.env.NEXT_PUBLIC_SUPABASE_URL
  const key = process.env.NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY
  const token = request.headers.get('Authorization')?.match(/^Bearer (\S+)$/i)?.[1]
  if (!url || !key || !token) return Response.json({ error: 'Sign in required' }, { status: 401, headers })
  const client = createClient(url, key, { auth: { persistSession: false, autoRefreshToken: false } })
  const { data, error } = await client.auth.getUser(token)
  if (error || !data.user) return Response.json({ error: 'Sign in required' }, { status: 401, headers })

  const turnSecret = process.env.TURN_SHARED_SECRET
  const urls = process.env.TURN_URLS?.split(',').map(value => value.trim()).filter(Boolean) ?? []
  const relay = turnSecret && urls.length && urls.every(value => /^turns?:[^\s]+$/.test(value))
  const stun = process.env.STUN_URL || 'stun:stun.l.google.com:19302'
  const iceServers: RTCIceServer[] = [{ urls: stun }]
  if (relay) {
    const username = Math.floor(Date.now() / 1000 + 3600) + ':' + data.user.id
    const credential = createHmac('sha1', turnSecret).update(username).digest('base64')
    iceServers.push({ urls, username, credential })
  }
  return Response.json({ iceServers, iceTransportPolicy: relay ? 'relay' : 'all' }, { headers })
}
