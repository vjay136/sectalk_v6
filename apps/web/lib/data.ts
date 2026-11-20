import { createClient } from '@supabase/supabase-js'

const url = process.env.NEXT_PUBLIC_SUPABASE_URL
const key = process.env.NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY
export const db = url && key ? createClient(url, key) : null

export function transientAuthClient() {
  return url && key ? createClient(url, key, {
    auth: {
      persistSession: false,
      autoRefreshToken: false,
      detectSessionInUrl: false,
      storageKey: 'sectalk-transient-auth',
    },
  }) : null
}

export function liveChannel(topic: string, catchUp: () => void) {
  return db!.channel(topic + ':' + crypto.randomUUID(), {
    config: { broadcast: { replication_ready: true } },
  }).on('system', {}, payload => {
    if (payload.extension === 'system' && payload.status === 'ok') catchUp()
  })
}

export function onReconnect(catchUp: () => void) {
  const visible = () => { if (document.visibilityState === 'visible') catchUp() }
  window.addEventListener('online', catchUp)
  document.addEventListener('visibilitychange', visible)
  return () => {
    window.removeEventListener('online', catchUp)
    document.removeEventListener('visibilitychange', visible)
  }
}

export type Profile = { id: string; handle: string; name: string }
export type Chat = {
  id: string; member_a: string; member_b: string; requester: string
  status: 'pending' | 'accepted' | 'declined'; updated_at: string
}
export type Message = { id: string; chat_id: string; sender: string; body: string; created_at: string; edited_at?: string | null; reply_to?: string | null; revoked_at?: string | null; forwarded?: boolean; expires_at?: string | null }
export type Call = {
  id: string; chat_id: string; caller: string; callee: string; video: boolean
  media_protection?: number
  status: 'ringing' | 'active' | 'ended'; expires_at: string; created_at: string
  end_reason?: 'missed' | 'declined' | 'cancelled' | 'busy' | null
}

export const categories = {
  harassment: 'Harassment or abuse',
  threat: 'Threat or stalking',
  scam: 'Scam or fraud',
  impersonation: 'Impersonation',
  spam: 'Spam or unwanted solicitation',
  sexual_content: 'Unwanted nudity or sexual content',
  other: 'Other concern',
}

export function peerId(chat: Chat, self: string) {
  return chat.member_a === self ? chat.member_b : chat.member_a
}

export function formatTime(value: string) {
  return new Intl.DateTimeFormat(undefined, { hour: 'numeric', minute: '2-digit' }).format(new Date(value))
}

export function formatError(error: unknown, fallback: string) {
  if (typeof error === 'object' && error && 'message' in error && typeof error.message === 'string') {
    return error.message
  }
  return fallback
}
