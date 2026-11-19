import { createClient } from '@supabase/supabase-js'

const url = process.env.NEXT_PUBLIC_SUPABASE_URL
const key = process.env.NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY
export const db = url && key ? createClient(url, key) : null

export type Profile = { id: string; handle: string; name: string }
export type Chat = {
  id: string; member_a: string; member_b: string; requester: string
  status: 'pending' | 'accepted' | 'declined'; updated_at: string
}
export type Message = { id: string; chat_id: string; sender: string; body: string; created_at: string }
export type Call = {
  id: string; chat_id: string; caller: string; callee: string; video: boolean
  status: 'ringing' | 'active' | 'ended'; expires_at: string
}

export const categories = {
  harassment: 'Harassment or abuse',
  threat: 'Threat or stalking',
  scam: 'Scam or fraud',
  impersonation: 'Impersonation',
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
