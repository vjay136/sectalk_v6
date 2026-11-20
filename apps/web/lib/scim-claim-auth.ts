import { createClient } from '@supabase/supabase-js'

export const scimClaimPath = '/auth/scim-claim'

export function scimClaimAuth() {
  const url = process.env.NEXT_PUBLIC_SUPABASE_URL
  const key = process.env.NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY
  if (!url || !key) throw new Error('Email verification is unavailable.')
  const memory = new Map<string, string>()
  // Keep the verifier available to the email link in the same browser.
  // The short-lived verification session itself stays in memory.
  const storage = {
    getItem(name: string) {
      return name.endsWith('-code-verifier') ? window.localStorage.getItem(name) : memory.get(name) ?? null
    },
    setItem(name: string, value: string) {
      if (name.endsWith('-code-verifier')) window.localStorage.setItem(name, value)
      else memory.set(name, value)
    },
    removeItem(name: string) {
      if (name.endsWith('-code-verifier')) window.localStorage.removeItem(name)
      else memory.delete(name)
    },
  }
  return createClient(url, key, { auth: { storage, storageKey: 'sectalk-scim-claim', flowType: 'pkce',
    detectSessionInUrl: false, autoRefreshToken: false } })
}
