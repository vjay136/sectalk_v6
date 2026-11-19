'use client'

import { useEffect, useState } from 'react'
import type { Session } from '@supabase/supabase-js'
import { db } from '../lib/data'
import { Entry } from '../components/entry'
import { Inbox } from '../components/inbox'

export default function Home() {
  const [session, setSession] = useState<Session | null>(null)
  useEffect(() => {
    if (!db) return
    const { data } = db.auth.onAuthStateChange((_event, value) => setSession(value))
    return () => data.subscription.unsubscribe()
  }, [])
  return session ? <Inbox key={session.user.id} user={session.user.id} /> : <Entry />
}
