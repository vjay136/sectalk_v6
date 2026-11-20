'use client'

import { useEffect, useState } from 'react'
import type { Session } from '@supabase/supabase-js'
import { db } from '../lib/data'
import { Brand, Entry } from '../components/entry'
import { Inbox } from '../components/inbox'

export default function Home() {
  const [session, setSession] = useState<Session | null>(null)
  const [loaded,setLoaded] = useState(!db)
  const [recovering, setRecovering] = useState(false)
  useEffect(() => {
    if (!db) return
    const { data } = db.auth.onAuthStateChange((event, value) => {
      if (event === 'PASSWORD_RECOVERY') setRecovering(true)
      if (event === 'SIGNED_OUT') setRecovering(false)
      setSession(value)
      setLoaded(true)
    })
    return () => data.subscription.unsubscribe()
  }, [])
  return loaded ? (session && !recovering ? <Inbox key={session.user.id} user={session.user.id} /> : <Entry recovering={recovering} />) :
    <main className="center-page"><Brand /><p role="status">Opening SecTalk…</p></main>
}
