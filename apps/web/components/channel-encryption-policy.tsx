'use client'

import { useCallback, useEffect, useState } from 'react'
import { db,formatError } from '../lib/data'
import { StaffMfa } from './staff-mfa'

export function ChannelEncryptionPolicy({ workspace }: { workspace: string }) {
  const [state,setState]=useState<{ verified: boolean; managed: boolean } | null>(null)
  const [busy,setBusy]=useState(false)
  const [error,setError]=useState('')
  const [notice,setNotice]=useState('')
  const load=useCallback(async()=>{
    const result=await db!.rpc('st_v8_channel_mode_policy',{p_workspace:workspace})
    if (result.error) setError('Could not load channel encryption policy.')
    else setState(result.data)
  },[workspace])
  useEffect(()=>{void load()},[load])

  async function update() {
    if (!state?.verified || busy) return
    setBusy(true);setError('');setNotice('')
    try {
      const result=await db!.rpc('st_v8_set_channel_mode_policy',{p_workspace:workspace,p_managed:!state.managed})
      if (result.error) throw result.error
      await load()
      setNotice('New channel policy saved.')
    } catch (failure) { setError(formatError(failure,'Could not change the policy.')) }
    finally { setBusy(false) }
  }
  return <details className="release-create">
    <summary>New channel encryption policy</summary>
    <section aria-label="New channel encryption policy">
      <p>The policy sets encryption when a workspace channel is created. Each channel keeps the mode assigned at creation.</p>
      {error && <p className="error" role="alert">{error}</p>}
      {notice && <p role="status">{notice}</p>}
      {state && !state.verified && <StaffMfa refresh={load} explanation="Verify your authenticator before changing channel encryption policy."/>}
      {state?.verified && <><p>{state.managed ? 'New channels use managed encryption.' : 'New channels use standard workspace storage.'}</p>
        <button className="secondary" type="button" disabled={busy} onClick={()=>void update()}>
          {state.managed ? 'Use standard storage for new channels' : 'Enable managed encryption for new channels'}</button>
      </>}
    </section>
  </details>
}
