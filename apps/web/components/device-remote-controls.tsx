'use client'

import { useState, type FormEvent } from 'react'
import { db } from '../lib/data'
import { verifyAccountCredential } from '../lib/account-credential'
import { enrollCurrentDevice } from '../lib/device-identity'

type Action='revoke'|'lock'|'wipe'|'cancel'|'unlock'
export type DeviceCommand = {device:string;locked:boolean;wiped:boolean;command:string|null;kind:'revoke'|'lock'|'wipe'|null;
  state:'pending'|'delivered'|'acknowledged'|'cancelled'|null;operator_wipe_pending?:boolean}
const labels={revoke:'Revoke device sessions',lock:'Lock device',wipe:'Wipe local device keys',cancel:'Cancel pending command',unlock:'Unlock device'}
const descriptions={
  revoke:'Active sessions linked to this device will end immediately.',
  lock:'The device will be signed out. SecTalk will require account verification to unlock this browser.',
  wipe:'Linked sessions will end immediately. This browser can erase its registered private keys when it next reaches SecTalk.',
  cancel:'Cancelling a pending command leaves its ended sessions signed out.',
  unlock:'This browser can verify its registered keys and bind a new session after unlock.',
}
const commandStatus={
  pending:'Pending delivery. The device may be offline.',
  delivered:'Dispatched in a browser poll. Awaiting acknowledgment.',
  acknowledged:'Acknowledged by the browser.',
  cancelled:'Cancelled before delivery.',
}

export function DeviceRemoteControls({status,hasFactor,hasRegisteredDevice,onChange}: {
  status:DeviceCommand;hasFactor:boolean;hasRegisteredDevice:boolean;onChange:()=>Promise<void>
}) {
  const [choice,setChoice]=useState<Action|null>(null)
  const [error,setError]=useState('')
  const [busy,setBusy]=useState(false)
  const [feedback,setFeedback]=useState('')
  const active=status.state==='pending'||status.state==='delivered'
  const actions:Action[]=status.wiped?[]:active
    ? status.state==='pending'&&!status.operator_wipe_pending?['cancel']:[]
    : status.locked?['unlock','wipe']:['revoke','lock','wipe']

  async function apply(event:FormEvent<HTMLFormElement>) {
    event.preventDefault()
    if (!choice||busy) return
    const form=event.currentTarget
    setBusy(true)
    setError('')
    setFeedback('')
    try {
      await verifyAccountCredential(String(new FormData(form).get('credential')??''),hasFactor)
      // A fresh password sign-in establishes a new native session.
      if (!hasFactor&&hasRegisteredDevice) await enrollCurrentDevice()
      const result=await db!.rpc('st_v7_issue_device_command',{
        p_device:status.device,p_action:choice,p_command:choice==='cancel'?status.command:null,
      })
      if (result.error||!result.data) throw new Error()
      setFeedback(choice==='cancel'?'Pending command cancelled.':choice==='unlock'?'Device unlocked.':'Device command issued.')
      setChoice(null)
      await onChange()
    } catch {setError('Could not complete the device action. Check your credentials and refresh device status.')}
    finally {setBusy(false);form.reset()}
  }

  return <div className="release-section" aria-label="Remote device actions">
    {status.locked&&<p>Device locked</p>}
    {status.wiped&&<p>Previous device identity retired</p>}
    {status.state&&status.kind&&<p><strong>{labels[status.kind]}</strong>{' · '}{commandStatus[status.state]}</p>}
    {status.operator_wipe_pending&&<p>An account operator requested this wipe. Contact support to cancel it before delivery.</p>}
    <div className="actions">{actions.map(action=><button className="secondary" type="button" disabled={busy}
      key={action} onClick={()=>{setChoice(action);setError('');setFeedback('')}}>{labels[action]}</button>)}</div>
    {choice&&<form className="release-form" onSubmit={apply}>
      <p>{descriptions[choice]}</p>
      <label>{hasFactor?'Current authenticator code':'Current password'}<input name="credential" type={hasFactor?'text':'password'}
        autoComplete={hasFactor?'one-time-code':'current-password'} inputMode={hasFactor?'numeric':undefined}
        pattern={hasFactor?'[0-9]{6}':undefined} required/></label>
      <div className="actions">
        <button className="primary" disabled={busy}>Confirm {labels[choice].toLowerCase()}</button>
        <button className="secondary" type="button" disabled={busy} onClick={()=>setChoice(null)}>Close remote action</button>
      </div>
    </form>}
    {error&&<p className="error" role="alert">{error}</p>}
    {feedback&&<p role="status">{feedback}</p>}
  </div>
}
