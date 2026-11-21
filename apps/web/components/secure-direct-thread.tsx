'use client'

import {useCallback,useEffect,useRef,useState,type FormEvent} from 'react'
import {getSecurePair,openSecureDirect,sendSecureDirect,type SecureDelivery,type SecureDirectMessage} from '../lib/olm-direct'
import {getApprovedOlmDevice,prepareApprovedOlmDevice} from '../lib/olm-browser'
import {db,formatError,formatTime} from '../lib/data'
import {RichMessage} from './rich-message'

type View=Awaited<ReturnType<typeof getSecurePair>>
type Props={chat:string;owner:string;peer:string;ownerName:string;peerName:string;hints:EventTarget;openDeviceSettings:()=>void}

export function SecureDirectThread({chat,owner,peer,ownerName,peerName,hints,openDeviceSettings}:Props) {
  const [approval,setApproval]=useState<'checking'|'unapproved'|'needs_keys'|'ready'>('checking')
  const [view,setView]=useState<View>()
  const [messages,setMessages]=useState<SecureDirectMessage[]>([])
  const [before,setBefore]=useState<string|null>(null)
  const [draft,setDraft]=useState('')
  const [busy,setBusy]=useState(false)
  const [openError,setOpenError]=useState('')
  const [actionError,setActionError]=useState('')
  const fetchInProgress=useRef(false)
  const hasPaged=useRef(false)
  const pending=useRef<{body:string;delivery:SecureDelivery}|undefined>(undefined)
  const revision=useRef(0)

  const refresh=useCallback(async()=>{
    if(fetchInProgress.current)return
    fetchInProgress.current=true
    const current=++revision.current
    try {
      const approved=await getApprovedOlmDevice(owner)
      if(current!==revision.current)return
      setApproval(approved?(approved.bundle?'ready':'needs_keys'):'unapproved')
      if(!approved?.bundle){setView(undefined);setMessages([]);setBefore(null);hasPaged.current=false;return}
      const state=await getSecurePair(chat)
      if(current!==revision.current)return
      setView(state)
      if(!state.enabled){setMessages([]);setBefore(null);hasPaged.current=false;return}
      const page=await openSecureDirect(chat,owner,peer)
      const session=await db!.auth.getSession()
      if(current!==revision.current||session.data.session?.user.id!==owner)return
      setMessages(previous=>{
        const first=page.messages[0]?.sequence
        return [...previous.filter(item=>first!==undefined&&BigInt(item.sequence)<BigInt(first)),...page.messages]
      })
      if(!hasPaged.current)setBefore(page.before)
      setOpenError('')
    } catch(cause) {
      if(current!==revision.current)return
      setMessages([])
      setBefore(null)
      hasPaged.current=false
      setOpenError(formatError(cause,'Could not open secure messages.'))
    } finally {
      fetchInProgress.current=false
    }
  },[chat,owner,peer])

  useEffect(()=>{
    const receive=(event:Event)=>{if((event as MessageEvent<string>).data===chat)void refresh()}
    const update=()=>void refresh()
    update()
    hints.addEventListener('olm_pair_changed',receive)
    hints.addEventListener('contact_key_changed',update)
    hints.addEventListener('device_registry',update)
    const timer=window.setInterval(update,8000)
    return ()=>{
      ++revision.current
      window.clearInterval(timer)
      hints.removeEventListener('olm_pair_changed',receive)
      hints.removeEventListener('contact_key_changed',update)
      hints.removeEventListener('device_registry',update)
    }
  },[hints,chat,refresh])

  async function act(action:()=>Promise<unknown>,completion?:()=>void) {
    if(busy)return
    setBusy(true)
    setActionError('')
    try{await action();completion?.()}
    catch(cause){setActionError(formatError(cause,'Could not complete this secure conversation action.'))}
    finally{setBusy(false)}
  }

  function submit(event:FormEvent<HTMLFormElement>) {
    event.preventDefault()
    const body=draft
    const previous=pending.current?.body===body?pending.current.delivery:undefined
    void act(async()=>{
      try{
        await sendSecureDirect(chat,owner,peer,body,previous,delivery=>{pending.current={body,delivery}})
      } catch(cause) {
        if(typeof cause==='object'&&cause!==null&&'code' in cause&&cause.code==='40001')pending.current=undefined
        throw cause
      }
    },()=>{pending.current=undefined;setDraft('');void refresh()})
  }

  return <section className="release-section" aria-label="Secure direct messages">
    <h3>Secure direct messages</h3>
    <p>End-to-end encrypted on approved browsers. Compare your safety number using Verify contact keys before opening the thread.</p>
    {approval==='checking'&&<p role="status">Checking this browser…</p>}
    {approval==='unapproved'&&<button type="button" className="secondary" onClick={openDeviceSettings}>Manage approved browsers</button>}
    {approval==='needs_keys'&&<button type="button" className="secondary" disabled={busy}
      onClick={()=>void act(()=>prepareApprovedOlmDevice(owner),()=>void refresh())}>Prepare this secure browser</button>}
    {view&&!view.enabled&&(view.optedIn?<p role="status">Waiting for {peerName} to enable secure messages.</p>:
      <button type="button" className="primary" disabled={busy} onClick={()=>void act(async()=>{
        setView(await getSecurePair(chat,true));void refresh()
      })}>Enable secure messages</button>)}
    {view?.enabled&&<>
      {before&&<button type="button" className="secondary" disabled={busy} onClick={()=>void act(async()=>{
        const older=await openSecureDirect(chat,owner,peer,before)
        if((await db!.auth.getSession()).data.session?.user.id!==owner)return
        setMessages(current=>[...older.messages.filter(item=>!current.some(message=>message.id===item.id)),...current])
        hasPaged.current=true
        setBefore(older.before)
      })}>Load earlier secure messages</button>}
      <div role="log" aria-label="Encrypted direct messages"><ol>{messages.map(message=><li key={message.id}>
        <strong>{message.actor===owner?ownerName:peerName}</strong> <time dateTime={message.sent}>{formatTime(message.sent)}</time>
        {message.body?<RichMessage value={message.body} account={owner} mode="encrypted" allowLinks={false}/>:
          <p>This encrypted message is unavailable on this browser.</p>}
      </li>)}</ol></div>
      <form className="release-form" onSubmit={submit}>
        <label>Write a secure message<textarea value={draft} maxLength={4000} disabled={busy} onChange={event=>setDraft(event.target.value)}/></label>
        <button type="submit" className="primary" disabled={busy||!view.epoch||!draft.trim()}>Send secure message</button>
      </form>
    </>}
    {(actionError||openError)&&<p className="error" role="alert">{actionError||openError}</p>}
  </section>
}
