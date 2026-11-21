'use client'

import {useCallback,useEffect,useRef,useState,type FormEvent} from 'react'
import {db,formatError} from '../lib/data'

type Candidate={id:string;name:string;copied:boolean;messageCount?:number}
type Plan={plan:string;channel?:string;room?:string;key?:string;endpoint?:string;invitation?:string;link?:string;group?:string;order?:string;change?:string;member?:string;name:string;sha256:string;copySha256:string;archiveSha256?:string
  approvedAt:string|null;deletedAt?:string|null;detachedAt?:string|null;messages?:{id:string;sha256:string}[]}
type Status={held:boolean;channels?:Candidate[];rooms?:Candidate[];keys?:Candidate[];endpoints?:Candidate[];invitations?:Candidate[];links?:Candidate[];groups?:Candidate[];orders?:Candidate[];changes?:Candidate[];members?:Candidate[];plans:Plan[]}
type Action='copy'|'capture'|'approve'|'delete'

const scopes={
  channel:{
    title:'Remove archived channels',selection:'Archived channel',record:'channel',actionRecord:'archived channel',label:'Channel',
    database:'channels',rpc:'st_v8_offboarding_archived_channel',file:'archived-channel',
    eligibility:'Eligible channels use standard workspace access, have one verified archive event, and contain at most 16 eligible messages written by the owner.',
    retained:'original archive event',
    removed:'The archived channel and any approved messages were permanently removed. Its archive event was retained.'
  },
  room:{
    title:'Remove empty archived rooms',selection:'Empty archived room',record:'room',actionRecord:'archived room',label:'Room',
    database:'rooms',rpc:'st_v8_offboarding_archived_room',file:'archived-room',
    eligibility:'Eligible rooms are empty, archived, standard public rooms with only the original creator membership and creation and archive events.',
    retained:'creation, membership and archive evidence',
    removed:'The empty archived room was permanently removed. Its creation, membership and archive evidence was retained.'
  },
  key:{
    title:'Retire revoked API keys',selection:'Revoked API key',record:'API key',actionRecord:'revoked API key',label:'API key',
    database:'keys',rpc:'st_v8_offboarding_api_key',file:'retired-api-key',
    eligibility:'Eligible keys were created by the workspace owner and already revoked. Keys with usage records remain protected.',
    retained:'original workspace audit records',
    removed:'The revoked API key was removed from live integrations. Its workspace audit and retirement evidence were retained.'
  },
  endpoint:{
    title:'Retire revoked webhooks',selection:'Revoked webhook',record:'webhook',actionRecord:'revoked webhook',label:'Webhook',
    database:'endpoints',rpc:'st_v8_offboarding_webhook',file:'retired-webhook',
    eligibility:'Eligible webhooks were created by the workspace owner and already revoked. Webhooks with delivery records remain protected.',
    retained:'original workspace audit records',
    removed:'The revoked webhook was removed from live integrations. Its workspace audit and retirement evidence were retained.'
  },
  invitation:{
    title:'Remove declined invitations',selection:'Declined invitation',record:'invitation',actionRecord:'declined invitation',label:'Invitation',
    database:'invitations',rpc:'st_v8_offboarding_declined_invite',file:'declined-invitation',
    eligibility:'Eligible invitations were sent by the workspace owner and declined by the recipient. Related membership and access records remain protected.',
    retained:'original workspace audit and decline record',
    removed:'The declined invitation was removed from live invitations. The original audit and decline record were retained.'
  },
  link:{
    title:'Remove expired invitation links',selection:'Expired invitation link',record:'invitation link',actionRecord:'expired invitation link',label:'Invitation link',
    database:'links',rpc:'st_v8_offboarding_expired_link',file:'expired-invitation-link',
    eligibility:'Eligible links were issued by the workspace owner, have expired, and were never used. The copy excludes the email address and invitation token.',
    retained:'expiry record and original workspace audit',
    removed:'The expired invitation link was removed from live invitations. Its expiry record and the workspace audit were retained.'
  },
  group:{
    title:'Remove empty archived groups',selection:'Empty archived group',record:'group',actionRecord:'archived group',label:'Group',
    database:'groups',rpc:'st_v8_offboarding_archived_group',file:'archived-workspace-group',
    eligibility:'Eligible groups, teams, and departments were created and archived by the workspace owner and have no membership or access dependencies.',
    retained:'original creation and archive audit',
    removed:'The archived group was removed from the live workspace. Its original creation and archive audit were retained.'
  },
  order:{
    title:'Retain withdrawn enterprise quotes',selection:'Withdrawn quote',record:'quote',actionRecord:'withdrawn quote',label:'Quote',
    database:'orders',rpc:'st_v8_offboarding_withdrawn_quote',file:'withdrawn-enterprise-quote',
    eligibility:'Eligible quotes were withdrawn before acceptance. A reviewer with commercial billing authorization must approve detachment.',
    retained:'original quote and billing events',
    removed:'The direct workspace link was released. The original quote and billing events were retained.'
  },
  change:{
    title:'Retire rejected seat changes',selection:'Rejected seat change',record:'seat change',actionRecord:'rejected seat change',label:'Seat change',
    database:'changes',rpc:'st_v8_offboarding_rejected_seat_change',file:'rejected-seat-change',
    eligibility:'Eligible changes were initiated by the owner, finished with a rejection, and have an expired lease. A delegated billing reviewer must approve removal.',
    retained:'original billing evidence',
    removed:'The rejected attempt was removed from the live seat-change ledger. Its billing evidence was retained.'
  },
  member:{
    title:'Retire suspended memberships',selection:'Suspended membership',record:'membership',actionRecord:'suspended membership',label:'Member',
    database:'members',rpc:'st_v8_offboarding_suspended_member',file:'suspended-membership',
    eligibility:'Eligible memberships belong to suspended ordinary members who joined through a direct invitation and have no other access, billing, or evidence links.',
    retained:'accepted invitation and original join and suspension history',
    removed:'The suspended membership was removed from the live roster. The account, accepted invitation, and original audit were preserved.'
  }
} as const

export function WorkspaceReviewedRemoval({workspace,role,kind}:{workspace:string;role:'owner'|'reviewer';kind:keyof typeof scopes}) {
  const scope=scopes[kind]
  const record=scope.actionRecord
  const detaching=kind==='order'
  const operation=detaching?'detachment':'removal'
  const [open,setOpen]=useState(false)
  const [status,setStatus]=useState<Status>()
  const [selected,setSelected]=useState('')
  const [busy,setBusy]=useState(false)
  const [notice,setNotice]=useState('')
  const [error,setError]=useState('')
  const [loadError,setLoadError]=useState('')
  const latest=useRef(0)

  const load=useCallback(async()=>{
    const request=++latest.current
    const result=await db!.rpc(scope.rpc+'_status',{p_workspace:workspace})
    if(request!==latest.current) return
    if(result.error) {
      setStatus(undefined)
      setLoadError(formatError(result.error,'The '+record+' '+operation+' status could not be loaded.'))
    } else {
      setStatus(result.data)
      setLoadError('')
    }
  },[scope.rpc,record,workspace,operation])
  useEffect(()=>{
    if(!open) return
    void load()
    const timer=window.setInterval(()=>{if(document.visibilityState==='visible') void load()},12000)
    return ()=>{++latest.current;window.clearInterval(timer)}
  },[load,open])

  async function submit(event:FormEvent<HTMLFormElement>,action:Action,recordId:string,plan?:Plan) {
    event.preventDefault()
    if(busy) return
    const form=event.currentTarget
    const values=new FormData(form)
    if(action==='delete'&&String(values.get(kind)).trim()!==recordId) {
      setError('Enter the exact '+record+' ID.')
      return
    }
    setBusy(true)
    setError('')
    setNotice('')
    try {
      const result=await db!.rpc(scope.rpc,{p_workspace:workspace,['p_'+kind]:recordId,
        p_confirmation:String(values.get('workspace')).trim(),p_action:detaching&&action==='delete'?'detach':action,
        ...(plan?{p_plan:plan.plan,p_sha256:plan.sha256}:{})})
      if(result.error) throw result.error
      if(action==='copy') {
        const url=URL.createObjectURL(new Blob([JSON.stringify(result.data)],{type:'application/json'}))
        const link=document.createElement('a')
        link.href=url
        link.download='sectalk-approved-'+scope.file+'-'+recordId+'.json'
        link.click()
        window.setTimeout(()=>URL.revokeObjectURL(url),1000)
      }
      setNotice({
        copy:scope.selection+' copy downloaded.',
        capture:scope.selection+' prepared for independent review.',
        approve:'Exact '+record+' '+operation+' approved.',
        delete:scope.removed
      }[action])
      form.reset()
    } catch(cause) {
      setError(formatError(cause,'The '+record+' action could not be completed.'))
    } finally {
      await load()
      setBusy(false)
    }
  }

  const candidates=status?.[scope.database]??[]
  const candidate=candidates.find(item=>item.id===selected)
  return <details className="release-create" onToggle={event=>setOpen(event.currentTarget.open)}>
    <summary>{scope.title}</summary>
    <section aria-label={scope.title}>
      <p>{scope.eligibility}</p>
      {status?.held&&<p>Active preservation holds block {record} {operation}.</p>}
      {(error||loadError)&&<p role="alert" className="error">{error||loadError}</p>}
      {notice&&<p role="status">{notice}</p>}
      {status&&role==='owner'&&candidates.length===0&&<p>No eligible {record}s found.</p>}
      {status&&role==='owner'&&candidates.length>0&&<>
        <label>{scope.selection}<select aria-label={scope.selection} value={candidate?.id??''}
          onChange={event=>setSelected(event.currentTarget.value)} disabled={busy}>
          <option value="">Choose a {record}</option>
          {candidates.map(item=><option key={item.id} value={item.id}>
            {item.name}{typeof item.messageCount==='number'?' · '+item.messageCount+' messages':''} · {item.id}
          </option>)}
        </select></label>
        {candidate&&<form key={candidate.id} className="release-form" onSubmit={event=>{
          const trigger=(event.nativeEvent as SubmitEvent).submitter?.getAttribute('value')
          void submit(event,trigger==='capture'?'capture':'copy',candidate.id)
        }}>
          <label>Confirm {record} workspace ID<input name="workspace" required maxLength={36} autoComplete="off"/></label>
          <div className="actions">
            <button type="submit" className="secondary" disabled={busy||status.held}>Download {record} copy</button>
            {candidate.copied&&<button type="submit" className="secondary" value="capture" disabled={busy||status.held}>
              Prepare exact {scope.record} {operation} plan
            </button>}
          </div>
        </form>}
      </>}
      {status?.plans.map(plan=>{
        const id=plan[kind]
        if(!id) return null
        const completedAt=plan.detachedAt??plan.deletedAt
        const operationLabel=detaching?'Detachment':'Removal'
        return <article key={plan.plan} className="release-board-item">
          <h5>{plan.name}</h5>
          <p>{scope.label} ID <code>{id}</code></p>
          <p>{operationLabel} plan SHA-256 <code>{plan.sha256}</code></p>
          <p>{scope.label} copy SHA-256 <code>{plan.copySha256}</code></p>
          {plan.archiveSha256&&<p>{kind==='channel'?'Retained archive event':'Retained room audit and membership'} SHA-256 <code>{plan.archiveSha256}</code></p>}
          {!!plan.messages?.length&&<details>
            <summary>Review {plan.messages.length} archived messages</summary>
            <ul>{plan.messages.map(message=><li key={message.id}>
              <code>{message.id}</code> · SHA-256 <code>{message.sha256}</code>
            </li>)}</ul>
          </details>}
          <p>{completedAt?(detaching?'Quote retained in billing custody':'Removed from the live workspace')
            :plan.approvedAt?operationLabel+' independently approved':'Awaiting independent review'}</p>
          {!status.held&&!completedAt&&role==='reviewer'&&!plan.approvedAt&&<form className="release-form"
            onSubmit={event=>void submit(event,'approve',id,plan)}>
            <label>Confirm {scope.record} review workspace ID<input name="workspace" required maxLength={36} autoComplete="off"/></label>
            <button type="submit" className="secondary" disabled={busy}>Approve exact {record} {operation}</button>
          </form>}
          {!status.held&&!completedAt&&role==='owner'&&plan.approvedAt&&<details className="release-create">
            <summary>{detaching?'Detach this '+record:'Permanently remove this '+record}</summary>
            <form className="release-form" onSubmit={event=>void submit(event,'delete',id,plan)}>
              <p>{detaching?'This releases the quote’s direct workspace link and retains the original quote and billing events. The retained records become immutable.'
                :'This removes the '+scope.record+' from the live workspace and preserves its '+scope.retained+'. You cannot undo this action in SecTalk.'}</p>
              {!!plan.messages?.length&&<p>This permanently removes all {plan.messages.length} approved messages from the channel and search.</p>}
              <label>Confirm {scope.record} {operation} workspace ID<input name="workspace" required maxLength={36} autoComplete="off"/></label>
              <label>Confirm exact {record} ID<input name={kind} required maxLength={36} autoComplete="off"/></label>
              <label className="task-check"><input type="checkbox" required/> I retained the approved {scope.record} copy according to my workspace’s policy.</label>
              <button type="submit" className="primary" disabled={busy}>{detaching?'Detach approved quote':'Permanently remove approved '+scope.record}</button>
            </form>
          </details>}
        </article>
      })}
      <button type="button" className="secondary" disabled={busy} onClick={()=>void load()}>Refresh {record} status</button>
    </section>
  </details>
}
