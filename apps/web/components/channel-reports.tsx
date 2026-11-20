'use client'

import {useCallback,useEffect,useState,type FormEvent} from 'react'
import {categories,db,formatError,formatTime} from '../lib/data'
import {Dialog} from './inbox'

type Category=keyof typeof categories
type ReviewScope='platform'|'workspace'
type ReportState='open'|'reviewing'|'resolved'|'dismissed'
type Decision='handoff'|Exclude<ReportState,'open'>
type Timeline={action:Decision;at:string}
type PersonalReport={id:string;category:Category;state:ReportState;created_at:string;timeline:Timeline[]}
type QueueReport=Omit<PersonalReport,'timeline'>&{handoff_allowed:boolean;handed_off_at:string|null;
  details:string;evidence:string;channel_name:string|null;workspace_name:string|null}
const states={open:'Open',reviewing:'In review',resolved:'Resolved',dismissed:'Dismissed'}
const changes={handoff:'Sent to workspace review',reviewing:'Review started',resolved:'Resolved',dismissed:'Dismissed'}

export function ChannelReportDialog({channel,post,body,close,done}:{channel:string;post:string;body:string;close:()=>void;done:()=>void}) {
  const [category,setCategory]=useState<Category>('harassment')
  const [busy,setBusy]=useState(false)
  const [error,setError]=useState('')
  const eligible=category==='spam'||category==='other'

  async function submit(event:FormEvent<HTMLFormElement>) {
    event.preventDefault()
    if(busy)return
    const fields=new FormData(event.currentTarget)
    setBusy(true)
    setError('')
    const result=await db!.rpc('st_v7_submit_channel_report',{p_channel:channel,p_post:post,p_category:category,
      p_details:String(fields.get('details')??''),p_share_with_safety:fields.has('share-safety'),
      p_share_with_workspace:eligible&&fields.has('share-workspace'),
    })
    setBusy(false)
    if(result.error){setError(formatError(result.error,'Could not submit this report.'));return}
    done()
  }

  return <Dialog title="Report channel message" close={close}><form className="release-form" onSubmit={submit}>
    <blockquote>{body}</blockquote>
    <label>Report category<select aria-label="Report category" value={category} onChange={event=>setCategory(event.target.value as Category)}>
      {Object.entries(categories).map(([id,label])=><option key={id} value={id}>{label}</option>)}
    </select></label>
    <label>Report details (optional)<textarea name="details" maxLength={1500} rows={3}/></label>
    <label className="task-check"><input name="share-safety" type="checkbox" required/> Share this message and my notes with SecTalk Safety</label>
    {eligible&&<label className="task-check"><input name="share-workspace" type="checkbox"/> Allow Safety to share this message with authorized workspace moderators</label>}
    {error&&<p className="error" role="alert">{error}</p>}
    <button className="primary" disabled={busy}>Submit channel report</button>
  </form></Dialog>
}

export function MyChannelReports({hints}:{hints:EventTarget}) {
  const [rows,setRows]=useState<PersonalReport[]|null>(null)
  const [error,setError]=useState('')
  useEffect(()=>{
    let active=true
    async function refresh(){
      const result=await db!.rpc('st_v7_my_channel_reports')
      if(!active)return
      if(result.error)setError('Could not load channel reports.')
      else{setRows(result.data as PersonalReport[]);setError('')}
    }
    void refresh()
    hints.addEventListener('channel_report_updated',refresh)
    const timer=window.setInterval(refresh,12000)
    return ()=>{active=false;window.clearInterval(timer);hints.removeEventListener('channel_report_updated',refresh)}
  },[hints])
  return <section className="release-section" aria-label="My channel reports">
    <h3>My channel reports</h3>
    {error&&<p className="error" role="alert">{error}</p>}
    {!error&&rows===null&&<p role="status">Loading reports…</p>}
    {rows?.length===0&&<p>No channel message reports yet.</p>}
    {rows?.map(row=><details className="release-create" key={row.id}>
      <summary>{categories[row.category]} · <span>{states[row.state]}</span></summary>
      <ol className="audit"><li>Report received <time dateTime={row.created_at}>{formatTime(row.created_at)}</time></li>
        {row.timeline.map(item=><li key={item.action+item.at}>{changes[item.action]} <time dateTime={item.at}>{formatTime(item.at)}</time></li>)}
      </ol>
    </details>)}
  </section>
}

export function ChannelReportQueue({scope}:{scope:ReviewScope}) {
  const [rows,setRows]=useState<QueueReport[]|null>(null)
  const [error,setError]=useState('')
  const [notice,setNotice]=useState('')
  const [busy,setBusy]=useState('')
  const refresh=useCallback(async()=>{
    const result=await db!.rpc('st_v7_channel_report_queue',{p_scope:scope})
    if(result.error){setRows(null);setError('Channel report review is unavailable.');return}
    setRows(result.data as QueueReport[])
  },[scope])
  useEffect(()=>{
    void refresh()
    const timer=window.setInterval(()=>void refresh(),8000)
    return ()=>window.clearInterval(timer)
  },[refresh])

  async function decide(event:FormEvent<HTMLFormElement>,row:QueueReport) {
    event.preventDefault()
    if(busy)return
    const fields=new FormData(event.currentTarget)
    setBusy(row.id);setError('');setNotice('')
    const result=await db!.rpc('st_v7_review_channel_report',{p_report:row.id,p_scope:scope,
      p_action:fields.get('decision'),p_reason:fields.get('reason'),
    })
    setBusy('')
    if(result.error){setError(formatError(result.error,'Could not save this decision.'));return}
    setNotice('Channel report decision saved.')
    await refresh()
  }

  return <section className="panel release-panel" aria-label="Channel report queue">
    <h2>Channel report queue</h2>
    {error&&<p role="alert" className="error">{error}</p>}
    {notice&&<p role="status">{notice}</p>}
    {!error&&rows===null&&<p role="status">Loading channel reports…</p>}
    {rows?.length===0&&<p>No channel reports are available.</p>}
    {rows?.map(row=><details className="release-create" key={row.id}>
      <summary>{row.channel_name?'#'+row.channel_name:'Channel'} · {categories[row.category]} · {states[row.state]}</summary>
      {row.workspace_name&&<p>{row.workspace_name}</p>}
      <blockquote aria-label="Consented channel evidence">{row.evidence}</blockquote>
      {row.details&&<p>{row.details}</p>}
      {(row.state==='open'||row.state==='reviewing')&&<form className="release-form" onSubmit={event=>void decide(event,row)}>
        <label>Channel review decision<select aria-label="Channel review decision" name="decision">
          <option value="reviewing">Start review</option>
          {scope==='platform'&&row.handoff_allowed&&!row.handed_off_at&&<option value="handoff">Refer to workspace review</option>}
          <option value="resolved">Resolve report</option>
          <option value="dismissed">Dismiss report</option>
        </select></label>
        <label>Decision reason<input name="reason" required maxLength={500}/></label>
        <button className="primary" disabled={!!busy}>Save channel decision</button>
      </form>}
    </details>)}
  </section>
}
