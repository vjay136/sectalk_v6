'use client'

import { useCallback, useEffect, useRef, useState, type FormEvent } from 'react'
import dynamic from 'next/dynamic'
import { CalendarDays, Video } from 'lucide-react'
import { db, formatError, liveChannel, onReconnect, type Profile } from '../lib/data'
import { SectionTabs } from './section-tabs'

const MeetingMedia = dynamic(() => import('./meeting-media'), { ssr: false })
type Meeting = { id:string; workspace_id:string; title:string; agenda:string; host_id:string; starts_at:string; ends_at:string; status:'scheduled'|'live'|'ended' }
type Attendance = { user_id:string; status:'waiting'|'admitted'|'declined'|'left'; requested_at:string; admitted_at:string|null; left_at:string|null }
type Space = { id:string; name:string; role:string }

export function Meetings({ user, requested }: { user:string; requested:string|null }) {
  const [meetings,setMeetings] = useState<Meeting[] | null>(null)
  const [spaces,setSpaces] = useState<Space[]>([])
  const [id,setId] = useState(requested)
  const [view,setView] = useState<'upcoming'|'past'|'schedule'|'instant'>('upcoming')
  const [ready,setReady] = useState(false)
  const [error,setError] = useState('')
  const [busy,setBusy] = useState(false)
  const pendingMeeting = useRef<{ input:string; id:string } | null>(null)
  const reload = useCallback(async () => {
    const { data,error } = await db!.from('st_v3_meetings').select('*').order('starts_at',{ascending:false}).limit(100)
    if (error) setError('Could not load meetings.')
    else setMeetings(data as Meeting[])
  },[])
  useEffect(() => {
    void reload()
    const subscription=liveChannel('meetings:'+user,reload)
      .on('postgres_changes',{event:'*',schema:'public',table:'st_v3_meetings'},reload).subscribe()
    const reconnect=onReconnect(reload)
    const interval=window.setInterval(reload,6000)
    const loadSpaces=async () => {
      const [membership,workspaces]=await Promise.all([
        db!.from('st_v2_members').select('workspace_id,role').eq('user_id',user),
        db!.from('st_v2_workspaces').select('id,name'),
      ])
      setSpaces((workspaces.data||[]).map(space => ({...space,role:membership.data?.find(row => row.workspace_id===space.id)?.role||'member'})))
    }
    void loadSpaces()
    void fetch('/api/meetings/token').then(reply=>reply.json()).then(data=>setReady(data.mediaConfigured===true)).catch(()=>undefined)
    return () => { reconnect();window.clearInterval(interval);void db!.removeChannel(subscription) }
  },[reload,user])
  async function createMeeting(event:FormEvent<HTMLFormElement>) {
    event.preventDefault()
    if (busy) return
    const form=event.currentTarget
    const data=new FormData(form)
    setBusy(true);setError('')
    try {
      const common={p_workspace:data.get('workspace'),p_title:data.get('title')}
      const input=instant?{...common,p_minutes:Number(data.get('duration'))}:{
        ...common,p_agenda:data.get('agenda'),p_start:new Date(String(data.get('start'))).toISOString(),
        p_end:new Date(String(data.get('end'))).toISOString(),
      }
      const key=JSON.stringify(input)
      if (pendingMeeting.current?.input!==key) pendingMeeting.current={input:key,id:crypto.randomUUID()}
      const result=await db!.rpc(instant?'st_v6_start_instant_meeting':'st_v3_schedule',{...input,p_id:pendingMeeting.current.id})
      if (result.error) throw result.error
      pendingMeeting.current=null
      form.reset();await reload();setView('upcoming');setId(result.data)
    } catch(error) { setError(formatError(error,instant?'Could not start the meeting.':'Could not schedule the meeting.')) }
    finally { setBusy(false) }
  }
  const selected=meetings?.find(m=>m.id===id)
  const hostSpaces=spaces.filter(space=>space.role==='owner'||space.role==='admin')
  const canHost=hostSpaces.length>0
  const instant=view==='instant'
  const editing=canHost && (view==='schedule'||instant)
  const past=(meeting:Meeting)=>meeting.status==='ended'||Date.parse(meeting.ends_at)<=Date.now()
  const list=meetings?.filter(meeting=>past(meeting)===(view==='past'))
  return <section className="content-page">
    <header className="content-title"><div className="card-icon"><Video size={22}/></div><div><h1>Meetings</h1><p>Schedule workspace meetings and manage the waiting room.</p></div></header>
    {!ready && <p className="release-info">Scheduling and waiting rooms are available. Live audio and video require a configured media provider.</p>}
    {error && <p role="alert" className="error">{error}</p>}
    <SectionTabs label="Meeting sections" value={editing ? view : view==='past' ? 'past' : 'upcoming'} onChange={next=>{if(!busy){setError('');setId(null);setView(next)}}} options={[
      ['upcoming','Upcoming & live'], ['past','Past meetings'], ...(canHost ? [['instant','Meet now'] as const,['schedule','Schedule'] as const] : []),
    ]}/>
    {editing ? <div className="panel release-panel">
      <h2>{instant?'Start a meeting now':'Schedule a meeting'}</h2><form key={view} className="release-form" onSubmit={createMeeting}>
        <label>Workspace<select required name="workspace">{hostSpaces.map(space=><option key={space.id} value={space.id}>{space.name}</option>)}</select></label>
        <label>Title<input name="title" required={!instant} placeholder={instant?'Instant meeting':undefined} maxLength={100}/></label>
        {instant ? <label>Duration<select name="duration" defaultValue="60">
          <option value="15">15 minutes</option><option value="30">30 minutes</option>
          <option value="60">1 hour</option><option value="120">2 hours</option>
        </select></label> : <>
          <label>Agenda<textarea name="agenda" rows={2} maxLength={2000}/></label>
          <div className="release-flex"><label>Starts at<input type="datetime-local" name="start" required/></label><label>Ends at<input type="datetime-local" name="end" required/></label></div>
        </>}
        <button className="primary" disabled={busy}>{instant?<Video size={16}/>:<CalendarDays size={16}/>} {instant?'Start meeting':'Schedule meeting'}</button>
      </form>
    </div> : <div className="panel release-panel">
      <h2>{view==='past'?'Past meetings':'Upcoming and live meetings'}</h2>
      {meetings===null && <p>Loading meetings…</p>}
      {list?.length===0 && <p>{view==='past'?'No past meetings.':'No upcoming meetings.'}</p>}
      {list?.map(meeting=><div className="release-row" key={meeting.id}>
        <button className={id===meeting.id?'primary':'secondary'} onClick={()=>setId(meeting.id)}>{meeting.title}</button>
        <span className="pill">{meeting.status}</span><time dateTime={meeting.starts_at}>{new Date(meeting.starts_at).toLocaleString()}</time>
      </div>)}
    </div>}
    {selected && <MeetingDetail key={selected.id} meeting={selected} user={user} mediaReady={ready}
      host={selected.host_id===user && hostSpaces.some(space=>space.id===selected.workspace_id)} refresh={reload}/>}
  </section>
}

function MeetingDetail({meeting,user,mediaReady,host,refresh}: {
  meeting:Meeting;user:string;mediaReady:boolean;host:boolean;refresh:()=>Promise<void>
}) {
  const [people,setPeople]=useState<Attendance[]>([])
  const [profiles,setProfiles]=useState<Record<string,Profile>>({})
  const [error,setError]=useState('')
  const [busy,setBusy]=useState(false)
  const [media,setMedia]=useState<{url:string;token:string}|null>(null)
  const [lobbyNotice,setLobbyNotice]=useState('')
  const reload=useCallback(async () => {
    const result=await db!.from('st_v3_attendance').select('*').eq('meeting_id',meeting.id).order('requested_at').limit(100)
    if(result.error) return
    const rows=result.data as Attendance[]
    setPeople(rows)
    if(!rows.find(row=>row.user_id===user && row.status==='admitted')) setMedia(null)
    const ids=rows.map(row=>row.user_id)
    if(host && ids.length) {
      const {data}=await db!.from('st_profiles').select('id,handle,name').in('id',ids)
      if(data) setProfiles(Object.fromEntries(data.map(row=>[row.id,row])))
    }
  },[meeting.id,user,host])
  useEffect(()=>{
    void reload()
    const subscription=liveChannel('attendees:'+meeting.id,reload)
      .on('postgres_changes',{event:'*',schema:'public',table:'st_v3_attendance',filter:'meeting_id=eq.'+meeting.id},reload).subscribe()
    const timer=window.setInterval(reload,4000)
    return ()=>{window.clearInterval(timer);void db!.removeChannel(subscription)}
  },[meeting.id,reload])
  const self=people.find(row=>row.user_id===user)?.status
  const ended=meeting.status==='ended'||Date.parse(meeting.ends_at)<=Date.now()

  async function action(name:string,input:Record<string,unknown>) {
    if(busy) return
    setBusy(true);setError('');setLobbyNotice('')
    try {
      const {data,error}=await db!.rpc(name,{p_meeting:meeting.id,...input})
      if(error) throw error
      if(name==='st_v6_admit_all'&&typeof data==='number'){
        setLobbyNotice(data===0?'No eligible attendees could be admitted.':
          data===1?'Admitted 1 attendee.':'Admitted '+data+' attendees.')
      }
      await Promise.all([refresh(),reload()])
    } catch(error){setError(formatError(error,'The meeting action failed.'))}
    finally{setBusy(false)}
  }
  async function connect() {
    if(busy || !mediaReady) return
    setBusy(true);setError('')
    try {
      const {data}=await db!.auth.getSession()
      const result=await fetch('/api/meetings/token',{method:'POST',headers:{'Content-Type':'application/json',Authorization:'Bearer '+data.session?.access_token},body:JSON.stringify({meetingId:meeting.id})})
      const value=await result.json()
      if(!result.ok) throw new Error(value.error||'Could not join the call.')
      setMedia(value)
    } catch(error){setError(formatError(error,'Could not join the call.'))}
    finally{setBusy(false)}
  }
  const refreshMedia=useCallback(()=>setMedia(null),[])
  return <div className="panel release-panel">
    <div className="release-row"><h2>{meeting.title}</h2><span className="pill">{ended?'ended':meeting.status}</span></div>
    {meeting.agenda&&<p className="meeting-agenda">{meeting.agenda}</p>}
    {error&&<p role="alert" className="error">{error}</p>}
    {!ended && <div className="release-row">
      {host && meeting.status==='scheduled' && <button className="primary" disabled={busy} onClick={()=>void action('st_v3_meeting_state',{p_state:'live'})}>Open waiting room</button>}
      {host && meeting.status==='live' && <button className="danger" disabled={busy} onClick={()=>{if(window.confirm('End this meeting for the workspace?')) void action('st_v3_meeting_state',{p_state:'ended'})}}>End meeting</button>}
      {(!host || meeting.status==='live') && (!self||self==='left') && <button className="secondary" disabled={busy} onClick={()=>void action('st_v3_request_admission',{})}>{host?'Rejoin meeting':'Request admission'}</button>}
      {self==='waiting' && <span role="status">Waiting for the host to admit you</span>}
      {self==='declined' && <span role="status">The host declined your request</span>}
      {self==='admitted' && meeting.status==='live' && !media && <button className="primary" disabled={busy||!mediaReady} onClick={()=>void connect()}>{mediaReady?'Join audio and video':'Live media unavailable'}</button>}
      {(self==='admitted'||self==='waiting') && <button className="secondary" disabled={busy} onClick={()=>{setMedia(null);void action('st_v3_leave',{})}}>Leave</button>}
    </div>}
    {media && self==='admitted' && !ended && <MeetingMedia {...media} leave={refreshMedia}/>}
    {host && <section className="release-section"><h2>Waiting room and attendance</h2>
      {meeting.status==='live'&&!ended&&people.some(person=>person.status==='waiting')&&
        <button className="primary" type="button" disabled={busy} onClick={()=>void action('st_v6_admit_all',{})}>Admit all eligible attendees</button>}
      {lobbyNotice&&<p role="status">{lobbyNotice}</p>}
      {!people.length&&<p>No attendees yet.</p>}
      {people.map(person=><div className="release-row" key={person.user_id}><strong>{profiles[person.user_id]?.name||'Workspace member'}</strong><span className="pill">{person.status}</span>
        {person.admitted_at&&<time dateTime={person.admitted_at}>{new Date(person.admitted_at).toLocaleString()}</time>}
        {person.status==='waiting'&&meeting.status==='live'&&!ended&&<>
          <button className="primary" disabled={busy} onClick={()=>void action('st_v3_admit',{p_user:person.user_id,p_allow:true})}>Admit</button>
          <button className="secondary" disabled={busy} onClick={()=>void action('st_v3_admit',{p_user:person.user_id,p_allow:false})}>Decline</button>
        </>}
      </div>)}
    </section>}
  </div>
}
