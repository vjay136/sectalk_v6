'use client'

import { useCallback, useEffect, useRef, useState, type FormEvent } from 'react'
import dynamic from 'next/dynamic'
import { CalendarDays, Video } from 'lucide-react'
import { db, formatError, liveChannel, onReconnect, type Profile } from '../lib/data'
import { saveDownload } from '../lib/chat-files'
import { meetingCalendar, meetingLink } from '../lib/meeting-calendar'
import { useFeature } from '../lib/use-feature'
import { SectionTabs } from './section-tabs'
import { WorkspaceSwitcher, useWorkspaceContext, type Workspace } from './workspace-context'
import { MeetingEngagement } from './meeting-engagement'
import { MeetingCollaboration } from './meeting-collaboration'
import { MeetingModeratorActions, MeetingParticipantModeration, useMeetingModeration } from './meeting-moderation'
import { MeetingRecording } from './meeting-recording'
import { MeetingCaptions } from './meeting-captions'
import { MeetingSummary } from './meeting-summary'
import { MeetingGuestHost } from './meeting-guest-host'
import type { MeetingChoices } from './meeting-prejoin'

const MeetingMedia = dynamic(() => import('./meeting-media'), { ssr: false })
const MeetingPrejoin = dynamic(() => import('./meeting-prejoin'), { ssr: false })
type Meeting = { id:string; workspace_id:string; title:string; agenda:string; host_id:string; starts_at:string; ends_at:string; status:'scheduled'|'live'|'ended'; series_id:string|null; series_index:number|null; series_total:number|null; meeting_locked:boolean; chat_disabled:boolean; screen_share_disabled:boolean }
type Attendance = { user_id:string; status:'waiting'|'admitted'|'declined'|'left'; requested_at:string; admitted_at:string|null; left_at:string|null; is_cohost:boolean; removed_at:string|null }
export function Meetings({ user, requested }: { user:string; requested:string|null }) {
  const {active,workspaces,select}=useWorkspaceContext()
  const [linkedWorkspace,setLinkedWorkspace]=useState<string|null|undefined>(requested?undefined:null)
  const [linkUsed,setLinkUsed]=useState(false)
  const [dismissed,setDismissed]=useState(false)
  useEffect(()=>{
    if(!requested)return
    let mounted=true
    void db!.from('st_v3_meetings').select('workspace_id').eq('id',requested).maybeSingle().then(({data})=>{
      if(mounted)setLinkedWorkspace(data?.workspace_id||null)
    })
    return()=>{mounted=false}
  },[requested])
  const permittedLink=Boolean(linkedWorkspace&&workspaces?.some(space=>space.id===linkedWorkspace))
  useEffect(()=>{
    if(!linkUsed&&!dismissed&&permittedLink&&linkedWorkspace){
      select(linkedWorkspace)
      setLinkUsed(true)
    }
  },[dismissed,linkUsed,linkedWorkspace,permittedLink,select])
  const opening=requested&&!dismissed&&(linkedWorkspace===undefined||!workspaces||(permittedLink&&!linkUsed))
  const linkedMeeting=!dismissed&&permittedLink&&active?.id===linkedWorkspace?requested:null
  return <section className="content-page">
    <header className="content-title"><div className="card-icon"><Video size={22}/></div><div><h1>Meetings</h1><p>Schedule workspace meetings and manage the waiting room.</p></div></header>
    <WorkspaceSwitcher onSwitch={()=>setDismissed(true)}/>
    {opening?<p role="status">Opening meeting…</p>:<>
      {requested&&!dismissed&&!permittedLink&&<p role="status">This meeting is unavailable to your account.</p>}
      {active?<WorkspaceMeetings key={active.id+active.role} user={user} requested={linkedMeeting} workspace={active}/>:
        workspaces?.length===0&&!requested&&<p>Join or create a workspace to see meetings.</p>}
    </>}
  </section>
}

function WorkspaceMeetings({ user, requested, workspace }: { user:string; requested:string|null; workspace:Workspace }){
  const [meetings,setMeetings] = useState<Meeting[] | null>(null)
  const [id,setId] = useState(requested)
  const [view,setView] = useState<'upcoming'|'past'|'schedule'|'instant'>('upcoming')
  const [ready,setReady] = useState(false)
  const [error,setError] = useState('')
  const [busy,setBusy] = useState(false)
  const [frequency,setFrequency]=useState('once')
  const pendingMeeting = useRef<{ input:string; id:string } | null>(null)
  const workspaceId=workspace.id
  const recurrence=useFeature('recurring_meetings',workspaceId,view==='schedule')
  const reload = useCallback(async () => {
    const { data,error } = await db!.from('st_v3_meetings').select('*').eq('workspace_id',workspaceId).order('starts_at',{ascending:false}).limit(100)
    if (error) setError('Could not load meetings.')
    else {
      if(requested&&!data.some(row=>row.id===requested)){
        const linked=await db!.from('st_v3_meetings').select('*').eq('workspace_id',workspaceId).eq('id',requested).maybeSingle()
        if(linked.data)data.push(linked.data)
      }
      setMeetings(data as Meeting[])
    }
  },[requested,workspaceId])
  useEffect(() => {
    void reload()
    const subscription=liveChannel('meetings:'+workspaceId,reload)
      .on('postgres_changes',{event:'*',schema:'public',table:'st_v3_meetings',filter:'workspace_id=eq.'+workspaceId},reload).subscribe()
    const reconnect=onReconnect(reload)
    const interval=window.setInterval(reload,6000)
    void fetch('/api/meetings/token').then(reply=>reply.json()).then(data=>setReady(data.mediaConfigured===true)).catch(()=>undefined)
    return () => { reconnect();window.clearInterval(interval);void db!.removeChannel(subscription) }
  },[reload,workspaceId])
  async function createMeeting(event:FormEvent<HTMLFormElement>) {
    event.preventDefault()
    if (busy) return
    const form=event.currentTarget
    const data=new FormData(form)
    setBusy(true);setError('')
    try {
      const common={p_workspace:workspaceId,p_title:data.get('title')}
      const repeats=!instant&&frequency!=='once'
      if(repeats&&!recurrence)throw new Error('Recurring meetings are unavailable.')
      const input=instant?{...common,p_minutes:Number(data.get('duration'))}:{
        ...common,p_agenda:data.get('agenda'),p_start:new Date(String(data.get('start'))).toISOString(),
        p_end:new Date(String(data.get('end'))).toISOString(),
        ...(repeats?{p_frequency:frequency,p_count:Number(data.get('count')),p_zone:Intl.DateTimeFormat().resolvedOptions().timeZone}:{}),
      }
      const key=JSON.stringify(input)
      if (pendingMeeting.current?.input!==key) pendingMeeting.current={input:key,id:crypto.randomUUID()}
      const action=instant?'st_v6_start_instant_meeting':repeats?'st_v6_schedule_series':'st_v3_schedule'
      const result=await db!.rpc(action,{...input,p_id:pendingMeeting.current.id})
      if (result.error) throw result.error
      pendingMeeting.current=null
      form.reset();setFrequency('once');await reload();setView('upcoming');setId(result.data)
    } catch(error) { setError(formatError(error,instant?'Could not start the meeting.':'Could not schedule the meeting.')) }
    finally { setBusy(false) }
  }
  const selected=meetings?.find(m=>m.id===id)
  const canHost=workspace.role==='owner'||workspace.role==='admin'
  const instant=view==='instant'
  const editing=canHost && (view==='schedule'||instant)
  const past=(meeting:Meeting)=>meeting.status==='ended'||Date.parse(meeting.ends_at)<=Date.now()
  const list=meetings?.filter(meeting=>past(meeting)===(view==='past'))
  return <>
    {!ready && <p className="release-info">Scheduling and waiting rooms are available. Live audio and video require a configured media provider.</p>}
    {error && <p role="alert" className="error">{error}</p>}
    <SectionTabs label="Meeting sections" value={editing ? view : view==='past' ? 'past' : 'upcoming'} onChange={next=>{if(!busy){setError('');setId(null);setView(next)}}} options={[
      ['upcoming','Upcoming & live'], ['past','Past meetings'], ...(canHost ? [['instant','Meet now'] as const,['schedule','Schedule'] as const] : []),
    ]}/>
    {editing ? <div className="panel release-panel">
      <h2>{instant?'Start a meeting now':'Schedule a meeting'}</h2><form key={view} className="release-form" onSubmit={createMeeting}>
        <label>Title<input name="title" required={!instant} placeholder={instant?'Instant meeting':undefined} maxLength={100}/></label>
        {instant ? <label>Duration<select name="duration" defaultValue="60">
          <option value="15">15 minutes</option><option value="30">30 minutes</option>
          <option value="60">1 hour</option><option value="120">2 hours</option>
        </select></label> : <>
          <label>Agenda<textarea name="agenda" rows={2} maxLength={2000}/></label>
          <div className="release-flex"><label>Starts at<input type="datetime-local" name="start" required/></label><label>Ends at<input type="datetime-local" name="end" required/></label></div>
          <div className="release-flex"><label>Repeat<select value={frequency} disabled={busy} onChange={event=>setFrequency(event.target.value)}>
            <option value="once">Does not repeat</option><option value="daily" disabled={!recurrence}>Daily</option>
            <option value="weekly" disabled={!recurrence}>Weekly</option>
          </select></label>{frequency!=='once'&&<label>Occurrences<input name="count" type="number" min="2" max="12" defaultValue="4" required/></label>}</div>
        </>}
        <button className="primary" disabled={busy}>{instant?<Video size={16}/>:<CalendarDays size={16}/>} {instant?'Start meeting':'Schedule meeting'}</button>
      </form>
    </div> : <div className="panel release-panel">
      <h2>{view==='past'?'Past meetings':'Upcoming and live meetings'}</h2>
      {meetings===null && <p>Loading meetings…</p>}
      {meetings&&requested&&id===requested&&!selected&&<p role="status">This meeting is unavailable to your account.</p>}
      {list?.length===0 && <p>{view==='past'?'No past meetings.':'No upcoming meetings.'}</p>}
      {list?.map(meeting=><div className="release-row" key={meeting.id}>
        <button className={id===meeting.id?'primary':'secondary'} onClick={()=>setId(meeting.id)}>{meeting.title}</button>
        <span className="pill">{meeting.status}</span><time dateTime={meeting.starts_at}>{new Date(meeting.starts_at).toLocaleString()}</time>
        {meeting.series_index&&<small>Occurrence {meeting.series_index} of {meeting.series_total}</small>}
      </div>)}
    </div>}
    {selected && <MeetingDetail key={selected.id} meeting={selected} user={user} mediaReady={ready}
      host={selected.host_id===user && canHost} bulkAdmit={workspace.policy?.bulk_admit!==false} refresh={reload}/>}
  </>
}

function MeetingDetail({meeting,user,mediaReady,host,bulkAdmit,refresh}: {
  meeting:Meeting;user:string;mediaReady:boolean;host:boolean;bulkAdmit:boolean;refresh:()=>Promise<void>
}) {
  const [people,setPeople]=useState<Attendance[]>([])
  const [profiles,setProfiles]=useState<Record<string,Profile>>({})
  const [error,setError]=useState('')
  const [busy,setBusy]=useState(false)
  const [media,setMedia]=useState<{url:string;token:string;choices:MeetingChoices}|null>(null)
  const [focus,setFocus]=useState<string|null>(null)
  const [lobbyNotice,setLobbyNotice]=useState('')
  const [calendarNotice,setCalendarNotice]=useState('')
  const [manualLink,setManualLink]=useState('')
  const reload=useCallback(async () => {
    const result=await db!.from('st_v3_attendance').select('*').eq('meeting_id',meeting.id).order('requested_at').limit(100)
    if(result.error) return
    const rows=result.data as Attendance[]
    setPeople(rows)
    if(!rows.find(row=>row.user_id===user && row.status==='admitted')) setMedia(null)
    const ids=rows.map(row=>row.user_id)
    if((host || rows.some(row=>row.user_id===user && row.status==='admitted' && row.is_cohost)) && ids.length) {
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
  const selfAttendance=people.find(row=>row.user_id===user)
  const self=selfAttendance?.status
  const ended=meeting.status==='ended'||Date.parse(meeting.ends_at)<=Date.now()
  const moderator=host || (self==='admitted' && selfAttendance?.is_cohost===true)
  const moderation=useMeetingModeration(meeting.id,()=>Promise.all([refresh(),reload()]))
  const actionBusy=busy||moderation.running

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
  async function requestMedia(networkCheck = false, signal?: AbortSignal) {
    const {data}=await db!.auth.getSession()
    const result=await fetch('/api/meetings/token',{method:'POST',signal,headers:{'Content-Type':'application/json',Authorization:'Bearer '+data.session?.access_token},body:JSON.stringify({meetingId:meeting.id,networkCheck})})
    const value=await result.json()
    if(!result.ok) throw new Error(value.error||'Could not join the call.')
    return value as {url:string;token:string}
  }
  async function connect(choices: MeetingChoices) {
    if(busy || !mediaReady) return
    setBusy(true);setError('')
    try {
      setMedia({...await requestMedia(),choices})
    } catch(error){setError(formatError(error,'Could not join the call.'))}
    finally{setBusy(false)}
  }
  const refreshMedia=useCallback(()=>setMedia(null),[])
  async function exportCalendar(series:boolean){
    setCalendarNotice('')
    try{
      let occurrences=[meeting]
      if(series&&meeting.series_id){
        const {data,error}=await db!.from('st_v3_meetings').select('*').eq('series_id',meeting.series_id)
          .neq('status','ended').order('series_index').limit(12)
        if(error||!data.length)throw new Error('Calendar export unavailable')
        occurrences=data as Meeting[]
      }
      const content=meetingCalendar(occurrences,window.location.origin)
      saveDownload(new Blob([content],{type:'text/calendar;charset=utf-8'}),series?'sectalk-meeting-series.ics':'sectalk-meeting.ics')
    }catch{setCalendarNotice('Could not export the meeting calendar.')}
  }
  async function copyLink(){
    const link=meetingLink(window.location.origin,meeting.id)
    try{await navigator.clipboard.writeText(link);setCalendarNotice('Join link copied.')}
    catch{setManualLink(link)}
  }
  return <div className="panel release-panel">
    <div className="release-row"><h2>{meeting.title}</h2><span className="pill">{ended?'ended':meeting.status}</span></div>
    {meeting.agenda&&<p className="meeting-agenda">{meeting.agenda}</p>}
    {error&&<p role="alert" className="error">{error}</p>}
    {moderation.error&&<p role="alert" className="error">{moderation.error}</p>}
    {moderation.notice&&<p role="status">{moderation.notice}</p>}
    {!ended&&<div className="release-row">
      <button type="button" className="secondary" onClick={()=>void exportCalendar(false)}>Add to calendar</button>
      {meeting.series_id&&<button type="button" className="secondary" onClick={()=>void exportCalendar(true)}>Add series to calendar</button>}
      <button type="button" className="secondary" onClick={()=>void copyLink()}>Copy join link</button>
    </div>}
    {calendarNotice&&<p role="status">{calendarNotice}</p>}
    {manualLink&&<label>Meeting link<input readOnly value={manualLink} onFocus={event=>event.target.select()}/></label>}
    {!ended && <div className="release-row">
      {host && meeting.status==='scheduled' && <button className="primary" disabled={busy} onClick={()=>void action('st_v3_meeting_state',{p_state:'live'})}>Open waiting room</button>}
      {moderator && meeting.status==='live' && <button className="danger" disabled={actionBusy} onClick={()=>{if(window.confirm('End this meeting for everyone?')) void moderation.act('end')}}>End meeting</button>}
      {(!host || meeting.status==='live') && (!self||self==='left') && <button className="secondary" disabled={actionBusy||(!host&&meeting.meeting_locked)} onClick={()=>void action('st_v3_request_admission',{})}>{host?'Rejoin meeting':'Request admission'}</button>}
      {self==='waiting' && <span role="status">Waiting for the host to admit you</span>}
      {self==='declined' && <span role="status">{selfAttendance?.removed_at?'A moderator removed you from the meeting.':'The host declined your request'}</span>}
      {meeting.meeting_locked && <span className="pill" role="status">Meeting locked</span>}
      {self==='admitted' && meeting.status==='live' && !mediaReady && <span role="status">Live media unavailable</span>}
      {(self==='admitted'||self==='waiting') && <button className="secondary" disabled={busy} onClick={()=>{setMedia(null);void action('st_v3_leave',{})}}>Leave</button>}
    </div>}
    {moderator && meeting.status==='live' && !ended &&
      <MeetingModeratorActions locked={meeting.meeting_locked} chatDisabled={meeting.chat_disabled} shareDisabled={meeting.screen_share_disabled}
        busy={actionBusy} moderate={moderation.act}/>}
    {self==='admitted' && meeting.status==='live' && !ended && mediaReady && !media &&
      <MeetingPrejoin busy={busy} join={connect} requestMedia={requestMedia}/>}
    <MeetingRecording meeting={meeting.id} workspace={meeting.workspace_id} ended={ended}/>
    {ended && <MeetingCaptions meeting={meeting.id} ended/>}
    <MeetingSummary meeting={meeting.id}/>
    {host && <MeetingGuestHost meeting={meeting.id} locked={meeting.meeting_locked}/>}
    {media && self==='admitted' && !ended && <MeetingMedia {...media} meeting={meeting.id} focus={focus}
      screenShareDisabled={meeting.screen_share_disabled} leave={refreshMedia}/>}
    {self==='admitted'&&meeting.status==='live'&&!ended&&<>
      <MeetingCollaboration meeting={meeting.id} user={user} host={host} chatDisabled={meeting.chat_disabled} setFocus={setFocus}/>
      <MeetingEngagement meeting={meeting.id} user={user}/>
    </>}
    {moderator && <section className="release-section" aria-label="Waiting room and attendance"><h2>Waiting room and attendance</h2>
      {host&&bulkAdmit&&meeting.status==='live'&&!ended&&people.some(person=>person.status==='waiting')&&
        <button className="primary" type="button" disabled={actionBusy||meeting.meeting_locked} onClick={()=>void action('st_v6_admit_all',{})}>Admit all eligible attendees</button>}
      {lobbyNotice&&<p role="status">{lobbyNotice}</p>}
      {!people.length&&<p>No attendees yet.</p>}
      {people.map(person=><div className="release-row" key={person.user_id}><strong>{profiles[person.user_id]?.name||'Workspace member'}</strong><span className="pill">{person.status}</span>
        {person.is_cohost&&<span className="pill">Co-host</span>}
        {person.admitted_at&&<time dateTime={person.admitted_at}>{new Date(person.admitted_at).toLocaleString()}</time>}
        {host&&person.status==='waiting'&&meeting.status==='live'&&!ended&&<>
          <button className="primary" disabled={actionBusy||meeting.meeting_locked} onClick={()=>void action('st_v3_admit',{p_user:person.user_id,p_allow:true})}>Admit</button>
          <button className="secondary" disabled={actionBusy} onClick={()=>void action('st_v3_admit',{p_user:person.user_id,p_allow:false})}>Decline</button>
        </>}
        {person.status==='admitted'&&!ended&&person.user_id!==user&&person.user_id!==meeting.host_id&&(host||!person.is_cohost)&&
          <MeetingParticipantModeration participant={person.user_id} name={profiles[person.user_id]?.name||'Workspace member'}
            cohost={person.is_cohost} organizer={host} busy={actionBusy} moderate={moderation.act}/>}
      </div>)}
    </section>}
  </div>
}
