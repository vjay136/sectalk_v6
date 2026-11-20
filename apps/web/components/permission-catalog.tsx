'use client'

import {useEffect,useState} from 'react'
import {db} from '../lib/data'

type Decision='allowed'|'verification_required'|'not_allowed'|'plan_required'
type Scope={id:string;name:string}
type Catalog={
  workspaces:Scope[];rooms:Scope[];workspace_role:string|null;room_role:string|null;operator_role:string|null
  workspace:Record<string,Decision>;room:Record<string,Decision>;platform:Record<string,Decision>
}

const names:Record<string,string>={
  'workspace.member.read':'Manage the workspace directory',
  'admin.user.suspend':'Suspend or restore eligible workspace members',
  'admin.user.role.write':'Change workspace roles',
  'audit.log.read':'Read the workspace audit log',
  'integration.key.manage':'Manage workspace integration keys',
  'compliance.export.request':'Request a compliance export',
  'compliance.export.review':'Review another administrator’s export request',
  'messaging.message.send':'Post in the room',
  'room.reaction.add':'React in the room',
  'room.mention.all':'Mention the entire room',
  'room.member.remove':'Remove eligible room members',
  'room.permission.write':'Change permissions for the room member role',
  'soc.queue.read':'Read the platform moderation queue',
  'platform.account.read':'Read permitted account metadata',
  'platform.session.revoke':'End an eligible account session',
  'platform.recovery.review':'Review a recovery request independently',
}
const decisions:Record<Decision,string>={
  allowed:'Allowed for this role',
  verification_required:'Fresh security verification required',
  not_allowed:'Unavailable for this role or scope',
  plan_required:'Requires an eligible workspace plan',
}

function Actions({value}:{value:Record<string,Decision>}) {
  return <dl>{Object.entries(value).map(([action,decision])=><div className="release-row" key={action}>
    <dt>{names[action]??action}</dt><dd>{decisions[decision]}</dd>
  </div>)}</dl>
}

export function PermissionCatalog() {
  const [open,setOpen]=useState(false)
  const [workspace,setWorkspace]=useState('')
  const [room,setRoom]=useState('')
  const [result,setResult]=useState<{workspace:string;room:string;catalog:Catalog|null}|null>(null)
  const [revision,setRevision]=useState(0)
  useEffect(()=>{
    if(!open) return
    const controller=new AbortController()
    void db!.rpc('st_v7_permission_catalog',{p_workspace:workspace||null,p_room:room||null})
      .abortSignal(controller.signal).then(response=>{
        if(!controller.signal.aborted)setResult({workspace,room,catalog:response.error?null:response.data})
      })
    return ()=>controller.abort()
  },[open,workspace,room,revision])
  const current=result?.workspace===workspace&&result.room===room?result:null
  const catalog=current?.catalog
  const options=result?.catalog
  return <section className="panel mfa-panel" aria-label="Permission catalog">
    <h2>Permission catalog</h2>
    <button type="button" className="secondary" aria-expanded={open} onClick={()=>setOpen(!open)}>
      {open?'Hide my permissions':'View my permissions'}
    </button>
    {open&&<>
      <p>Review the actions your current roles allow. Individual actions also check the selected record and its policy.</p>
      <button type="button" className="secondary" onClick={()=>setRevision(value=>value+1)}>Refresh permissions</button>
      {options&&<label>Workspace for permissions<select value={workspace} onChange={event=>{
        setWorkspace(event.target.value);setRoom('')
      }}><option value="">Choose a workspace</option>{options.workspaces.map(item=>
        <option key={item.id} value={item.id}>{item.name}</option>)}</select></label>}
      {workspace&&options?.rooms.length!==0&&<label>Room for permissions<select value={room} onChange={event=>setRoom(event.target.value)}>
        <option value="">Choose a room</option>{options?.rooms.map(item=><option key={item.id} value={item.id}>{item.name}</option>)}
      </select></label>}
      {!current&&<p role="status">Checking permissions…</p>}
      {current&&!catalog&&<p role="alert">Could not load your permissions. Verify your session and try again.</p>}
      {catalog&&<>
        {catalog.workspace_role&&<section aria-label="Workspace permissions">
          <h3>Workspace role: {catalog.workspace_role}</h3>
          <Actions value={catalog.workspace}/>
          {catalog.workspace_role==='owner'&&<a href="/siem">SIEM exports</a>}
        </section>}
        {Object.keys(catalog.room).length>0&&<section aria-label="Room permissions">
          <h3>Room role: {catalog.room_role?.replaceAll('_',' ')??'No room membership'}</h3>
          <Actions value={catalog.room}/>
        </section>}
        <section aria-label="Platform permissions">
          <h3>{catalog.operator_role? 'Platform account '+catalog.operator_role:'Platform access'}</h3>
          <Actions value={catalog.platform}/>
        </section>
      </>}
    </>}
  </section>
}
