'use client'

import {useCallback,useEffect,useRef,useState,type FormEvent} from 'react'
import {db,formatError} from '../lib/data'
import {WorkspaceResidencySourceReceipt} from './workspace-residency-source-receipt'
import {WorkspaceResidencySourceCoverage} from './workspace-residency-source-coverage'
import {isFreeRelease} from '../lib/release-scope'

type Status={role:'owner'|'reviewer';id:string|null;records:number|null;manifestSha256:string|null;expiresAt:string|null;
  includesFiles:boolean;includesRoomFiles:boolean}
type PreparedFile={file:string;filename:string;bytes:number;room?:string;roomKind?:string;classification?:string}

export function WorkspaceContentExport({workspace,storagePlan,onStorageCopy}:{workspace:string;storagePlan?:string;onStorageCopy?:()=>void}) {
  const [status,setStatus]=useState<Status>()
  const [error,setError]=useState('')
  const [copyNotice,setCopyNotice]=useState('')
  const [cursor,setCursor]=useState<number|null>(0)
  const [busy,setBusy]=useState(false)
  const [files,setFiles]=useState<PreparedFile[]>([])
  const pending=useRef<string|undefined>(undefined)
  const load=useCallback(async()=>{
    const result=await db!.rpc('st_v8_offboarding_content',{p_workspace:workspace})
    if(!result.error)setStatus(result.data)
  },[workspace])
  useEffect(()=>{void load()},[load])

  async function run(action:string,confirmation:string) {
    setBusy(true);setError('')
    try {
      const request=['export_content','export_content_files','export_content_room_files','export_content_all_files'].includes(action)
      if(request&&!pending.current)pending.current=crypto.randomUUID()
      const result=await db!.rpc('st_v8_offboarding_content',{p_workspace:workspace,p_action:action,
        p_id:request?pending.current:status?.id,p_confirmation:confirmation,p_after:cursor??0})
      if(result.error)throw result.error
      if(action==='page') {
        const url=URL.createObjectURL(new Blob([JSON.stringify(result.data)],{type:'application/json'}))
        const link=document.createElement('a')
        link.href=url;link.download='sectalk-content-page-'+((cursor??0)/25+1)+'.json';link.click()
        window.setTimeout(()=>URL.revokeObjectURL(url),1000)
        setFiles(result.data.records.filter((row:{kind:string})=>row.kind==='workspace_file'||row.kind==='room_file')
          .map((row:{json:string})=>JSON.parse(row.json) as PreparedFile))
        setCursor(result.data.next)
      } else {
        pending.current=undefined
        setCursor(0)
        setFiles([])
        await load()
      }
    } catch(cause) {setError(formatError(cause,'Content export unavailable.'))}
    finally {setBusy(false)}
  }
  async function downloadFile(file:PreparedFile,verifyStorageCopy=false) {
    setBusy(true);setError('');setCopyNotice('')
    try {
      const {data}=await db!.auth.getSession()
      if(!data.session||!status?.id)throw new Error('Sign in again to download this file.')
      const query=new URLSearchParams({file:file.file,offboarding:status.id})
      query.set(file.room?'room':'workspace',file.room??workspace)
      if(verifyStorageCopy&&storagePlan)query.set('offboarding-storage-plan',storagePlan)
      const path=file.room?'/api/room-files?':'/api/workspace-files?'
      const response=await fetch(path+query,{headers:{Authorization:'Bearer '+data.session.access_token}})
      if(!response.ok)throw new Error('This approved file version is unavailable.')
      const receipt=response.headers.get('X-SecTalk-Storage-Copy-Receipt')
      if(verifyStorageCopy&&!receipt)throw new Error('The approved Storage copy could not be verified.')
      const content=await response.blob()
      if(content.size!==file.bytes)throw new Error('The approved file size did not match.')
      const url=URL.createObjectURL(content)
      const link=document.createElement('a')
      link.href=url;link.download=file.filename;link.click()
      window.setTimeout(()=>URL.revokeObjectURL(url),1000)
      if(receipt){setCopyNotice('Exact Storage copy verified and issued.');onStorageCopy?.()}
    } catch(cause) {setError(formatError(cause,'Approved file download is unavailable.'))}
    finally {setBusy(false)}
  }
  function form(action:string,label:string) {
    return <form className="release-form" onSubmit={(event:FormEvent<HTMLFormElement>)=>{
      event.preventDefault()
      void run(action,String(new FormData(event.currentTarget).get('workspace')??'').trim())
    }}>
      <label>{action==='export_content_files'?'Confirm workspace ID for file export':
        action==='export_content_room_files'?'Confirm workspace ID for room file export':
        action==='export_content_all_files'?'Confirm workspace ID for combined file export':'Confirm content export workspace ID'}
        <input name="workspace" required maxLength={36} autoComplete="off"/></label>
      <button className="secondary" disabled={busy}>{label}</button>
    </form>
  }
  if(!status)return null
  const expired=Boolean(status.expiresAt&&Date.parse(status.expiresAt)<=Date.now())
  return <section aria-label="Workspace content export">
    <h4>Workspace content export</h4>
    <p>Separate approval authorizes up to 500 eligible records. Choose workspace files, room files, or both. Both participants need current source access. In a standard private room, only files uploaded by one of the two approving participants are eligible.</p>
    <p>Confirm workspace <code>{workspace}</code>.</p>
    {error&&<p role="alert">{error}</p>}
    {copyNotice&&<p role="status">{copyNotice}</p>}
    {!status.id&&status.role==='owner'&&form('export_content','Request separate content approval')}
    {!status.id&&status.role==='owner'&&form('export_content_files','Request content and workspace file approval')}
    {!status.id&&status.role==='owner'&&form('export_content_room_files','Request content and room file approval')}
    {!status.id&&status.role==='owner'&&form('export_content_all_files','Request content and both file scopes')}
    {status.id&&status.records===null&&<p>Awaiting independent content approval.</p>}
    {status.id&&status.includesFiles&&<p>This request includes eligible workspace files.</p>}
    {status.id&&status.includesRoomFiles&&<p>This request includes eligible standard room files.</p>}
    {status.id&&status.records===null&&status.role==='reviewer'&&form('approve','Approve exact content revisions')}
    {status.records!==null&&<p>{status.records} approved records · Manifest SHA-256 <code>{status.manifestSha256}</code></p>}
    {!isFreeRelease&&status.id&&status.records!==null&&!expired&&<WorkspaceResidencySourceReceipt key={status.id} workspace={workspace} approval={status.id}/>}
    {!isFreeRelease&&status.id&&status.records!==null&&!expired&&<WorkspaceResidencySourceCoverage key={'coverage:'+status.id} workspace={workspace} approval={status.id}/>}
    {expired&&<p>Content approval has expired.</p>}
    {status.id&&status.records!==null&&!expired&&status.role==='owner'&&cursor!==null&&
      <button type="button" disabled={busy} onClick={()=>void run('page',workspace)}>Download next content page</button>}
    {cursor===null&&<button type="button" onClick={()=>setCursor(0)}>Restart content downloads</button>}
    {!expired&&files.length>0&&<ul aria-label="Approved files on this page">{files.map(file=><li key={(file.room??workspace)+':'+file.file}>
      <button type="button" disabled={busy} onClick={()=>void downloadFile(file)}>Download {file.filename}</button>
      {storagePlan&&(!file.room||(file.roomKind==='public'&&['public','internal'].includes(file.classification??'')))&&
        <button type="button" disabled={busy} onClick={()=>void downloadFile(file,true)}>Verify and download {file.filename}</button>}
    </li>)}</ul>}
    {status.id&&status.role==='owner'&&form('withdraw','Withdraw content approval')}
    <button type="button" disabled={busy} onClick={()=>void load()}>Refresh content approval</button>
  </section>
}
