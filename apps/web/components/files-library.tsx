'use client'

import { useCallback, useEffect, useState } from 'react'
import { Download, Folder, RefreshCw } from 'lucide-react'
import { db } from '../lib/data'
import { downloadChatFile, downloadName, fetchChatFile, saveDownload, type ChatFile } from '../lib/chat-files'
import { SectionTabs } from './section-tabs'
import { Vault } from './vault'
import { AttachmentDetails } from './attachment-details'

type LibraryFile=ChatFile & {message_id:string;chat_id:string;created_at:string}
const pageSize=25
const selectedLimit=8
const sizeLimit=20*1024*1024
const sortFields={recent:'created_at',name:'filename',size:'size_bytes'} as const

export function FilesLibrary({user,openChat}: {user:string;openChat:(id:string)=>void}) {
  const [view,setView]=useState<'chat'|'vault'>('chat')
  return <>
    <div className="content-page files-library">
      <header className="content-title"><div className="card-icon"><Folder size={22}/></div>
        <div><h1>Files</h1><p>Find chat attachments or open your private vault.</p></div></header>
      <SectionTabs label="File sections" value={view} onChange={setView} options={[
        ['chat','Chat files'],['vault','Private vault'],
      ]}/>
      {view==='chat'?<ChatLibrary openChat={openChat}/>:<Vault user={user} embedded/>}
    </div>
  </>
}

function ChatLibrary({openChat}: {openChat:(id:string)=>void}) {
  const [rows,setRows]=useState<LibraryFile[]|null>(null)
  const [selection,setSelection]=useState<string[]>([])
  const [page,setPage]=useState(0)
  const [hasMore,setHasMore]=useState(false)
  const [sort,setSort]=useState<keyof typeof sortFields>('recent')
  const [direction,setDirection]=useState<'all'|'sent'|'received'>('all')
  const [filter,setFilter]=useState('')
  const [query,setQuery]=useState('')
  const [busy,setBusy]=useState(false)
  const [error,setError]=useState('')
  const [loadedCriteria,setLoadedCriteria]=useState('')
  const [detailFile,setDetailFile]=useState<string|null>(null)

  const criteria=JSON.stringify([page,sort,direction,query])
  const load=useCallback(async (alive:()=>boolean=()=>true)=>{
    const auth=await db!.auth.getUser()
    if(!alive()) return
    if(!auth.data.user){setError('Sign in to view chat files.');return}
    let list=db!.from('st_v5_files').select('id,message_id,chat_id,filename,size_bytes,created_at').not('message_id','is',null)
    if(direction!=='all') list=direction==='sent'?list.eq('uploader',auth.data.user.id):list.neq('uploader',auth.data.user.id)
    if(query) list=list.ilike('filename','%'+query.replace(/[\\%_*]/g,'\\$&')+'%')
    const result=await list.order(sortFields[sort],{ascending:sort==='name'}).order('id')
      .range(page*pageSize,(page+1)*pageSize).returns<LibraryFile[]>()
    if(!alive())return
    if(result.error){setError('Could not load chat files.');return}
    const removed=result.data.length?await db!.from('st_v5_hidden_messages').select('message_id').in('message_id',result.data.map(file=>file.message_id)):null
    if(!alive())return
    if(removed?.error){setError('Could not check file visibility.');return}
    const hidden=new Set(removed?.data?.map(row=>row.message_id))
    setRows(result.data.slice(0,pageSize).filter(file=>!hidden.has(file.message_id)))
    setHasMore(result.data.length>pageSize)
    setLoadedCriteria(criteria)
    setSelection([])
    setError('')
  },[criteria,direction,page,query,sort])
  useEffect(()=>{
    let active=true
    void load(()=>active)
    return ()=>{active=false}
  },[load])
  const visible=criteria===loadedCriteria?rows:null
  const selected=visible?.filter(file=>selection.includes(file.id))||[]

  async function downloadSelected() {
    if(busy||!selected.length)return
    if(selected.reduce((total,file)=>total+file.size_bytes,0)>sizeLimit){setError('Select up to 20 MiB per download.');return}
    setBusy(true);setError('')
    try{
      const [{zipSync},...objects]=await Promise.all([import('fflate'),...selected.map(file=>fetchChatFile(file.id))])
      const entries=await Promise.all(objects.map(async (object,index)=>[
        String(index+1).padStart(2,'0')+'-'+downloadName(selected[index].filename),new Uint8Array(await object.arrayBuffer()),
      ] as const))
      const zip=zipSync(Object.fromEntries(entries),{level:0})
      saveDownload(new Blob([Uint8Array.from(zip)],{type:'application/zip'}),'sectalk-files.zip')
    }catch{setError('The download could not finish. A file may have been revoked.')}
    finally{setBusy(false)}
  }

  return <section aria-label="Chat files" className="release-section">
    <form className="release-flex" onSubmit={event=>{event.preventDefault();setPage(0);setQuery(filter.trim())}}>
      <label>Filename<input type="search" maxLength={100} value={filter} onChange={event=>setFilter(event.target.value)}/></label>
      <button type="submit" className="secondary">Search</button>
      <label>Direction<select value={direction} onChange={event=>{setPage(0);setDirection(event.target.value as typeof direction)}}>
        <option value="all">All chat files</option><option value="sent">Sent</option><option value="received">Received</option>
      </select></label>
      <label>Sort<select value={sort} onChange={event=>{setPage(0);setSort(event.target.value as typeof sort)}}>
        <option value="recent">Newest first</option><option value="name">Filename A–Z</option><option value="size">Largest first</option>
      </select></label>
      <button type="button" className="secondary" onClick={()=>void load()} disabled={busy}><RefreshCw size={15}/> Refresh</button>
    </form>
    {error&&<p className="error" role="alert">{error}</p>}
    {!visible&&!error&&<p role="status">Loading attachments…</p>}
    {visible?.length===0&&<p>No visible attachments match this page.</p>}
    <button type="button" className="primary" disabled={busy||selected.length===0} onClick={()=>void downloadSelected()}>
      <Download size={16}/> Download selected {selected.length>0&&'('+selected.length+')'}
    </button>
    {visible?.map(file=><div className="release-row" key={file.id}>
      <label className="task-check"><input type="checkbox" disabled={busy||(!selection.includes(file.id)&&selection.length>=selectedLimit)}
        checked={selection.includes(file.id)} onChange={event=>setSelection(previous=>event.target.checked?[...previous,file.id]:previous.filter(id=>id!==file.id))}/>
        {file.filename}</label>
      <span className="pill">{Math.ceil(file.size_bytes/1024)} KiB</span>
      <button type="button" className="secondary" onClick={()=>openChat(file.chat_id)}>Open conversation</button>
      <button type="button" className="secondary" onClick={()=>setDetailFile(file.id)}>View details</button>
      <button type="button" className="secondary" disabled={busy} onClick={async()=>{
        setError('')
        try{await downloadChatFile(file)}catch{setError('The attachment could not be downloaded.')}
      }}>Download</button>
    </div>)}
    {(page>0||hasMore)&&<div className="pagination">
      <button className="secondary" type="button" disabled={page===0||busy||!visible} onClick={()=>setPage(page-1)}>Previous</button>
      <span>Page {page+1}</span>
      <button className="secondary" type="button" disabled={!hasMore||busy||!visible} onClick={()=>setPage(page+1)}>Next</button>
    </div>}
    {detailFile && <AttachmentDetails key={detailFile} file={detailFile} close={()=>setDetailFile(null)}/>}
  </section>
}
