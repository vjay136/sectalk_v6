'use client'

import {useCallback,useEffect,useState,type FormEvent} from 'react'
import {verifyAccountCredential} from '../lib/account-credential'
import {db,formatError} from '../lib/data'
import {workspaceFileRequest} from '../lib/workspace-files-client'

type ManifestState={
  state:'inactive'|'admission_required'|'review_required'|'ready'|'received'
  side?:'source'|'destination'
  digest?:string
  packetSha256?:string
  receivedAt?:string
  changeCount?:number
  packet?:{payload:string;signature:string}
}

export function WorkspaceResidencyRollbackManifest({workspace}:{workspace:string}) {
  const [manifest,setManifest]=useState<ManifestState>()
  const [busy,setBusy]=useState(false)
  const [error,setError]=useState('')
  const [issued,setIssued]=useState(false)
  const [staged,setStaged]=useState('')
  const refresh=useCallback(async (signal?:AbortSignal)=>{
    const query=db!.rpc('st_v8_residency_rollback_manifest',{p_workspace:workspace})
    const result=await (signal?query.abortSignal(signal):query)
    if(!signal?.aborted&&!result.error)setManifest(result.data as ManifestState)
  },[workspace])

  useEffect(()=>{
    const controller=new AbortController()
    void refresh(controller.signal)
    return ()=>controller.abort()
  },[refresh])

  async function verifyCredential(values:FormData) {
    const assurance=await db!.rpc('st_v7_sensitive_action_status',{p_kind:'room_role'})
    if(assurance.error)throw assurance.error
    if(assurance.data!=='verified'){
      const code=String(values.get('code')||'')
      if(!code)throw new Error('Enter a current authenticator code.')
      await verifyAccountCredential(code,true)
    }
  }

  async function stageFile(event:FormEvent<HTMLFormElement>) {
    event.preventDefault()
    if(busy||manifest?.state!=='received'||manifest.side!=='source')return
    const form=event.currentTarget
    const values=new FormData(form)
    setBusy(true);setError('');setStaged('')
    try {
      const packageFile=values.get('recovery-file')
      if(!(packageFile instanceof File)||!packageFile.size||packageFile.size>5600000){
        throw new Error('Choose a signed recovery file package containing a file up to 4 MiB.')
      }
      let file:File
      let id:string
      let rollbackProof:string
      try {
        const copy=JSON.parse(await packageFile.text())
        if(copy?.format!=='sectalk-residency-file-copy-v1'||typeof copy.contentBase64!=='string'||
          typeof copy.proof?.payload!=='string'||typeof copy.proof.signature!=='string')throw new Error()
        const proofBytes=new TextEncoder().encode(JSON.stringify({payload:copy.proof.payload,signature:copy.proof.signature}))
        if(proofBytes.length>4096)throw new Error()
        const claim=JSON.parse(copy.proof.payload)
        if(claim.workspace!==workspace||typeof claim.file!=='string'||
          !/^[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}$/.test(claim.file))throw new Error()
        const bytes=Uint8Array.from(atob(copy.contentBase64),char=>char.charCodeAt(0))
        if(!bytes.length||bytes.length>4194304)throw new Error()
        id=claim.file
        file=new File([bytes],'recovery-copy',{type:'application/octet-stream'})
        rollbackProof=btoa(String.fromCharCode(...proofBytes)).replaceAll('+','-').replaceAll('/','_').replace(/=+$/,'')
      } catch { throw new Error('Choose a valid signed recovery file package for this workspace.') }
      await verifyCredential(values)
      const result=await workspaceFileRequest(workspace,'POST',{id,file,rollbackProof})
      const receipt=await result.json()
      if(receipt.state!=='staged'||receipt.file!==id)throw new Error('The recovery copy could not be verified in private staging.')
      form.reset()
      setStaged(id)
    } catch(cause){setError(formatError(cause,'Could not stage the rollback file.'))}
    finally{setBusy(false)}
  }

  async function transfer(event:FormEvent<HTMLFormElement>){
    event.preventDefault()
    if(busy||manifest?.state!=='ready')return
    const form=event.currentTarget
    const values=new FormData(form)
    const confirmation=String(values.get('workspace')||'')
    const issue=manifest.side==='destination'
    setBusy(true);setError('');setIssued(false)
    try {
      if(confirmation!==workspace)throw new Error('Enter the exact workspace ID shown above.')
      let packet
      if(!issue){
        const file=values.get('manifest')
        if(!(file instanceof File)||!file.size||file.size>4194304)throw new Error('Choose the signed manifest JSON file, up to 4 MB.')
        try{packet=JSON.parse(await file.text())}catch{throw new Error('Choose a valid signed manifest JSON file.')}
      }
      await verifyCredential(values)
      const result=await db!.rpc('st_v8_residency_rollback_manifest',{
        p_workspace:workspace,p_action:issue?'issue':'receive',p_confirmation:confirmation,p_packet:packet,
      })
      if(result.error)throw result.error
      const next=result.data as ManifestState
      if(issue&&next.packet){
        const url=URL.createObjectURL(new Blob([JSON.stringify(next.packet)],{type:'application/json'}))
        const link=document.createElement('a')
        link.href=url
        link.download='sectalk-rollback-manifest-'+workspace+'.json'
        link.click()
        window.setTimeout(()=>URL.revokeObjectURL(url),1000)
        setIssued(true)
      }else setManifest(next)
      form.reset()
    } catch(cause){setError(formatError(cause,'Could not transfer the rollback manifest.'))}
    finally{setBusy(false)}
  }

  if(!manifest||manifest.state==='inactive')return null
  const destination=manifest.side==='destination'
  return <section className="release-section" aria-label="Rollback recovery manifest">
    <h4>Rollback recovery manifest</h4>
    {manifest.state==='admission_required'&&<p role="status">An approved recovery plan and transfer credential are required.</p>}
    {manifest.state==='review_required'&&<p role="status">The destination needs a current independent change review.</p>}
    {manifest.state==='received'&&<>
      <p role="status">The source verified the recovery manifest. Workspace writes remain held.</p>
      <p>{manifest.changeCount} reviewed {manifest.changeCount===1?'change':'changes'} · Review digest <code>{manifest.digest}</code></p>
      <p>Transfer digest <code>{manifest.packetSha256}</code></p>
      {!destination&&<form className="release-form" onSubmit={event=>void stageFile(event)}>
        <p>Stage a reviewed workspace file copy within five minutes of downloading it. Staged files stay private while rollback review continues.</p>
        <label>Signed recovery file<input name="recovery-file" type="file" accept=".json,application/json" required disabled={busy}/></label>
        <label>Authenticator code for file staging if prompted<input name="code" inputMode="numeric" autoComplete="one-time-code" pattern="[0-9]{6}" disabled={busy}/></label>
        <button className="secondary" type="submit" disabled={busy}>Stage reviewed file copy</button>
      </form>}
      {staged&&<p role="status">File copy <code>{staged}</code> was staged in private storage. Workspace writes remain held.</p>}
    </>}
    {manifest.state==='ready'&&<form className="release-form" onSubmit={event=>void transfer(event)}>
      <p>{destination?'Download the signed manifest and transfer it to the source owner within five minutes.':
        'Choose the signed manifest from the reviewed destination. Verification records the evidence while source writes stay held.'}</p>
      <p>Workspace ID <code>{workspace}</code></p>
      <label>Confirm recovery manifest workspace ID<input name="workspace" autoComplete="off" required disabled={busy}/></label>
      {!destination&&<label>Signed manifest file<input name="manifest" type="file" accept=".json,application/json" required disabled={busy}/></label>}
      <label>Authenticator code if prompted<input name="code" inputMode="numeric" autoComplete="one-time-code" pattern="[0-9]{6}" disabled={busy}/></label>
      <button className="secondary" type="submit" disabled={busy}>{destination?'Download recovery manifest':'Verify recovery manifest'}</button>
    </form>}
    {issued&&<p role="status">The signed recovery manifest was prepared for download.</p>}
    {manifest.state!=='received'&&<button className="secondary" disabled={busy} onClick={()=>void refresh()}>Refresh manifest status</button>}
    {error&&<p role="alert">{error}</p>}
  </section>
}
