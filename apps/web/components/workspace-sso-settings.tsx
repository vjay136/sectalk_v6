'use client'

import { useCallback,useEffect,useState,type FormEvent } from 'react'
import { db,formatError } from '../lib/data'
import { StaffMfa } from './staff-mfa'

type Setup={domain:string;protocol:'oidc'|'saml';jit:boolean;available:boolean}
type State={access:'none'|'mfa'|'upgrade'}|{access:'verified';setup:Setup|null}

export function WorkspaceSsoSettings({workspace,onManageDomains}:{workspace:string;onManageDomains:()=>void}){
  const [state,setState]=useState<State>()
  const [domains,setDomains]=useState<string[]>()
  const [busy,setBusy]=useState(false)
  const [notice,setNotice]=useState('')
  const [error,setError]=useState('')
  const load=useCallback(async(signal?:AbortSignal)=>{
    const request=db!.rpc('st_v7_workspace_sso_settings',{p_workspace:workspace})
    const result=await (signal?request.abortSignal(signal):request)
    if(signal?.aborted)return
    if(result.error){setError('Workspace sign-in settings are unavailable.');return}
    const next=result.data as State
    setState(next)
    if(next.access!=='verified')return
    const directory=db!.rpc('st_v7_org_settings',{p_workspace:workspace})
    const available=await (signal?directory.abortSignal(signal):directory)
    if(signal?.aborted)return
    if(available.error){setError('Could not read verified domains.');return}
    const verified=(available.data.domains as {domain:string;verifiedAt:string|null}[])
      .filter(domain=>domain.verifiedAt).map(domain=>domain.domain)
    setDomains(verified)
  },[workspace])
  useEffect(()=>{
    const controller=new AbortController()
    void load(controller.signal)
    return()=>controller.abort()
  },[load])
  async function update(action:'save'|'remove',extra?:Record<string,unknown>){
    if(busy)return
    setBusy(true);setNotice('');setError('')
    try{
      const result=await db!.rpc('st_v7_workspace_sso_settings',{p_workspace:workspace,p_action:action,...extra})
      if(result.error)throw result.error
      setState(result.data as State)
      if(result.data.access==='verified')setNotice(action==='save'?'Workspace sign-in configured.':'Workspace sign-in removed.')
    }catch(cause){setError(formatError(cause,'Could not update workspace sign-in.'))}
    finally{setBusy(false)}
  }
  function save(event:FormEvent<HTMLFormElement>){
    event.preventDefault()
    const fields=new FormData(event.currentTarget)
    void update('save',{p_domain:fields.get('domain'),p_protocol:fields.get('protocol'),p_jit:fields.has('jit')})
  }
  const selection=state?.access==='verified'?state.setup:null
  return <section className="release-section" aria-label="Enterprise workspace sign-in">
    <h3>Enterprise workspace SSO</h3>
    <p>Connect a verified domain to an approved SAML or OpenID Connect provider. Existing SecTalk sign-in methods remain available.</p>
    {!state&&!error&&<p role="status">Checking single sign-on access…</p>}
    {state?.access==='mfa'&&<StaffMfa refresh={load} explanation="Verify your authenticator to configure enterprise sign-in."/>}
    {state?.access==='none'&&<p>Workspace sign-in settings are unavailable.</p>}
    {state?.access==='upgrade'&&<p>Enterprise SSO requires an Enterprise workspace.</p>}
    {state?.access==='verified'&&<>
      {selection&&<p role="status">{selection.domain} · {selection.protocol==='saml'?'SAML':'OIDC'} · {selection.available?'Configured':'Provider unavailable'}</p>}
      {domains&&domains.length>0?<form className="release-form" key={selection?.domain+'|'+selection?.protocol+'|'+selection?.jit} onSubmit={save}>
        <label>Verified domain<select name="domain" required defaultValue={selection?.domain??''}>
          <option value="">Select a verified domain</option>{domains.map(domain=><option key={domain} value={domain}>{domain}</option>)}
        </select></label>
        <label>Identity provider type<select name="protocol" defaultValue={selection?.protocol??'saml'}>
          <option value="saml">SAML</option><option value="oidc">OpenID Connect</option>
        </select></label>
        <label><input type="checkbox" name="jit" defaultChecked={selection?.jit}/> Admit new verified domain users as ordinary members</label>
        <p>SecTalk uses the provider configured by your operator. Accounts are matched by their Auth identity. Email addresses alone never merge accounts.</p>
        <button className="primary" disabled={busy}>Save workspace sign-in</button>
      </form>:domains&&<p>Verify a domain before configuring a provider.</p>}
      <button type="button" className="secondary" onClick={onManageDomains}>Manage verified domains</button>
      {selection&&<button type="button" className="secondary" disabled={busy} onClick={()=>void update('remove')}>Disconnect workspace SSO</button>}
    </>}
    {notice&&<p role="status">{notice}</p>}
    {error&&<p role="alert">{error}</p>}
  </section>
}
