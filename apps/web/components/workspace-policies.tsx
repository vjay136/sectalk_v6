'use client'

import { useEffect, useState, type FormEvent } from 'react'
import { db, formatError } from '../lib/data'
import { SectionTabs } from './section-tabs'
import { StaffMfa } from './staff-mfa'

type Value = string | number | boolean | string[] | null
type Settings = Record<string, Value>
type Field = { key: string; name: string; options?: Array<[string,string]>; min?: number; max?: number; toggle?: boolean; domains?: boolean }
type Domain = 'messaging'|'files'|'calls'|'ai'|'retention'|'sharing'|'dlp'|'external'
type Revision = { revision: number; settings: Settings; recorded_at: string }
type Verified = { access: 'verified'; revision: number; current: Settings; history: Revision[] }
type Policy = Verified | { access: 'none'|'mfa'|'sso' }
type Preview = { current: Settings; proposed: Settings; effect: Record<string, boolean> }

const dlpActions: Array<[string,string]> = [['allow','Allow'],['warn','Warn'],['block','Block'],['redact','Redact']]
const domains: Record<Domain,{ label: string; description: string; fields: Field[] }> = {
  messaging: { label:'Messaging', description:'Controls reactions to managed room messages.', fields:[
    {key:'set',name:'Allowed emoji',options:[['all','All'],['native','Standard emoji'],['essential','Essential emoji'],['off','Disabled']]},
    {key:'limit',name:'Reactions per person',min:1,max:8},
  ]},
  files: { label:'Files', description:'Controls whether verified workspace managers can view file access history. Members still control access to their own files through existing rules.',
    fields:[{key:'history',name:'Allow workspace file access history',toggle:true}]},
  calls: { label:'Calls', description:'Pauses recurring workspace meetings. Plans, release rules and emergency stops still determine availability.',
    fields:[{key:'paused',name:'Pause recurring meetings',toggle:true}]},
  ai: { label:'AI', description:'Controls managed workspace AI processing and retention. Existing participant consent and prior deletion still apply.',
    fields:[{key:'enabled',name:'Enable managed AI',toggle:true},{key:'consent',name:'Allow workspace processing',toggle:true},
      {key:'threshold',name:'Advisory threshold',min:1,max:3},{key:'days',name:'Managed AI retention days',min:1,max:90}]},
  retention: { label:'Retention', description:'Controls when archived rooms become eligible for retirement. Preservation holds still apply.',
    fields:[{key:'days',name:'Room retirement days',min:7,max:3650}]},
  sharing: { label:'Sharing', description:'Controls managed file sharing and downloads. The rule never grants file membership or overrides stricter controls.',
    fields:[{key:'mode',name:'File egress',options:[['inherit','Use existing permissions'],['require','Require attributes'],['block','Block sharing and downloads']]},
      {key:'device',name:'Required device trust',options:[['','Any'],['trusted','Trusted'],['managed','Managed']]},
      {key:'risk_max',name:'Maximum session risk',min:0,max:100},{key:'network',name:'Allowed CIDR network'},
      {key:'utc_start',name:'Start UTC hour',min:0,max:23},{key:'utc_end',name:'End UTC hour',min:0,max:23},
      {key:'classification_max',name:'Highest allowed classification',options:[['','Any'],['public','Public'],['internal','Internal'],
        ['confidential','Confidential'],['restricted','Restricted']]},{key:'tenant_type',name:'Required workspace type'}]},
  dlp: { label:'DLP', description:'Applies pattern-based data loss rules to managed room and channel messages. Workspace safeguards still apply.',
    fields:[{key:'pii',name:'Email addresses',options:dlpActions},{key:'phi',name:'Health record identifiers',options:dlpActions},
      {key:'payment_card',name:'Payment card numbers',options:dlpActions},{key:'credential',name:'Credentials',options:dlpActions}]},
  external: { label:'External access', description:'Restricts email invitation links to approved domains. Workspace profile, domain and lifetime checks still apply.',
    fields:[{key:'domains',name:'Allowed email domains',domains:true}]},
}
function displays(field:Field,value:Value|undefined) {
  if(value===null||value===undefined||value==='')return 'Unset'
  if(typeof value==='boolean')return value?'On':'Off'
  if(Array.isArray(value))return value.length?value.join(', '):'None configured'
  return field.options?.find(([key])=>key===value)?.[1]??String(value)
}
function PolicyValues({ domain, settings }: { domain: Domain; settings: Settings }) {
  return <dl>{domains[domain].fields.filter(field=>Object.hasOwn(settings,field.key)).map(field=><div key={field.key}>
    <dt>{field.name}</dt><dd>{displays(field,settings[field.key])}</dd>
  </div>)}</dl>
}

export function WorkspacePolicies({ workspace }: { workspace: string }) {
  const [domain,setDomain]=useState<Domain>('messaging')
  return <section className="release-section" aria-label="Workspace policies">
    <h2>Policies</h2>
    <SectionTabs label="Policy areas" value={domain} onChange={setDomain} options={Object.entries(domains).map(([key,item])=>
      [key as Domain,item.label] as const)}/>
    <PolicyEditor key={workspace+domain} workspace={workspace} domain={domain}/>
  </section>
}

function PolicyEditor({ workspace, domain }: { workspace:string; domain:Domain }) {
  const [policy,setPolicy]=useState<Policy>()
  const [draft,setDraft]=useState<Settings>({})
  const [preview,setPreview]=useState<Preview>()
  const [version,setVersion]=useState('')
  const [reviewTarget,setReviewTarget]=useState<number|null>()
  const [busy,setBusy]=useState(false)
  const [error,setError]=useState('')
  const [notice,setNotice]=useState('')
  const config=domains[domain]
  async function read(signal?:AbortSignal) {
    const request=db!.rpc('st_v7_workspace_policies',{p_workspace:workspace,p_domain:domain})
    const reply=await (signal?request.abortSignal(signal):request)
    if(signal?.aborted)return
    if(reply.error){setError('Could not load this policy.');return}
    const result=reply.data as Policy
    setPolicy(result)
    setDraft(result.access==='verified'?result.current:{})
    setPreview(undefined);setReviewTarget(undefined);setVersion('')
  }
  useEffect(()=>{
    const controller=new AbortController()
    void read(controller.signal)
    return()=>controller.abort()
  },[workspace,domain])

  async function submit(action:'preview'|'apply'|'rollback', target:number|null) {
    if(policy?.access!=='verified'||busy)return
    setBusy(true);setError('');setNotice('')
    if(action==='preview')setPreview(undefined)
    try {
      const candidate=domain==='external'?{domains:Array.isArray(draft.domains)?draft.domains:
        String(draft.domains??'').split(',').map(item=>item.trim()).filter(Boolean)}:
        domain==='sharing'&&draft.mode!=='require'?{mode:draft.mode}:draft
      const response=await db!.rpc('st_v7_workspace_policies',{p_workspace:workspace,p_domain:domain,p_action:action,
        p_revision:policy.revision,p_settings:target===null?candidate:null,p_target:target})
      if(response.error)throw response.error
      if(response.data.access!=='verified'){
        setPolicy(response.data);setDraft({});setPreview(undefined);setReviewTarget(undefined);setVersion('')
        return
      }
      if(action==='preview'){setPreview(response.data as Preview);setReviewTarget(target)}
      else{
        const applied=response.data as Verified
        setPolicy(applied);setDraft(applied.current);setPreview(undefined);setReviewTarget(undefined);setVersion('')
        setNotice(action==='rollback'?'Policy revision restored.':'Policy applied.')
      }
    }catch(cause){setError(formatError(cause,'Could not change this policy.'))}
    finally{setBusy(false)}
  }
  function update(key:string,value:Value){
    const next={...draft}
    if(value===null||value==='')delete next[key];else next[key]=value
    setDraft(next);setPreview(undefined);setReviewTarget(undefined)
  }
  function previewDraft(event:FormEvent<HTMLFormElement>){event.preventDefault();void submit('preview',null)}
  return <section aria-label={config.label+' policy'} className="release-section">
    <h3>{config.label} policy</h3><p>{config.description}</p>
    {!policy&&!error&&<p role="status">Loading policy…</p>}
    {policy?.access==='none'&&<p>Only the current workspace owner can open this policy editor.</p>}
    {policy?.access==='mfa'&&<StaffMfa refresh={()=>read()} explanation="Verify your authenticator to manage workspace policies."/>}
    {policy?.access==='sso'&&<p>Sign in with workspace single sign-on to manage policies.</p>}
    {policy?.access==='verified'&&<>
      <div className="release-flex"><strong>Current revision {policy.revision}</strong>
        <button className="secondary" type="button" disabled={busy} onClick={()=>void read()}>Refresh policy</button></div>
      <PolicyValues domain={domain} settings={policy.current}/>
      <form className="release-form" onSubmit={previewDraft}>
        <fieldset disabled={busy}><legend>Proposed policy</legend>
          {config.fields.filter(field=>domain!=='sharing'||draft.mode==='require'||field.key==='mode').map(field=>{
            const value=draft[field.key]
            return <label key={field.key}>{field.toggle?<><input type="checkbox" checked={value===true}
              onChange={event=>update(field.key,event.target.checked)}/>{field.name}</>:<>{field.name}
              {field.options?<select value={String(value??'')} onChange={event=>update(field.key,event.target.value)}>
                {field.options.map(([key,label])=><option key={key} value={key}>{label}</option>)}
              </select>:<input type={field.min===undefined?'text':'number'} min={field.min} max={field.max}
                required={field.min!==undefined&&domain!=='sharing'}
                value={Array.isArray(value)?value.join(','):String(value??'')} onChange={event=>{
                  const raw=event.target.value
                  update(field.key,field.min===undefined?raw:(raw?Number(raw):null))
                }}/>}
            </>}</label>
          })}
          <button className="primary">Preview proposed policy</button>
        </fieldset>
      </form>
      {policy.history.length>1&&<div className="release-form">
        <label>Earlier revision<select value={version} onChange={event=>{setVersion(event.target.value);setPreview(undefined);setReviewTarget(undefined)}}>
          <option value="">Choose a revision</option>{policy.history.filter(item=>item.revision!==policy.revision).map(item=><option
            key={item.revision} value={item.revision}>Revision {item.revision} · {new Date(item.recorded_at).toLocaleString()}</option>)}
        </select></label>
        <button className="secondary" type="button" disabled={busy||!version} onClick={()=>void submit('preview',Number(version))}>Preview earlier revision</button>
      </div>}
      {preview&&<section aria-label="Policy preview" className="release-board-item">
        <h4>Policy preview</h4>
        <PolicyValues domain={domain} settings={preview.proposed}/>
        {typeof preview.effect.available_to_requester==='boolean'&&<p>Recurring meetings would be {preview.effect.available_to_requester?'available':'unavailable'} to this account.</p>}
        {preview.effect.allowlist_required&&<p>The workspace profile requires an approved invitation domain.</p>}
        <p>Preview validated against the live policy. No settings were saved.</p>
        <button className="primary" type="button" disabled={busy} onClick={()=>void submit(reviewTarget===null?'apply':'rollback',reviewTarget??null)}>
          {reviewTarget===null?'Apply policy':'Restore earlier revision'}</button>
      </section>}
    </>}
    {notice&&<p role="status">{notice}</p>}
    {error&&<p role="alert">{error}</p>}
  </section>
}
