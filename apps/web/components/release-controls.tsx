'use client'

import { useCallback, useEffect, useState, type FormEvent } from 'react'
import { db, formatError } from '../lib/data'
import type { Feature } from '../lib/use-feature'

type Scope='global'|'workspace'|'account'
type Rule={feature:Feature;scope:Scope;target:string|null;enabled:boolean;rollout:number;killed:boolean}
const labels:Record<Feature,string>={task_creation:'Task creation',recurring_meetings:'Recurring meetings',integration_api:'Workspace API'}
const scopeLabel={global:'Global',workspace:'Workspace',account:'Account'}
const firstRule:Rule={feature:'task_creation',scope:'global',target:null,enabled:true,rollout:100,killed:false}

export function ReleaseControls(){
  const [rules,setRules]=useState<Rule[]|null>(null)
  const [editing,setEditing]=useState<Rule>(firstRule)
  const [error,setError]=useState('')
  const [notice,setNotice]=useState('')
  const [busy,setBusy]=useState(false)

  const load=useCallback(async()=>{
    const result=await db!.rpc('st_v6_flag_rules')
    if(result.error){setRules(null);setError('Release rules could not be loaded.');return}
    setRules(result.data as Rule[])
  },[])
  useEffect(()=>{void load()},[load])

  function selectRule(feature:Feature,scope:Scope,target:string|null){
    setEditing(rules?.find(rule=>rule.feature===feature&&rule.scope===scope&&rule.target===target)||
      {...firstRule,feature,scope,target})
    setNotice('');setError('')
  }
  async function save(event:FormEvent<HTMLFormElement>){
    event.preventDefault()
    if(busy)return
    const remove=(event.nativeEvent as SubmitEvent).submitter?.getAttribute('data-action')==='remove'
    setBusy(true);setError('');setNotice('')
    try{
      const {error}=await db!.rpc('st_v6_save_flag_rule',{
        p_feature:editing.feature,p_scope:editing.scope,p_target:editing.scope==='global'?null:editing.target?.trim(),
        p_enabled:editing.enabled,p_rollout:editing.rollout,p_killed:editing.killed,p_remove:remove,
      })
      if(error)throw error
      await load()
      setNotice(remove?'Override removed.':'Release rule saved.')
    }catch(error){setError(formatError(error,'Release rule could not be saved.'))}
    finally{setBusy(false)}
  }
  return <section className="panel release-panel" aria-labelledby="release-controls-title">
    <div className="panel-header"><h2 id="release-controls-title">Release controls</h2>
      <button type="button" className="secondary" disabled={busy} onClick={()=>void load()}>Refresh rules</button></div>
    {error&&<p role="alert" className="error">{error}</p>}
    {notice&&<p role="status">{notice}</p>}
    {!rules&&!error&&<p role="status">Loading release rules…</p>}
    {rules&&<>
      <form className="release-form" onSubmit={save}>
        <div className="release-flex">
          <label>Feature<select disabled={busy} value={editing.feature} onChange={event=>
            selectRule(event.target.value as Feature,editing.scope,editing.target)}>
            {Object.entries(labels).map(([id,title])=><option key={id} value={id}>{title}</option>)}
          </select></label>
          <label>Rule scope<select disabled={busy} value={editing.scope} onChange={event=>
            selectRule(editing.feature,event.target.value as Scope,null)}>
            {Object.entries(scopeLabel).map(([id,title])=><option key={id} value={id}>{title}</option>)}
          </select></label>
        </div>
        {editing.scope!=='global'&&<label>{scopeLabel[editing.scope]} ID<input required disabled={busy}
          pattern="[0-9a-fA-F]{8}(-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}" maxLength={36} value={editing.target||''}
          onChange={event=>setEditing({...editing,target:event.target.value})}/></label>}
        <label className="task-check"><input type="checkbox" disabled={busy} checked={editing.enabled}
          onChange={event=>setEditing({...editing,enabled:event.target.checked})}/> Enabled</label>
        <label>Rollout percentage<input type="number" min="0" max="100" step="1" required disabled={busy}
          value={Number.isNaN(editing.rollout)?'':editing.rollout} onChange={event=>setEditing({...editing,rollout:event.target.valueAsNumber})}/></label>
        {editing.scope==='global'&&<label className="task-check"><input type="checkbox" disabled={busy} checked={editing.killed}
          onChange={event=>setEditing({...editing,killed:event.target.checked})}/> Emergency stop for all scopes</label>}
        <div className="action-row">
          <button className="primary" disabled={busy}>Save release rule</button>
          {editing.scope!=='global'&&editing.target&&<button className="secondary" data-action="remove" disabled={busy}>Remove override</button>}
        </div>
      </form>
      <h3>Current rules</h3>
      {rules.map(rule=><div className="release-row" key={rule.feature+rule.scope+rule.target}>
        <strong>{labels[rule.feature]}</strong><span>{scopeLabel[rule.scope]}{rule.target&&' · '+rule.target}</span>
        <span className="pill">{rule.killed?'Emergency stop':rule.enabled?rule.rollout+'% enabled':'Disabled'}</span>
        <button type="button" className="text-button" disabled={busy} onClick={()=>selectRule(rule.feature,rule.scope,rule.target)}>Edit rule</button>
      </div>)}
    </>}
  </section>
}
