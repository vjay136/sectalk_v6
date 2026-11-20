'use client'

import { useCallback, useEffect, useState, type FormEvent } from 'react'
import { db, onReconnect } from '../lib/data'
import { threatTaxonomy } from '../lib/safety.mjs'
import { SectionTabs } from './section-tabs'

type Cohort = {
  category: keyof typeof threatTaxonomy
  rule_version: string
  accounts: number
  reviewed: boolean
}
type ProposalKind = 'rule_review' | 'threshold_review'
type Proposal = {
  id: string
  feedback_month: string
  category: Cohort['category']
  rule_version: string
  cohort_size: number
  kind: ProposalKind
  minimum_confidence: number | null
  status: 'pending' | 'approved' | 'declined'
  can_review: boolean
}
const keyFor = (cohort: Cohort) => cohort.category + ':' + cohort.rule_version
const decisions = { pending: 'Awaiting independent review', approved: 'Approved for evaluation', declined: 'Declined' }
const changes = { rule_review: 'Review the detection rule', threshold_review: 'Evaluate a confidence threshold' }

export function RiskFeedback(){
  const [cohorts,setCohorts]=useState<Cohort[]|null>(null)
  const [error,setError]=useState('')
  const [busy,setBusy]=useState(false)
  const [tab,setTab]=useState<'cohorts'|'proposals'>('cohorts')

  useEffect(()=>{
    let current=true
    void db!.rpc('st_v6_risk_feedback_summary').then(result=>{
      if(!current)return
      if(result.error)setError('Could not load warning feedback.')
      else setCohorts(result.data as Cohort[])
    })
    return()=>{current=false}
  },[])

  async function review(cohort:Cohort){
    setBusy(true)
    setError('')
    const {error}=await db!.rpc('st_v6_review_risk_feedback',{
      p_category:cohort.category,p_rule_version:cohort.rule_version,
    })
    setBusy(false)
    if(error){setError('Could not mark the cohort as reviewed.');return}
    setCohorts(previous=>previous?.map(row=>row.category===cohort.category&&row.rule_version===cohort.rule_version
      ?{...row,reviewed:true}:row)??null)
  }

  return <section className="panel release-panel" aria-labelledby="risk-feedback-title">
    <h2 id="risk-feedback-title">Warning feedback</h2>
    <SectionTabs label="Warning feedback sections" value={tab} onChange={setTab}
      options={ [['cohorts','Feedback cohorts'],['proposals','Rule proposals']] }/>
    {tab==='proposals'?<WarningProposals cohorts={cohorts??[]}/>:<>
    <p>Review this month’s aggregate feedback by category and rule version. Counts show the minimum number of accounts that marked a warning as incorrect.</p>
    {error&&<p role="alert" className="error">{error}</p>}
    {!error&&!cohorts&&<p role="status">Loading warning feedback…</p>}
    {cohorts?.length===0&&<p>No feedback cohorts meet the reporting threshold.</p>}
    {cohorts?.map(cohort=><div key={keyFor(cohort)} className="release-row">
      <strong>{threatTaxonomy[cohort.category]??cohort.category}</strong>
      <small>{cohort.rule_version}</small>
      <span>{cohort.accounts}+ accounts</span>
      {cohort.reviewed?<span role="status">Reviewed</span>:
        <button type="button" className="secondary" disabled={busy} onClick={()=>void review(cohort)}>Mark reviewed</button>}
    </div>)}
    </>}
  </section>
}

function WarningProposals({cohorts}:{cohorts:Cohort[]}){
  const [proposals,setProposals]=useState<Proposal[]|null>(null)
  const [cohortKey,setCohortKey]=useState('')
  const [kind,setKind]=useState<ProposalKind>('rule_review')
  const [confidence,setConfidence]=useState(70)
  const [busy,setBusy]=useState(false)
  const [error,setError]=useState('')
  const [notice,setNotice]=useState('')
  const refresh=useCallback(async()=>{
    const result=await db!.rpc('st_v6_warning_proposals')
    if(result.error){setProposals(null);setError('Could not load warning proposals.');return}
    setProposals(result.data as Proposal[])
    setError('')
  },[])
  useEffect(()=>{
    void refresh()
    const disconnect=onReconnect(refresh)
    const timer=window.setInterval(()=>{
      if(document.visibilityState==='visible') void refresh()
    },12000)
    return()=>{disconnect();window.clearInterval(timer)}
  },[refresh])

  async function submit(event:FormEvent<HTMLFormElement>){
    event.preventDefault()
    const cohort=cohorts.find(current=>keyFor(current)===cohortKey)
    if(busy||!cohort)return
    setBusy(true)
    setNotice('')
    const {error}=await db!.rpc('st_v6_propose_warning_change',{
      p_category:cohort.category,p_rule_version:cohort.rule_version,p_kind:kind,
      p_minimum_confidence:kind==='threshold_review'?confidence:null,
    })
    if(error)setError('Could not create the proposal. Check whether a proposal already exists for this cohort.')
    else{
      setCohortKey('')
      await refresh()
      setNotice('Proposal submitted for independent review.')
    }
    setBusy(false)
  }

  async function decide(id:string,decision:'approved'|'declined'){
    if(busy)return
    setBusy(true)
    setNotice('')
    const {error}=await db!.rpc('st_v6_review_warning_change',{p_id:id,p_status:decision})
    if(error)setError('Could not save the review decision. Refresh and check whether it was already reviewed.')
    else{
      await refresh()
      setNotice(decision==='approved'?'Proposal approved for evaluation.':'Proposal declined.')
    }
    setBusy(false)
  }

  return <section aria-labelledby="warning-proposals-title">
    <div className="panel-header">
      <h3 id="warning-proposals-title">Rule and threshold proposals</h3>
      <button type="button" className="secondary" disabled={busy} onClick={()=>void refresh()}>Refresh proposals</button>
    </div>
    <p>A second verified staff member must review each proposal. Approved proposals go to evaluation for a future rule release.</p>
    {error&&<p role="alert" className="error">{error}</p>}
    {notice&&<p role="status">{notice}</p>}
    {cohorts.length>0&&<form className="release-form" onSubmit={submit}>
      <label>Feedback cohort<select aria-label="Feedback cohort" value={cohortKey} required onChange={e=>setCohortKey(e.target.value)}>
        <option value="">Choose a feedback cohort</option>
        {cohorts.map(cohort=><option key={keyFor(cohort)} value={keyFor(cohort)}>
          {threatTaxonomy[cohort.category]} · {cohort.rule_version}
        </option>)}
      </select></label>
      <label>Proposed change<select aria-label="Proposed change" value={kind} onChange={e=>setKind(e.target.value as ProposalKind)}>
        <option value="rule_review">{changes.rule_review}</option>
        <option value="threshold_review">{changes.threshold_review}</option>
      </select></label>
      {kind==='threshold_review'&&<label>Minimum rule confidence (%)<input type="number" required min={60} max={95}
        value={Number.isNaN(confidence)?'':confidence} onChange={e=>setConfidence(e.target.valueAsNumber)}/></label>}
      <button className="primary" type="submit" disabled={busy||!cohortKey}>Submit proposal</button>
    </form>}
    {proposals===null&&!error&&<p role="status">Loading proposals…</p>}
    {proposals?.length===0&&<p>No rule proposals yet.</p>}
    {proposals?.map(proposal=><article className="release-board-item" key={proposal.id}>
      <h4>{threatTaxonomy[proposal.category]??proposal.category}</h4>
      <p>{proposal.rule_version} · {proposal.feedback_month.slice(0,7)} · {proposal.cohort_size}+ accounts</p>
      <p>{changes[proposal.kind]}{proposal.minimum_confidence!==null?' · '+proposal.minimum_confidence+'% minimum confidence':''}</p>
      <p>{decisions[proposal.status]}</p>
      {proposal.can_review&&<div className="action-row">
        <button type="button" className="primary" disabled={busy} onClick={()=>void decide(proposal.id,'approved')}>Approve for evaluation</button>
        <button type="button" className="secondary" disabled={busy} onClick={()=>void decide(proposal.id,'declined')}>Decline proposal</button>
      </div>}
    </article>)}
  </section>
}
