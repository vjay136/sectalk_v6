'use client'

import { useEffect, useState } from 'react'
import { db } from '../lib/data'
import { threatTaxonomy } from '../lib/safety.mjs'

type Cohort = {
  category: keyof typeof threatTaxonomy
  rule_version: string
  accounts: number
  reviewed: boolean
}

export function RiskFeedback(){
  const [cohorts,setCohorts]=useState<Cohort[]|null>(null)
  const [error,setError]=useState('')
  const [busy,setBusy]=useState(false)

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
    <p>Review this month’s aggregate feedback by category and rule version. Counts show the minimum number of accounts that marked a warning as incorrect.</p>
    {error&&<p role="alert" className="error">{error}</p>}
    {!error&&!cohorts&&<p role="status">Loading warning feedback…</p>}
    {cohorts?.length===0&&<p>No feedback cohorts meet the reporting threshold.</p>}
    {cohorts?.map(cohort=><div key={cohort.category+':'+cohort.rule_version} className="release-row">
      <strong>{threatTaxonomy[cohort.category]??cohort.category}</strong>
      <small>{cohort.rule_version}</small>
      <span>{cohort.accounts}+ accounts</span>
      {cohort.reviewed?<span role="status">Reviewed</span>:
        <button type="button" className="secondary" disabled={busy} onClick={()=>void review(cohort)}>Mark reviewed</button>}
    </div>)}
  </section>
}
