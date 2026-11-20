'use client'

import { useEffect, useState } from 'react'
import { db } from '../lib/data'
import { SectionTabs } from './section-tabs'

const categories=[
  ['accounts','Active accounts'],['messages','Direct messages sent'],['calls','Direct calls started'],
  ['meetings','Meeting occurrences created'],['tasks','Task completions'],
] as const
type Category=typeof categories[number][0]
type Usage={through:string;metrics:Partial<Record<Category,number>>}

export function UsageMetrics(){
  const [period,setPeriod]=useState<'7d'|'30d'>('7d')
  const [usage,setUsage]=useState<Usage|null>(null)
  const [error,setError]=useState(false)
  const [attempt,retry]=useState(0)

  useEffect(()=>{
    let active=true
    setUsage(null);setError(false)
    void db!.rpc('st_v6_usage_metrics',{p_window:period}).then(result=>{
      if(!active)return
      if(result.error)setError(true)
      else setUsage(result.data as Usage)
    })
    return()=>{active=false}
  },[period,attempt])

  return <section className="panel release-panel" aria-labelledby="usage-metrics-title">
    <div className="panel-header"><h2 id="usage-metrics-title">Product usage</h2>
      <button type="button" className="secondary" onClick={()=>retry(value=>value+1)}>Refresh usage</button></div>
    <SectionTabs label="Usage period" value={period} onChange={setPeriod} options={[['7d','7 days'],['30d','30 days']]}/>
    {error&&<p role="alert" className="error">Could not load usage metrics.</p>}
    {!usage&&!error&&<p role="status">Loading usage metrics…</p>}
    {usage&&<>
      <p>Counts are rounded down to the nearest ten. Small groups are omitted.</p>
      <dl className="release-row" aria-label="Usage counts">{categories.map(([key,label])=><div className="release-board-item" key={key}>
        <dt>{label}</dt><dd>{usage.metrics[key]?.toLocaleString()??'Below reporting threshold'}</dd>
      </div>)}</dl>
      <p className="muted">Through <time dateTime={usage.through}>{new Date(usage.through).toLocaleString()}</time></p>
    </>}
  </section>
}
