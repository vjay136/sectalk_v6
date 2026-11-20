'use client'

import { useState } from 'react'
import { useAnalyticsSnapshot } from '../lib/live-analytics'
import { SectionTabs } from './section-tabs'
import { CallQualityMetrics, type CallQuality } from './call-quality-metrics'

const categories=[
  ['accounts','Active accounts'],['messages','Direct messages sent'],['calls','Direct calls started'],
  ['meetings','Meeting occurrences created'],['tasks','Task completions'],
] as const
type Category=typeof categories[number][0]
type Usage={through:string;metrics:Partial<Record<Category,number>>;qos?:CallQuality}

export function UsageMetrics({ revision }: { revision: number }){
  const [period,setPeriod]=useState<'7d'|'30d'>('7d')
  const { snapshot: usage, error, refresh } = useAnalyticsSnapshot<Usage>('st_v6_usage_metrics', period, revision)

  return <section className="panel release-panel" aria-labelledby="usage-metrics-title">
    <div className="panel-header"><h2 id="usage-metrics-title">Product usage</h2>
      <button type="button" className="secondary" onClick={refresh}>Refresh usage</button></div>
    <SectionTabs label="Usage period" value={period} onChange={setPeriod} options={[['7d','7 days'],['30d','30 days']]}/>
    {error&&<p role="alert" className="error">Could not load usage metrics.</p>}
    {!usage&&!error&&<p role="status">Loading usage metrics…</p>}
    {usage&&<>
      <p>Counts are rounded down to the nearest ten. Small groups are omitted.</p>
      <dl className="release-row" aria-label="Usage counts">{categories.map(([key,label])=><div className="release-board-item" key={key}>
        <dt>{label}</dt><dd>{usage.metrics[key]?.toLocaleString()??'Below reporting threshold'}</dd>
      </div>)}</dl>
      <p className="muted">Through <time dateTime={usage.through}>{new Date(usage.through).toLocaleString()}</time></p>
      {usage.qos&&<CallQualityMetrics quality={usage.qos}/>}
    </>}
  </section>
}
