'use client'

import { useState } from 'react'
import { useAnalyticsSnapshot } from '../lib/live-analytics'
import { SectionTabs } from './section-tabs'

type Window='24h'|'7d'|'30d'
type Metrics={through:string;available:false}|{through:string;available:true;p50:number;p95:number;p99:number}

export function DeliveryLatency({ revision }: { revision: number }){
  const [window,setWindow]=useState<Window>('24h')
  const { snapshot: metrics, error, refresh } = useAnalyticsSnapshot<Metrics>('st_v6_delivery_latency', window, revision)

  return <section className="panel release-panel" aria-labelledby="delivery-latency-title">
    <div className="panel-header">
      <h2 id="delivery-latency-title">Message delivery latency</h2>
      <button type="button" className="secondary" onClick={refresh}>Refresh metrics</button>
    </div>
    <p>Time from server acceptance to acknowledgment by a direct-chat recipient.</p>
    <SectionTabs label="Latency period" value={window} onChange={setWindow}
      options={ [['24h','24 hours'],['7d','7 days'],['30d','30 days']] }/>
    {error&&<p role="alert" className="error">Could not load delivery metrics.</p>}
    {!metrics&&!error&&<p role="status">Loading delivery metrics…</p>}
    {metrics&&!metrics.available&&<p role="status">More acknowledged conversations are needed to show delivery metrics.</p>}
    {metrics?.available&&<dl className="release-row" aria-label="Delivery percentiles">
      {(['p50','p95','p99'] as const).map(key=><div className="release-board-item" key={key}>
        <dt>{key}</dt><dd>{metrics[key].toLocaleString()} ms</dd>
      </div>)}
    </dl>}
    {metrics&&<p className="muted">Through <time dateTime={metrics.through}>{new Date(metrics.through).toLocaleString()}</time></p>}
  </section>
}
