'use client'

import { useEffect, useState } from 'react'
import { Activity, ArrowRight, Database, HardDrive, MessageSquare, RefreshCw, ShieldAlert, Users, Video } from 'lucide-react'
import { db } from '../../web/lib/data'
import { SectionTabs } from '../../web/components/section-tabs'
import { DeliveryLatency } from '../../web/components/delivery-latency'
import { OperationalMetrics } from '../../web/components/operational-metrics'
import { ThreatTrends } from '../../web/components/threat-trends'
import { UsageMetrics } from '../../web/components/usage-metrics'
import { useAnalyticsStream } from '../../web/lib/live-analytics'
import type { FeatureCoverage } from '../lib/feature-coverage'

type Storage = { label: string; objects: number; bytes: number; unknown_sizes: number }
type Snapshot = {
  asOf: string; accounts: number; newAccounts: number; workspaces: number;
  directMessages: number; groupMessages: number; workspacePosts: number;
  audioCalls: number; videoCalls: number; openReports: number; restrictedAccounts: number;
  storage: Storage[];
}
type Tab = 'activity' | 'safety' | 'storage' | 'coverage' | 'usage' | 'delivery' | 'trends' | 'operations'
type Status = 'loading' | 'ready' | 'error'
const integer = new Intl.NumberFormat()
const decimal = new Intl.NumberFormat(undefined, {maximumFractionDigits: 1})
const featurePageSize = 12
const groupNames: Record<string, string> = {
  AUTH:'Authentication', ORG:'Organizations', MSG:'Messaging', THR:'Threads', ROOM:'Rooms', PRES:'Presence',
  NOTIF:'Notifications', FILE:'Files', TASK:'Tasks', SRCH:'Search', CALL:'Calls', AI:'AI', SEC:'Security',
  BILL:'Billing', ADM:'Administration', SOC:'Security operations', PLT:'Platform operations',
  ANL:'Analytics', PLAT:'Platform experience',
}

function bytes(value: number) {
  if (value < 1024) return integer.format(value) + ' B'
  if (value < 1024 ** 2) return decimal.format(value / 1024) + ' KiB'
  if (value < 1024 ** 3) return decimal.format(value / 1024 ** 2) + ' MiB'
  return decimal.format(value / 1024 ** 3) + ' GiB'
}

function FeatureInventory({features}: {features: FeatureCoverage[]}) {
  const [query, setQuery] = useState('')
  const [group, setGroup] = useState('')
  const [page, setPage] = useState(0)
  const needle = query.trim().toLocaleLowerCase()
  const matches = features.filter(item => (!group || item.id.startsWith(group + '-')) &&
    (!needle || [item.id, item.name, item.surface].some(text => text.toLocaleLowerCase().includes(needle))))
  const pageCount = Math.ceil(matches.length / featurePageSize)
  return <div className="ops-inventory">
    <div className="ops-inventory-filters">
      <label>Find a feature<input type="search" value={query} maxLength={100} placeholder="Name, ID, or screen"
        onChange={event => {setQuery(event.target.value);setPage(0)}}/></label>
      <label>Feature area<select value={group} onChange={event => {setGroup(event.target.value);setPage(0)}}>
        <option value="">All feature areas</option>
        {Object.entries(groupNames).map(([id,label]) => <option value={id} key={id}>{label}</option>)}
      </select></label>
    </div>
    <p className="ops-muted" role="status">{integer.format(matches.length)} of {features.length} Free-tier features. Implementation status comes from the release matrix.</p>
    {matches.length ? <ul className="ops-feature-list">
      {matches.slice(page * featurePageSize, (page + 1) * featurePageSize).map(item => <li key={item.id}>
        <span className="ops-feature-id">{item.id}</span>
        <div><strong>{item.name}</strong><small>{item.surface}</small><small>Access · {item.role}</small>
          <small>Recorded signal · {item.signal}</small></div>
        <span className="ops-feature-state" data-implemented={item.implemented}>{item.implemented ? 'Implemented' : 'Open in matrix'}</span>
      </li>)}
    </ul> : <p className="ops-empty">No features match these filters.</p>}
    {pageCount > 1 && <div className="ops-pagination">
      <button type="button" className="secondary" disabled={page === 0} onClick={() => setPage(page - 1)}>Previous</button>
      <span>Page {page + 1} of {pageCount}</span>
      <button type="button" className="secondary" disabled={page + 1 >= pageCount} onClick={() => setPage(page + 1)}>Next</button>
    </div>}
  </div>
}

export function OperatorOverview({features, openModeration, openAccounts, openBeSafe, openResponses}: {
  features: FeatureCoverage[]; openModeration: () => void; openAccounts?: () => void
  openBeSafe: () => void; openResponses?: () => void
}) {
  const [tab, setTab] = useState<Tab>('activity')
  const [attempt, setAttempt] = useState(0)
  const [status, setStatus] = useState<Status>('loading')
  const [snapshot, setSnapshot] = useState<Snapshot | null>(null)
  const showSnapshot = tab === 'activity' || tab === 'safety' || tab === 'storage'
  const analyticsRevision = useAnalyticsStream(tab === 'usage' || tab === 'delivery')

  useEffect(() => {
    if (!showSnapshot) return
    const request = new AbortController()
    let busy = false
    async function load() {
      if (busy || request.signal.aborted || document.visibilityState !== 'visible') return
      busy = true
      try {
        const {data,error} = await db!.rpc('st_v8_operator_overview').abortSignal(request.signal)
        if (request.signal.aborted) return
        if (error || !data) {
          if (error?.code === '42501') setSnapshot(null)
          setStatus('error')
          return
        }
        setSnapshot(data)
        setStatus('ready')
      } catch {
        if (!request.signal.aborted) setStatus('error')
      } finally {busy = false}
    }
    void load()
    const timer = window.setInterval(load, 30000)
    document.addEventListener('visibilitychange', load)
    return () => {request.abort();window.clearInterval(timer);document.removeEventListener('visibilitychange', load)}
  }, [attempt, showSnapshot])

  return <section className="ops-overview" aria-labelledby="ops-overview-title">
    <div className="ops-overview-heading">
      <div><h2 id="ops-overview-title">Platform overview</h2>
        {showSnapshot && <p className="ops-muted">{snapshot ? 'Updated ' + new Date(snapshot.asOf).toLocaleTimeString(undefined, {timeStyle:'short'}) : 'SecTalk activity, safety, and storage'}</p>}</div>
      {showSnapshot && <button type="button" className="secondary" onClick={() => setAttempt(value => value + 1)}><RefreshCw size={16}/> Refresh</button>}
    </div>
    <SectionTabs label="Overview dashboards" value={tab} onChange={setTab} options={[
      ['activity','Activity'],['safety','Safety'],['storage','Storage'],['coverage','Feature coverage'],
      ['usage','Product usage'],['delivery','Delivery latency'],['trends','Threat trends'],['operations','Operational metrics'],
    ]}/>
    {showSnapshot && status === 'loading' && <p role="status" className="ops-empty">Loading dashboard…</p>}
    {showSnapshot && status === 'error' && <p role="alert" className="ops-empty">
      {snapshot ? 'Could not refresh. Showing the last available snapshot.' : 'Dashboard metrics are unavailable. Refresh or verify your authenticator again.'}
    </p>}
    {tab === 'activity' && snapshot && <>
      <div className="ops-metrics">
        <Metric icon={Users} label="Profiles" value={snapshot.accounts} detail={integer.format(snapshot.newAccounts) + ' signups in 24h'}/>
        <Metric icon={MessageSquare} label="Direct messages" value={snapshot.directMessages} detail="Last 24 hours"/>
        <Metric icon={Activity} label="Group messages" value={snapshot.groupMessages} detail="Last 24 hours"/>
        <Metric icon={MessageSquare} label="Workspace posts" value={snapshot.workspacePosts} detail="Last 24 hours"/>
        <Metric icon={Video} label="Direct calls started" value={snapshot.audioCalls + snapshot.videoCalls}
          detail={integer.format(snapshot.audioCalls) + ' audio · ' + integer.format(snapshot.videoCalls) + ' video in 24h'}/>
        <Metric icon={Database} label="Workspaces" value={snapshot.workspaces} detail="Current total"/>
      </div>
    </>}
    {tab === 'safety' && <>
      {snapshot && <div className="ops-metrics">
        <Metric icon={ShieldAlert} label="Open reports" value={snapshot.openReports} detail="Direct chat, room, and channel"/>
        <Metric icon={Users} label="Restricted accounts" value={snapshot.restrictedAccounts} detail="Active platform restrictions"/>
      </div>}
      <div className="ops-pagination">
        <button type="button" className="primary" onClick={openModeration}>Review reports <ArrowRight size={16}/></button>
        {openAccounts && <button type="button" className="secondary" onClick={openAccounts}>Account controls <ArrowRight size={16}/></button>}
        {openResponses && <button type="button" className="secondary" onClick={openResponses}>Review response actions <ArrowRight size={16}/></button>}
        <button type="button" className="secondary" onClick={openBeSafe}>Preview Be Safe <ArrowRight size={16}/></button>
      </div>
    </>}
    {tab === 'storage' && snapshot && <>
      <div className="ops-metrics"><Metric icon={HardDrive} label="Stored object data"
        value={bytes(snapshot.storage.reduce((sum, item) => sum + item.bytes, 0))}
        detail={integer.format(snapshot.storage.reduce((sum, item) => sum + item.objects, 0)) + ' objects across SecTalk buckets'}/></div>
      {snapshot.storage.length > 0 && <ul className="ops-storage">
        {snapshot.storage.map(item => <li key={item.label}><strong>{item.label}</strong>
          <span>{integer.format(item.objects)} objects{item.unknown_sizes > 0 && ' · ' + integer.format(item.unknown_sizes) + ' sizes unavailable'}</span>
          <b>{bytes(item.bytes)}</b></li>)}
      </ul>}
      <p className="ops-muted">Totals use reported object sizes. Database size and network traffic are separate.</p>
    </>}
    {tab === 'coverage' && <FeatureInventory features={features}/>}
    {tab === 'usage' && <UsageMetrics revision={analyticsRevision}/>}
    {tab === 'delivery' && <DeliveryLatency revision={analyticsRevision}/>}
    {tab === 'trends' && <ThreatTrends/>}
    {tab === 'operations' && <OperationalMetrics/>}
  </section>
}

function Metric({icon: Icon,label,value,detail}: {
  icon: typeof Activity; label: string; value: number | string; detail: string
}) {
  return <article className="ops-metric">
    <Icon size={19} aria-hidden="true"/>
    <h3>{label}</h3>
    <strong>{typeof value === 'number' ? integer.format(value) : value}</strong>
    <small>{detail}</small>
  </article>
}
