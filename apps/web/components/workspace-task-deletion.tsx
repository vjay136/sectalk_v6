'use client'

import { useCallback, useEffect, useRef, useState, type FormEvent } from 'react'
import { db, formatError } from '../lib/data'

type Source = {id: string; title: string; containerId?: string; copied: boolean}
type Plan = {plan: string; id: string; title: string | null; containerId?: string; sha256: string; expiresAt: string;
  approvedAt: string | null; deletedAt: string | null}
type Status = {held: boolean; sources: Source[]; plans: Plan[]}
type PostContainer = {channel?: string; room?: string}
type PostStatus = {held: boolean; posts: (PostContainer & {id: string; name: string; copied: boolean})[];
  plans: (Omit<Plan,'id' | 'title'> & PostContainer & {post: string})[]}
type TaskStatus = {held: boolean; tasks: (Source & {room?: string})[];
  plans: (Omit<Plan,'id'> & {task: string; room?: string})[]}
type Action = 'copy' | 'capture' | 'approve' | 'delete'
const scopes = {
  task: {label: 'task', idLabel: 'Task', rpc: 'task', container: undefined, sourceParam: 'p_task'},
  post: {label: 'channel post', idLabel: 'Channel post', rpc: 'post', container: 'channel', sourceParam: 'p_post'},
  roomPost: {label: 'room message', idLabel: 'Room message', rpc: 'room_post', container: 'room', sourceParam: 'p_post'},
  roomTask: {label: 'room task', idLabel: 'Room task', rpc: 'room_task', container: 'room', sourceParam: 'p_task'}
} as const

export function WorkspaceSourceDeletion({workspace, role, kind}: {
  workspace: string; role: 'owner' | 'reviewer'; kind: keyof typeof scopes
}) {
  const {label, idLabel, rpc, container, sourceParam} = scopes[kind]
  const title = 'Permanent workspace ' + label + ' deletion'
  const [status, setStatus] = useState<Status>()
  const [selected, setSelected] = useState('')
  const [busy, setBusy] = useState(false)
  const [notice, setNotice] = useState('')
  const [error, setError] = useState('')
  const version = useRef(0)

  const load = useCallback(async () => {
    const request = ++version.current
    const result = await db!.rpc('st_v8_offboarding_' + rpc + '_status',
      {p_workspace: workspace})
    if (request !== version.current) return
    if (result.error) {
      setStatus(undefined)
      return
    }
    if (container && sourceParam === 'p_post') {
      const value = result.data as PostStatus
      setStatus({held: value.held, sources: value.posts.map(post => ({id: post.id, copied: post.copied,
        title: container === 'channel' ? '#' + post.name : post.name, containerId: post[container]})),
        plans: value.plans.map(plan => ({...plan,id: plan.post,title: null,containerId: plan[container]}))})
    } else {
      const value = result.data as TaskStatus
      setStatus({held: value.held, sources: value.tasks.map(task => ({...task,containerId: task.room})),
        plans: value.plans.map(plan => ({...plan,id: plan.task,containerId: plan.room}))})
    }
  }, [workspace, rpc, container, sourceParam])

  useEffect(() => {
    void load()
    const timer = window.setInterval(() => {if (document.visibilityState === 'visible') void load()}, 12000)
    return () => {++version.current; window.clearInterval(timer)}
  }, [load])

  async function run(event: FormEvent<HTMLFormElement>, action: Action, source: Pick<Source, 'id' | 'containerId'>, plan?: Plan) {
    event.preventDefault()
    if (busy || (container && !source.containerId)) return
    const form = event.currentTarget
    const values = new FormData(form)
    const confirmation = String(values.get('workspace') ?? '').trim()
    if (action === 'delete' && String(values.get('source') ?? '').trim() !== source.id) {
      setError('Enter the exact ' + label + ' ID to confirm permanent deletion.')
      return
    }
    setBusy(true)
    setError('')
    setNotice('')
    try {
      const args = {p_workspace: workspace, p_confirmation: confirmation, [sourceParam]: source.id,
        ...(container ? {['p_' + container]: source.containerId} : {})}
      const result = action === 'copy'
        ? await db!.rpc('st_v8_offboarding_' + rpc + '_copy', args)
        : await db!.rpc('st_v8_offboarding_' + rpc + '_delete', {
          ...args, p_action: action, ...(plan ? {p_plan: plan.plan, p_sha256: plan.sha256} : {})
        })
      if (result.error) throw result.error
      if (action === 'copy') {
        const url = URL.createObjectURL(new Blob([JSON.stringify(result.data)], {type: 'application/json'}))
        const link = document.createElement('a')
        link.href = url
        link.download = 'sectalk-approved-' + label.replace(' ', '-') + '-' + source.id + '.json'
        link.click()
        window.setTimeout(() => URL.revokeObjectURL(url), 1000)
      }
      const feedback = {copy: 'Approved ' + label + ' copy issued.',
        capture: 'The ' + label + ' deletion plan is ready for independent review.',
        approve: 'Exact ' + label + ' deletion plan approved.',
        delete: 'The live workspace ' + label + ' and its search entry were permanently deleted.'}
      setNotice(feedback[action])
      form.reset()
    } catch (cause) {setError(formatError(cause, 'The ' + label + ' offboarding action could not be completed.'))}
    finally {await load(); setBusy(false)}
  }

  const source = status?.sources.find(item => item.id === selected)
  if (!status) return null
  return <section aria-label={title}>
    <h4>{title}</h4>
    <p>Review one approved workspace {label} at a time. Download its exact copy and retain it according to your policy before preparing the deletion plan.</p>
    {container === 'channel' && <p>Only eligible posts in standard, workspace-wide channels can be selected.</p>}
    {kind === 'roomPost' && <p>Choose an eligible message from a standard public room. Messages with replies, reports, or related records are preserved.</p>}
    {kind === 'roomTask' && <p>Choose an eligible open task from a standard public room. Tasks with assignments, notices, message links, or later activity are preserved.</p>}
    {status.held && <p>Active preservation holds block {label} deletion.</p>}
    {error && <p role="alert" className="error">{error}</p>}
    {notice && <p role="status">{notice}</p>}
    {role === 'owner' && status.sources.length > 0 && <>
      <label>Approved {label}<select aria-label={'Approved ' + label} value={source?.id ?? ''} disabled={busy}
        onChange={event => setSelected(event.currentTarget.value)}>
        <option value="">Choose a {label}</option>
        {status.sources.map(item => <option key={item.id} value={item.id}>{item.title} · {item.id}</option>)}
      </select></label>
      {source && <form key={source.id} className="release-form" onSubmit={event => {
        const submitter = (event.nativeEvent as SubmitEvent).submitter
        void run(event, submitter?.getAttribute('value') === 'capture' ? 'capture' : 'copy', source)
      }}>
        <label>Confirm {label} offboarding workspace ID<input name="workspace" autoComplete="off" maxLength={36} required/></label>
        <div className="actions">
          <button className="secondary" disabled={busy}>Download approved {label} copy</button>
          {source.copied && <button className="secondary" value="capture" disabled={busy || status.held}>Prepare exact {label} deletion plan</button>}
        </div>
      </form>}
    </>}
    {status.plans.map(plan => <article key={plan.plan} className="release-board-item">
      <h5>{plan.title ?? 'Workspace ' + label}</h5>
      <p>{idLabel} ID <code>{plan.id}</code></p>
      {plan.containerId && <p>{container === 'room' ? 'Room' : 'Channel'} ID <code>{plan.containerId}</code></p>}
      <p>Deletion plan SHA-256 <code>{plan.sha256}</code></p>
      <p>{plan.deletedAt ? 'Permanently deleted from the live source' : plan.approvedAt ? 'Independently approved' : 'Awaiting independent deletion approval'}</p>
      {!plan.deletedAt && !status.held && role === 'reviewer' && !plan.approvedAt &&
        <form className="release-form" onSubmit={event => void run(event, 'approve', plan, plan)}>
          <label>Confirm review workspace ID<input name="workspace" autoComplete="off" maxLength={36} required/></label>
          <button className="secondary" disabled={busy}>Approve exact {label} deletion</button>
        </form>}
      {!plan.deletedAt && !status.held && role === 'owner' && plan.approvedAt && <details className="release-create">
        <summary>Permanently delete this workspace {label}</summary>
        <form className="release-form" onSubmit={event => void run(event, 'delete', plan, plan)}>
          <p>Deletion removes this {label} from the live workspace and search. This action cannot be undone in SecTalk.</p>
          <label>Confirm deletion workspace ID<input name="workspace" autoComplete="off" maxLength={36} required/></label>
          <label>Confirm deletion {label} ID<input name="source" autoComplete="off" maxLength={36} required/></label>
          <label className="task-check"><input type="checkbox" required/> I retained the approved copy according to my workspace’s policy.</label>
          <button className="primary" disabled={busy}>Permanently delete approved {label}</button>
        </form>
      </details>}
    </article>)}
    <button type="button" className="secondary" disabled={busy} onClick={() => void load()}>Refresh {label} deletion status</button>
  </section>
}
