'use client'

import { useCallback, useEffect, useState, type FormEvent } from 'react'
import { db, formatError } from '../lib/data'
import { StaffMfa } from './staff-mfa'

type Scope = 'group' | 'room' | 'file'
type Permission = 'rename' | 'archive' | 'restore' | 'room.pin' | 'room.unpin' | 'room.slow' | 'file.download' | 'file.share'
type Choice = { id: string; name: string }
type Role = {
  id: string; revision: number; name: string; target: string; scope_type: Scope; file_gate: boolean; permissions: Permission[]; device: string
  risk_max: number | null; utc_start: number | null; utc_end: number | null; enabled: boolean
  assignments: string[]; history: Array<{ revision: number; recordedAt: string }>
}
type State = { access: 'none' | 'mfa' | 'sso' } | { access: 'verified'; roles: Role[] }
const permissions: Record<Scope, Partial<Record<Permission, string>>> = {
  group: { rename: 'Edit directory details', archive: 'Archive entry', restore: 'Restore entry' },
  room: { 'room.pin': 'Pin messages', 'room.unpin': 'Unpin messages', 'room.slow': 'Change slow mode' },
  file: { 'file.download': 'Download workspace file', 'file.share': 'Create private workspace file link' },
}
const conditionLabels: Record<string, string> = { disabled: 'Role disabled', device: 'Device trust', risk: 'Risk ceiling', time: 'UTC access window', permission: 'Permission not granted' }
const optionalNumber = (data: FormData, key: string) => data.get(key) === '' ? null : Number(data.get(key))

export function WorkspaceCustomRoles({ workspace, members }: { workspace: string; members: Choice[] }) {
  const [state, setState] = useState<State>()
  const [targets, setTargets] = useState<Array<Choice & { scope: Scope }>>([])
  const [newScope, setNewScope] = useState<Scope>('group')
  const [selected, setSelected] = useState('')
  const [working, setWorking] = useState(false)
  const [notice, setNotice] = useState('')
  const [error, setError] = useState('')
  const [simulation, setSimulation] = useState<{ allowed: boolean; conditions: string[] }>()
  const roles = state?.access === 'verified' ? state.roles : []
  const role = roles.find(item => item.id === selected)
  const scope = role?.scope_type ?? newScope
  const groups = targets.filter(target => target.scope === scope)

  const load = useCallback(async () => {
    const access = await db!.rpc('st_v7_workspace_custom_roles', { p_workspace: workspace })
    if (access.error) { setError('Could not load custom roles.'); return }
    const current = access.data as State
    setState(current)
    if (current.access !== 'verified') {
      setTargets([])
      setSimulation(undefined)
      return
    }
    const list = await db!.rpc('st_v7_custom_role_targets', { p_workspace: workspace })
    if (list.error) setError('Could not load eligible resources.')
    else setTargets(list.data)
  }, [workspace])
  useEffect(() => { void load() }, [load])

  async function apply(action: string, params: Record<string, unknown>) {
    if (working) return
    setWorking(true); setError(''); setNotice(''); setSimulation(undefined)
    try {
      const result = await db!.rpc('st_v7_workspace_custom_roles', { p_workspace: workspace, p_action: action, ...params })
      if (result.error) throw result.error
      if (result.data.access !== 'verified') {
        setState(result.data as State)
        setTargets([])
        return
      }
      if (action === 'simulate') setSimulation(result.data)
      else {
        setState(result.data as State)
        if (action === 'save') setSelected(String(params.p_role))
        setNotice(action === 'save' ? 'Role revision saved.' : action === 'assign' ? 'Role assigned.' : action === 'gate' ? 'File protection updated.' : 'Role revoked.')
      }
    } catch (cause) { setError(formatError(cause, 'Could not update custom roles.')) }
    finally { setWorking(false) }
  }

  function save(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    const fields = new FormData(event.currentTarget)
    void apply('save', { p_role: role?.id ?? crypto.randomUUID(), p_revision: role?.revision ?? 0,
      p_definition: { name: fields.get('name'), target: role?.target ?? fields.get('target'), scope_type: scope, permissions: fields.getAll('permission'),
        device: fields.get('device'), risk_max: optionalNumber(fields, 'risk'), utc_start: optionalNumber(fields, 'start'),
        utc_end: optionalNumber(fields, 'end'), enabled: fields.has('enabled') } })
  }
  const revision = { p_role: role?.id, p_revision: role?.revision }

  return <section className="release-section" aria-label="Workspace custom roles">
    <h2>Custom roles</h2>
    <p>Delegate approved actions on one directory entry, eligible room, or workspace file. Members keep their existing visibility and restrictions. No role grants membership or ownership.</p>
    {state?.access === 'mfa' && <StaffMfa refresh={load} explanation="Verify your authenticator to manage workspace custom roles."/>}
    {state?.access === 'none' && <p>Only the workspace owner can open this editor.</p>}
    {state?.access === 'sso' && <p>Sign in with workspace single sign-on to manage custom roles.</p>}
    {state?.access === 'verified' && <>
      <label>Custom role<select value={selected} onChange={event => {
        setSelected(event.target.value);setSimulation(undefined);setNotice('')
      }}>
        <option value="">Create a role</option>
        {roles.map(item => <option key={item.id} value={item.id}>{item.name}</option>)}
      </select></label>
      <button type="button" className="secondary" disabled={working} onClick={() => void load()}>Refresh roles</button>
      {!role&&<label>Resource type<select value={scope} onChange={event=>setNewScope(event.target.value as Scope)}>
        <option value="group">Group, team or department</option><option value="room">Room</option><option value="file">Workspace file</option>
      </select></label>}
      {!groups.length && <p>No eligible resources of this type.</p>}
      <form className="release-form" key={(role?.id ?? scope) + ':' + (role?.revision ?? 0)} onSubmit={save}>
        <fieldset disabled={working || !groups.length}>
          <legend>Role permissions and conditions</legend>
          <label>Role name<input name="name" required maxLength={64} defaultValue={role?.name}/></label>
          <label>{scope==='group'?'Directory entry':scope==='room'?'Room to moderate':'Workspace file'}<select name="target" required disabled={!!role} defaultValue={role?.target ?? ''}>
            <option value="">Select an entry</option>{groups.map(group => <option value={group.id} key={group.id}>{group.name}</option>)}
          </select></label>
          {Object.entries(permissions[scope]).map(([value,label]) => <label key={value}>
            <input type="checkbox" name="permission" value={value} defaultChecked={role?.permissions.includes(value as Permission)}/>{label}
          </label>)}
          <label>Required device trust<select name="device" defaultValue={role?.device ?? 'any'}>
            <option value="any">Any active device</option><option value="trusted">Trusted or managed</option><option value="managed">Managed only</option>
          </select></label>
          <label>Maximum session risk<input name="risk" type="number" min={0} max={100} defaultValue={role?.risk_max ?? ''}/></label>
          <label>Start hour UTC<input name="start" type="number" min={0} max={23} defaultValue={role?.utc_start ?? ''}/></label>
          <label>End hour UTC<input name="end" type="number" min={0} max={24} defaultValue={role?.utc_end ?? ''}/></label>
          <p>Leave both hours blank for no time restriction. A missing risk score fails a configured risk ceiling.</p>
          <label><input type="checkbox" name="enabled" defaultChecked={role?.enabled ?? true}/> Role enabled</label>
          <button className="primary">Save role revision</button>
        </fieldset>
      </form>
      {role && <>
        <p>Current revision {role.revision}</p>
        {scope==='file'&&<section aria-label="Role-based file protection">
          <p>When enabled, ordinary members also need an eligible custom role for this file. Existing file policies still apply.</p>
          <button type="button" className="secondary" aria-pressed={role.file_gate} disabled={working}
            onClick={()=>void apply('gate',{...revision,p_definition:{required:!role.file_gate}})}>Require a custom role for this file</button>
        </section>}
        <details><summary>Revision history</summary><ol>{role.history.map(item => <li key={item.revision}>
          Revision {item.revision} · <time dateTime={item.recordedAt}>{new Date(item.recordedAt).toLocaleString()}</time>
        </li>)}</ol></details>
        <form className="release-form" onSubmit={event => {
          event.preventDefault()
          void apply('assign', { ...revision, p_account: new FormData(event.currentTarget).get('account') })
        }}>
          <label>Assign to member<select name="account" required defaultValue="">
            <option value="">Choose a member</option>
            {members.filter(person => !role.assignments.includes(person.id)).map(person => <option key={person.id} value={person.id}>{person.name}</option>)}
          </select></label>
          <button className="secondary" disabled={working}>Assign role</button>
        </form>
        <ul aria-label="Role assignments">{role.assignments.map(id => <li key={id}>
          {members.find(person => person.id === id)?.name ?? 'Workspace member'}
          <button type="button" className="text-button" disabled={working} onClick={() => void apply('revoke', { ...revision, p_account: id })}>Revoke role</button>
        </li>)}</ul>
        <form className="release-form" aria-label="Simulate role decision" onSubmit={event => {
          event.preventDefault()
          const fields = new FormData(event.currentTarget)
          void apply('simulate', { ...revision, p_definition: { device: fields.get('testDevice'), risk: optionalNumber(fields,'testRisk'),
            hour: optionalNumber(fields,'testHour'), permission: fields.get('testPermission') } })
        }}>
          <h3>Simulate a decision</h3>
          <p>These hypothetical values do not grant access. Real decisions use server-verified session attributes.</p>
          <label>Test permission<select name="testPermission">{Object.entries(permissions[scope]).map(([value,label]) => <option key={value} value={value}>{label}</option>)}</select></label>
          <label>Test device trust<select name="testDevice"><option value="known">Untrusted</option>
            <option value="trusted">Trusted</option><option value="managed">Managed</option></select></label>
          <label>Test risk score<input type="number" name="testRisk" min={0} max={100}/></label>
          <label>Test hour UTC<input type="number" name="testHour" min={0} max={23}/></label>
          <button className="secondary" disabled={working}>Simulate role decision</button>
        </form>
        {simulation && <p role="status">{simulation.allowed ? 'Simulation allowed' :
          'Simulation denied: ' + simulation.conditions.map(reason => conditionLabels[reason] ?? reason).join(', ')}</p>}
      </>}
    </>}
    {notice && <p role="status">{notice}</p>}
    {error && <p role="alert">{error}</p>}
  </section>
}
