'use client'

import { useCallback, useEffect, useState, type FormEvent } from 'react'
import { db, formatError } from '../lib/data'

const tiers = ['Unassigned', 'L1', 'L2', 'Platform'] as const

type Assignment = {
  report_id: string
  tier: number
  acknowledge_by: string
  action_by: string
  acknowledged_at: string | null
}

type Stage = Omit<Assignment, 'report_id' | 'tier'> & {
  tier: number | null
  assignee: string | null
  can_acknowledge: boolean
  can_route: boolean
}

function Deadline({value}: {value: string}) {
  return <time dateTime={value}>{new Date(value).toLocaleString()}</time>
}

export function CaseEscalation({report}: {report: string}) {
  const [stage, setStage] = useState<Stage | null>(null)
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)
  const [feedback, setFeedback] = useState('')
  const load = useCallback(async () => {
    const {data, error} = await db!.rpc('st_v6_case_escalation', {p_report: report})
    setStage(error ? null : data as Stage)
    setError(error ? 'Case escalation is unavailable.' : '')
  }, [report])
  useEffect(() => { void load() }, [load])

  async function change(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    if (!stage || busy) return
    const form = event.currentTarget
    const action = ((event.nativeEvent as SubmitEvent).submitter as HTMLButtonElement | null)?.value
    const reason = new FormData(form).get('routing-reason')
    if (!action) return
    setBusy(true)
    setFeedback('')
    const result = await db!.rpc('st_v6_update_case_escalation', {
      p_report: report, p_action: action, p_expected_tier: stage.tier ?? 0, p_reason: reason,
    })
    await load()
    if (result.error) setError(formatError(result.error, 'Could not update case routing.'))
    else {
      setFeedback(action === 'route' ? 'Case routed.' : 'Stage acknowledged.')
      form.reset()
    }
    setBusy(false)
  }

  return <section className="release-section" aria-label="Case escalation">
    <div className="release-row">
      <h3>Case escalation</h3>
      <button type="button" className="secondary" disabled={busy} onClick={() => void load()}>Refresh routing</button>
    </div>
    {error && <p className="error" role="alert">{error}</p>}
    {feedback && <p role="status">{feedback}</p>}
    {stage && <>
      {stage.tier ? <dl className="profile-stats">
        <div><dt>Current stage</dt><dd>{tiers[stage.tier]}</dd></div>
        <div><dt>Assigned responder</dt><dd>{stage.assignee}</dd></div>
        <div><dt>Acknowledge by</dt><dd><Deadline value={stage.acknowledge_by}/></dd></div>
        <div><dt>Action due</dt><dd><Deadline value={stage.action_by}/></dd></div>
        {stage.acknowledged_at && <div><dt>Stage acknowledged</dt><dd><Deadline value={stage.acknowledged_at}/></dd></div>}
      </dl> : <p>Case routing has not started.</p>}
      {(stage.can_acknowledge || stage.can_route) && <form className="release-form" onSubmit={change}>
        <label>Routing reason<textarea name="routing-reason" rows={2} required maxLength={500} disabled={busy}/></label>
        <div className="actions">
          {stage.can_acknowledge && <button className="secondary" type="submit" value="acknowledge" disabled={busy}>Acknowledge stage</button>}
          {stage.can_route && <button className="secondary" type="submit" value="route" disabled={busy}>
            Route to {tiers[(stage.tier ?? 0) + 1]}
          </button>}
        </div>
      </form>}
    </>}
  </section>
}

export function CaseEscalationAssignments({open}: {open: (report: string) => Promise<boolean>}) {
  const [assignments, setAssignments] = useState<Assignment[]>([])
  useEffect(() => {
    let active = true
    async function load() {
      const {data, error} = await db!.rpc('st_v6_case_escalation_assignments')
      if (active) setAssignments(error ? [] : data as Assignment[])
    }
    void load()
    const interval = window.setInterval(load, 15000)
    return () => { active = false; window.clearInterval(interval) }
  }, [])

  if (!assignments.length) return null
  return <section className="release-section" aria-label="On-call case assignments">
    <h3>On-call case assignments</h3>
    {assignments.map(assignment => <article className="release-board-item" key={assignment.report_id}>
      <div className="release-row">
        <p>{tiers[assignment.tier]} · {assignment.acknowledged_at ? 'Action due' : 'Acknowledge by'}{' '}
          <Deadline value={assignment.acknowledged_at ? assignment.action_by : assignment.acknowledge_by}/></p>
        <button type="button" className="secondary" onClick={() => void open(assignment.report_id)}>Open assigned case</button>
      </div>
    </article>)}
  </section>
}
