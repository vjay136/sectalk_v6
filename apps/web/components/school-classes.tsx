'use client'

import { useCallback, useEffect, useState, type FormEvent } from 'react'
import { db, formatError } from '../lib/data'
import { useSensitiveAction } from './sensitive-action'

type Learner = { id: string; name: string }
type Classroom = { id: string; name: string; room: string | null; myRole: 'teacher' | 'student' | null;
  people: Array<Learner & { role: 'teacher' | 'student' }> }
type Candidate = Learner & { ordinary: boolean }

export function SchoolClasses({ workspace, manager, members, openRoom }: {
  workspace: string; manager: boolean; members: Candidate[]; openRoom: (room: string) => void
}) {
  const [classes, setClasses] = useState<Classroom[]>()
  const [selectedId, setSelectedId] = useState('')
  const [notice, setNotice] = useState('')
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)
  const { authorize, confirmation } = useSensitiveAction()
  const selected = classes?.find(item => item.id === selectedId) ?? classes?.[0]
  const canEnroll = manager || (selected?.myRole === 'teacher' && !!selected.room)

  const load = useCallback(async (signal?: AbortSignal) => {
    const request = db!.rpc('st_v7_school_classes', { p_workspace: workspace })
    const response = await (signal ? request.abortSignal(signal) : request)
    if (signal?.aborted) return
    if (response.error) setError('Could not load classrooms.')
    else setClasses(response.data as Classroom[])
  }, [workspace])

  useEffect(() => {
    const controller = new AbortController()
    void load(controller.signal)
    return () => controller.abort()
  }, [load])

  function update(action: 'create' | 'enroll' | 'remove', classroom: string, params: Record<string, unknown>) {
    if (busy) return
    setError('')
    setNotice('')
    void authorize('room_role', async () => {
      setBusy(true)
      try {
        const result = await db!.rpc('st_v7_school_classes', { p_workspace: workspace, p_action: action, p_class: classroom, ...params })
        if (result.error) throw result.error
        setClasses(result.data as Classroom[])
        setSelectedId(classroom)
        setNotice({ create: 'Classroom created.', enroll: 'Classroom roster updated.', remove: 'Classroom access removed.' }[action])
      } catch (cause) { setError(formatError(cause, 'Could not update this classroom.')) }
      finally { setBusy(false) }
    })
  }
  function enroll(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    if (!selected) return
    const fields = new FormData(event.currentTarget)
    update('enroll', selected.id, { p_person: fields.get('person'), p_role: manager ? fields.get('role') : 'student' })
  }

  return <section className="release-section" aria-label="School classrooms">
    <h2>School classrooms</h2>
    <p>Classroom teachers manage enrolled students and moderate their assigned room.
      School managers assign teachers. Classroom roles do not grant access to other rooms or private conversations.</p>
    <p>Classrooms use private rooms with confidential classification, slow mode, and forwarding and guest access disabled.
      Enrollment is for workspace accounts and does not verify a person’s age or professional role.</p>
    {manager && <form className="release-form" onSubmit={event => {
      event.preventDefault()
      update('create', crypto.randomUUID(), { p_name: new FormData(event.currentTarget).get('name') })
    }}>
      <label>Classroom name<input name="name" maxLength={64} required/></label>
      <button className="primary" disabled={busy}>Create classroom</button>
    </form>}
    <button type="button" className="secondary" disabled={busy} onClick={() => void load()}>Refresh classrooms</button>
    {classes?.length === 0 && <p>No classrooms are assigned to you.</p>}
    {selected && <>
      <label>Classroom<select value={selected.id} onChange={event => setSelectedId(event.target.value)}>
        {classes?.map(item => <option value={item.id} key={item.id}>{item.name}</option>)}
      </select></label>
      <h3>{selected.name}</h3>
      {selected.room && <button type="button" className="primary" onClick={() => openRoom(selected.room!)}>Open supervised room</button>}
      <ul aria-label="Classroom roster">{selected.people.map(person => <li key={person.id}>
        {person.name} · {person.role === 'teacher' ? 'Teacher' : 'Student'}
        {(manager || (canEnroll && person.role === 'student')) && <button type="button" className="text-button" disabled={busy}
          aria-label={'Remove ' + person.name + ' from classroom'} onClick={() => update('remove', selected.id, { p_person: person.id })}>Remove</button>}
      </li>)}</ul>
      {canEnroll && <form className="release-form" onSubmit={enroll}>
        <label>Workspace account<select name="person" required defaultValue="">
          <option value="">Choose an account</option>
          {members.filter(person => manager || person.ordinary).map(person => <option value={person.id} key={person.id}>{person.name}</option>)}
        </select></label>
        {manager && <label>Classroom role<select name="role">
          <option value="student">Student</option><option value="teacher">Teacher</option>
        </select></label>}
        <button className="primary" disabled={busy}>Save classroom enrollment</button>
      </form>}
    </>}
    {confirmation}
    {notice && <p role="status">{notice}</p>}
    {error && <p role="alert">{error}</p>}
  </section>
}
