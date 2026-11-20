'use client'

import { useEffect, useRef, useState, type FormEvent } from 'react'
import { db, formatError } from '../lib/data'
import { Dialog } from './inbox'
import { useDlpPublishWarning } from './dlp-publish-warning'

export type ForwardDestination = { id: string; name: string }

type ForwardSource =
  | { kind: 'direct'; conversation: string; message: string; destinations: ForwardDestination[] }
  | { kind: 'room'; conversation: string; message: string }

export function ForwardMessageDialog({ source, close, onSent }: {
  source: ForwardSource
  close: () => void
  onSent: () => void
}) {
  const [roomDestinations, setRoomDestinations] = useState<ForwardDestination[] | null>(null)
  const [destination, setDestination] = useState('')
  const [working, setWorking] = useState(false)
  const [error, setError] = useState('')
  const requests = useRef(new Map<string, string>())
  const { publish: publishWithDlp, prompt: dlpPrompt } = useDlpPublishWarning()
  const destinations = source.kind === 'direct' ? source.destinations : roomDestinations

  useEffect(() => {
    if (source.kind !== 'room') return
    const abort = new AbortController()
    void (async () => {
      const result = await db!.rpc('st_v6_forward_room_destinations', { p_room: source.conversation }).abortSignal(abort.signal)
      if (abort.signal.aborted) return
      if (result.error) setError('Could not load eligible rooms.')
      else setRoomDestinations(result.data ?? [])
    })()
    return () => abort.abort()
  }, [source.kind, source.conversation])

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    if (working || !destinations?.some(item => item.id === destination)) return
    setWorking(true)
    setError('')
    const id = requests.current.get(destination) ?? crypto.randomUUID()
    requests.current.set(destination, id)
    const target = { p_source_message: source.message, p_destination: destination, p_id: id }
    try {
      if (source.kind === 'direct') {
        const result = await db!.rpc('st_v6_forward_direct', { ...target, p_source_chat: source.conversation })
        if (result.error) throw result.error
      } else {
        const original = await db!.from('st_v6_room_posts').select('body').eq('room_id', source.conversation)
          .eq('id', source.message).is('removed_at', null).maybeSingle()
        if (original.error || !original.data) throw new Error('The source message is no longer available.')
        await publishWithDlp('room', destination, id, original.data.body, async () => {
          const result = await db!.rpc('st_v6_forward_room', { ...target, p_source_room: source.conversation })
          if (result.error) throw result.error
        })
      }
    } catch (failure) {
      setError(formatError(failure, 'Could not forward the message.'))
      setWorking(false)
      return
    }
    onSent()
    close()
  }

  return <Dialog title="Forward message" close={close}>
    {dlpPrompt}
    {error && <p className="error" role="alert">{error}</p>}
    {!destinations && !error && <p role="status">Loading eligible rooms…</p>}
    {destinations?.length === 0 && <p>{source.kind === 'direct' ? 'No eligible conversations.' : 'No eligible rooms in this workspace.'}</p>}
    {Boolean(destinations?.length) && <form className="release-form" onSubmit={submit}>
      <label>Forward to<select required value={destination} disabled={working} onChange={event => setDestination(event.target.value)}>
        <option value="">Choose a destination</option>
        {destinations?.map(item => <option key={item.id} value={item.id}>{item.name}</option>)}
      </select></label>
      <button className="primary" disabled={working || !destination}>{working ? 'Forwarding…' : 'Forward'}</button>
    </form>}
  </Dialog>
}
