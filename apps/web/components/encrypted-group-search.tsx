'use client'

import { useEffect, useRef, useState, type FormEvent } from 'react'
import { db } from '../lib/data'
import { groupLocalDevice } from '../lib/group-chat-crypto'
import { clearGroupIndex, findGroupMessages, type GroupSearchMetadata, type LocalSearchMessage } from '../lib/encrypted-group-search'

export function EncryptedGroupSearch({ owner, group, device }: { owner: string; group: string; device: string }) {
  const [query, setQuery] = useState('')
  const [matches, setMatches] = useState<LocalSearchMessage[]>()
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)
  const generation = useRef(0)
  useEffect(() => () => { generation.current++ }, [])

  async function search(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    if (busy || query.trim().length < 2) return
    const run = ++generation.current
    setBusy(true)
    setMatches(undefined)
    setError('')
    try {
      const response = await db!.rpc('st_group_search_metadata', { p_group: group })
      const { data: auth } = await db!.auth.getSession()
      if (generation.current !== run || auth.session?.user.id !== owner) return
      if (response.error?.code === '42501') await clearGroupIndex(owner, group).catch(() => {})
      if (response.error || !response.data) throw new Error('Search authorization unavailable')
      const current = await groupLocalDevice(owner, device)
      const results = await findGroupMessages(current, group, query, response.data as GroupSearchMetadata)
      if (generation.current === run) setMatches(results)
    } catch {
      if (generation.current === run) setError('Could not search recent messages on this device.')
    } finally {
      if (generation.current === run) setBusy(false)
    }
  }

  return <section aria-label="Encrypted group search">
    <form onSubmit={event => void search(event)}>
      <label>Search encrypted messages
        <input type="search" value={query} maxLength={120} autoComplete="off" spellCheck={false}
          onChange={event => {
            generation.current++
            setQuery(event.target.value)
            setBusy(false)
            setMatches(undefined)
            setError('')
          }} />
      </label>
      <button className="secondary" type="submit" disabled={busy || query.trim().length < 2}>Search this device</button>
    </form>
    <p>Search includes recent messages opened on this device.</p>
    {error && <p role="alert">{error}</p>}
    {matches && <div aria-label="Encrypted search results">
      <p role="status">{matches.length ? matches.length + ' matching messages' : 'No matching messages on this device.'}</p>
      {matches.length > 0 && <ol>{matches.map(match => <li key={match.id}>
        <time dateTime={match.sent}>{new Date(match.sent).toLocaleString()}</time>
        <p style={{ whiteSpace: 'pre-wrap', overflowWrap: 'anywhere' }}>{match.text.slice(0, 480)}{match.text.length > 480 ? '…' : ''}</p>
      </li>)}</ol>}
    </div>}
  </section>
}
