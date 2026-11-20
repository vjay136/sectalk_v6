'use client'

import { useEffect, useRef, useState, type FormEvent } from 'react'
import { db } from '../lib/data'

type Theme = 'light' | 'dark' | 'high-contrast'
type Appearance = { theme: Theme; reduceMotion: boolean }
const defaults: Appearance = { theme: 'dark', reduceMotion: false }
let currentAppearance: symbol | undefined

export function useAccountAppearance(user: string) {
  const [loaded, setLoaded] = useState<{ user: string; appearance: Appearance }>()
  const [error, setError] = useState('')
  const ownership = useRef<symbol>(undefined)
  useEffect(() => {
    const scope = Symbol()
    currentAppearance = scope
    ownership.current = scope
    const request = new AbortController()
    setError('')
    const root = document.documentElement
    delete root.dataset.userTheme
    delete root.dataset.userMotion
    void db!.rpc('st_v7_user_appearance', { p_owner: user }).abortSignal(request.signal).then(result => {
      if (request.signal.aborted || currentAppearance !== scope) return
      if (result.error || !result.data) setError('Could not load your account appearance.')
      else setLoaded({ user, appearance: result.data as Appearance })
    })
    return () => {
      request.abort()
      if (currentAppearance === scope) {
        currentAppearance = undefined
        delete root.dataset.userTheme
        delete root.dataset.userMotion
      }
    }
  }, [user])

  const appearance = loaded?.user === user ? loaded.appearance : undefined
  useEffect(() => {
    if (!ownership.current || ownership.current !== currentAppearance || !appearance) return
    document.documentElement.dataset.userTheme = appearance.theme
    document.documentElement.dataset.userMotion = appearance.reduceMotion ? 'reduce' : 'system'
  }, [appearance, user])

  async function save(next: Appearance) {
    const scope = ownership.current
    const result = await db!.rpc('st_v7_user_appearance', { p_owner: user, p_theme: next.theme, p_reduce: next.reduceMotion })
    if (scope !== currentAppearance || result.error || !result.data) throw new Error('Appearance update unavailable')
    setLoaded({ user, appearance: result.data as Appearance })
  }

  return { appearance, save, error }
}

export function AccountAppearance({ settings }: { settings: ReturnType<typeof useAccountAppearance> }) {
  const [busy, setBusy] = useState(false)
  const [notice, setNotice] = useState('')
  const [error, setError] = useState('')
  async function save(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    if (busy || !settings.appearance) return
    const form = new FormData(event.currentTarget)
    setBusy(true)
    setNotice('')
    setError('')
    try {
      await settings.save({ theme: form.get('theme') as Theme, reduceMotion: form.has('motion') })
      setNotice('Appearance saved for your account.')
    } catch { setError('Could not save your appearance.') }
    finally { setBusy(false) }
  }
  const active = settings.appearance ?? defaults
  return <section className="release-section" aria-label="Account appearance">
    <h2>Appearance</h2>
    <form className="release-form" onSubmit={event => void save(event)} key={active.theme + ':' + active.reduceMotion}>
      <fieldset disabled={busy || !settings.appearance}>
        <legend>Display preferences</legend>
        <label>Color theme<select name="theme" defaultValue={active.theme}>
          <option value="light">Light</option><option value="dark">Dark</option><option value="high-contrast">High contrast</option>
        </select></label>
        <label className="task-check"><input type="checkbox" name="motion" defaultChecked={active.reduceMotion}/> Reduce motion</label>
        <p>SecTalk also respects the reduced-motion preference of your device.</p>
        <button className="primary" type="submit">Save appearance</button>
      </fieldset>
    </form>
    {notice && <p role="status">{notice}</p>}
    {(error || settings.error) && <p role="alert">{error || settings.error}</p>}
  </section>
}
