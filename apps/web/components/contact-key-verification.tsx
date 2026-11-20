'use client'

import { useCallback, useEffect, useRef, useState, type FormEvent } from 'react'
import { Fingerprint } from 'lucide-react'
import { db } from '../lib/data'
import { contactSafetyNumber, type ManifestEntry } from '../lib/contact-key-verification'
import { Dialog } from './inbox'

type SafetyNumber = NonNullable<Awaited<ReturnType<typeof contactSafetyNumber>>>

async function currentNumber(owner: string, peer: string) {
  const { data, error } = await db!.rpc('st_v7_contact_key_manifest', { p_peer: peer })
  if (error || !Array.isArray(data)) throw new Error('Contact keys could not be checked.')
  return contactSafetyNumber(data as ManifestEntry[], owner, peer)
}

export function ContactKeyVerification({ owner, peer, name, hints }: { owner: string; peer: string; name: string; hints: EventTarget }) {
  const storageKey = 'sectalk:verified-contact-keys:v1:' + owner + ':' + peer
  const [comparison, setComparison] = useState(false)
  const [number, setNumber] = useState<SafetyNumber | null>(null)
  const [pending, setPending] = useState(true)
  const [qr, setQr] = useState('')
  const [error, setError] = useState('')
  const [mismatch, setMismatch] = useState(false)
  const [checking, setChecking] = useState(false)
  const [previous, setPrevious] = useState(() => {
    try { return window.localStorage.getItem(storageKey) }
    catch { return null }
  })
  const request = useRef(0)

  const load = useCallback(async () => {
    const current = ++request.current
    try {
      const safety = await currentNumber(owner, peer)
      if (current !== request.current) return
      setNumber(safety)
      setError('')
    } catch {
      if (current !== request.current) return
      setNumber(null)
      setError('Contact keys could not be verified. Try again.')
    } finally {
      if (current === request.current) setPending(false)
    }
  }, [owner, peer])

  useEffect(() => {
    void load()
    const refresh = () => { if (document.visibilityState === 'visible') void load() }
    const timer = window.setInterval(refresh, 30000)
    hints.addEventListener('contact_key_changed', load)
    document.addEventListener('visibilitychange', refresh)
    return () => {
      ++request.current
      window.clearInterval(timer)
      hints.removeEventListener('contact_key_changed', load)
      document.removeEventListener('visibilitychange', refresh)
    }
  }, [hints, load])

  const qrValue = number?.qrValue
  useEffect(() => {
    setQr('')
    if (!comparison || !qrValue) return
    let active = true
    void import('qrcode-generator').then(({ default: create }) => {
      const symbol = create(0, 'M')
      symbol.addData(qrValue, 'Alphanumeric')
      symbol.make()
      if (active) setQr(symbol.createDataURL(5, 20))
    }).catch(() => undefined)
    return () => { active = false }
  }, [comparison, qrValue])

  const changed = Boolean(previous && number && previous !== number.fingerprint)
  const verified = Boolean(number && previous === number.fingerprint)

  async function compare(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    if (!number || checking) return
    const submitted = String(new FormData(event.currentTarget).get('number')).trim()
    const matched = submitted === number.qrValue || submitted.replace(/\s+/g, '') === number.number.replace(/ /g, '')
    setMismatch(!matched)
    if (!matched) return
    setChecking(true)
    setError('')
    try {
      const checked = await currentNumber(owner, peer)
      if (checked?.fingerprint !== number.fingerprint) {
        setNumber(checked)
        setError('The device keys changed while you were comparing. Check the new values.')
        return
      }
      window.localStorage.setItem(storageKey, number.fingerprint)
      setPrevious(number.fingerprint)
    } catch { setError('Could not verify and save these keys on this browser.') }
    finally { setChecking(false) }
  }

  return <>
    <button className="icon" type="button" aria-label="Verify contact keys" title="Verify contact keys"
      onClick={() => { setComparison(true); setMismatch(false); void load() }}><Fingerprint size={18}/></button>
    {changed && <span className="pill" role="status">Contact keys changed</span>}
    {verified && <span className="pill" role="status">Contact keys verified</span>}
    {comparison && <Dialog title={'Verify keys with ' + name} close={() => setComparison(false)}>
      <p>Compare this safety number or QR value with your contact through a trusted channel.</p>
      {pending && <p role="status">Loading signed device keys…</p>}
      {error && <p role="alert" className="error">{error}</p>}
      {!pending && !number && !error && <p>Both accounts need approved devices. Register or review yours in Profile → Devices and sessions.</p>}
      {changed && <p role="alert">A previously verified key set changed. Compare the new keys before trusting it.</p>}
      {number && <>
        <p><code dir="ltr" aria-label="Safety number" style={{ overflowWrap: 'anywhere' }}>{number.number}</code></p>
        {qr && <img src={qr} width={180} height={180} alt="QR code for the current safety number"/>}
        <form onSubmit={event => void compare(event)} className="release-form">
          <label>Safety number or scanned QR value<input name="number" dir="ltr" maxLength={110} required/></label>
          <button className="primary" disabled={checking}>Check and verify</button>
        </form>
        {mismatch && <p className="error" role="alert">The values differ. Confirm them with your contact.</p>}
        {verified && <p role="status">The current contact keys are verified on this browser.</p>}
      </>}
      <button type="button" className="secondary" onClick={() => void load()}>Refresh contact keys</button>
    </Dialog>}
  </>
}
