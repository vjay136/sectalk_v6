'use client'

import { useEffect, useState } from 'react'
import { db } from '../lib/data'

function supported() {
  return window.isSecureContext && 'serviceWorker' in navigator && 'PushManager' in window && 'Notification' in window
}

async function pushRequest(method: 'GET' | 'POST' | 'DELETE', body?: unknown) {
  const { data } = await db!.auth.getSession()
  if (!data.session) throw new Error('Sign in to manage browser push.')
  const response = await fetch('/api/push/subscription', {
    method,
    headers: { Authorization: 'Bearer ' + data.session.access_token, ...(body ? { 'Content-Type': 'application/json' } : {}) },
    ...(body ? { body: JSON.stringify(body) } : {}),
    cache: 'no-store',
  })
  const result = await response.json()
  if (!response.ok) throw new Error(result.error || 'Browser push is unavailable.')
  return result as {publicKey: string; enabled: boolean}
}

function applicationKey(value: string) {
  return Uint8Array.from(atob(value.replace(/-/g, '+').replace(/_/g, '/')), character => character.charCodeAt(0))
}

export async function unsubscribeBrowserPush() {
  if (!supported()) return
  const worker = await navigator.serviceWorker.getRegistration('/')
  const subscription = await worker?.pushManager.getSubscription()
  await subscription?.unsubscribe()
}

export function WebPushSettings() {
  const [registration, setRegistration] = useState<ServiceWorkerRegistration | null>(null)
  const [configuration, setConfiguration] = useState<{publicKey: string; enabled: boolean} | null>(null)
  const [available, setAvailable] = useState(true)
  const [busy, setBusy] = useState(false)
  const [status, setStatus] = useState('')
  const [error, setError] = useState('')

  useEffect(() => {
    if (!supported()) { setAvailable(false);return }
    let active = true
    void pushRequest('GET').then(async config => {
      await navigator.serviceWorker.register('/sectalk-sw.js', { updateViaCache: 'none' })
      const worker = await navigator.serviceWorker.ready
      const subscription = await worker.pushManager.getSubscription()
      if (!active) return
      setRegistration(worker)
      setConfiguration({ ...config, enabled: config.enabled && Boolean(subscription) })
    }).catch(() => { if (active) setAvailable(false) })
    return () => { active = false }
  }, [])

  async function toggle() {
    if (!configuration || !registration || busy) return
    setBusy(true)
    setStatus('')
    setError('')
    try {
      if (configuration.enabled) {
        const current = await registration.pushManager.getSubscription()
        if (current) {
          await pushRequest('DELETE', { endpoint: current.endpoint })
          await current.unsubscribe()
        }
        setConfiguration({ ...configuration, enabled: false })
        setStatus('Browser push turned off.')
        return
      }
      // Request permission directly from the click, before awaiting another API.
      if (await Notification.requestPermission() !== 'granted') {
        setError('Allow notifications in this browser to turn on push.')
        return
      }
      const existing = await registration.pushManager.getSubscription()
      const subscription = existing ?? await registration.pushManager.subscribe({
        userVisibleOnly: true, applicationServerKey: applicationKey(configuration.publicKey),
      })
      try { await pushRequest('POST', subscription.toJSON()) }
      catch (failure) {
        if (!existing) await subscription.unsubscribe().catch(() => undefined)
        throw failure
      }
      setConfiguration({ ...configuration, enabled: true })
      setStatus('Browser push turned on.')
    } catch (failure) {
      setError(failure instanceof Error ? failure.message : 'Could not update browser push.')
    } finally { setBusy(false) }
  }

  return <section className="panel release-panel" aria-label="Browser push">
    <h2>Browser push</h2>
    <p>Get SecTalk alerts and incoming call notifications while you stay signed in, even when the app is in the background. Your device controls notification sound and vibration.</p>
    {available ? configuration
      ? <button type="button" className="secondary" disabled={busy} onClick={() => void toggle()}>
        {configuration.enabled ? 'Turn off browser push' : 'Turn on browser push'}
      </button>
      : <p role="status">Checking browser push…</p>
      : <p role="status">Browser push is unavailable on this browser or server.</p>}
    {status && <p role="status">{status}</p>}
    {error && <p role="alert" className="error">{error}</p>}
  </section>
}
