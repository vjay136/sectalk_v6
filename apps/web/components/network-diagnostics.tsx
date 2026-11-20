'use client'

import { useEffect, useRef, useState } from 'react'
import { db } from '../lib/data'
import { relayKinds, runNetworkDiagnostics, type DiagnosticConfiguration, type DiagnosticResult,
  type DiagnosticStatus, type RelayKind } from '../lib/network-diagnostics'

const relayLabels: Record<RelayKind, string> = { udp: 'TURN UDP', tcp: 'TURN TCP', tls: 'TURN TLS on port 443' }
const display: Record<DiagnosticStatus, string> = {
  not_configured: 'Not configured', unconfirmed: 'Could not confirm', allocated: 'Relay allocated. Data transfer could not be confirmed.',
  passed: 'Data transfer confirmed',
}

export function NetworkDiagnostics({ inCall }: { inCall: boolean }) {
  const [running, setRunning] = useState(false)
  const [notice, setNotice] = useState('')
  const [error, setError] = useState('')
  const [results, setResults] = useState<DiagnosticResult | null>(null)
  const active = useRef<AbortController | null>(null)

  useEffect(() => () => active.current?.abort(), [])
  useEffect(() => { if (inCall) active.current?.abort() }, [inCall])

  async function start() {
    if (active.current || inCall) return
    if (typeof RTCPeerConnection === 'undefined') {
      setError('This browser does not support WebRTC diagnostics.')
      return
    }
    const controller = new AbortController()
    const signal = controller.signal
    active.current = controller
    setRunning(true)
    setNotice('')
    setError('')
    setResults(null)
    const timeout = window.setTimeout(() => controller.abort(), 25_000)
    try {
      const { data } = await db!.auth.getSession()
      const response = await fetch('/api/ice/diagnostics', { method: 'POST', signal,
        headers: { Authorization: 'Bearer ' + data.session?.access_token } })
      if (!response.ok) {
        const failure = await response.json().catch(() => null)
        throw new Error(failure?.error || 'Could not start network diagnostics.')
      }
      const config = await response.json() as DiagnosticConfiguration
      const report = await runNetworkDiagnostics(config, signal)
      if (!signal.aborted) setResults(report)
    } catch (failure) {
      if (!signal.aborted) setError(failure instanceof Error ? failure.message : 'Network diagnostics could not finish.')
    } finally {
      window.clearTimeout(timeout)
      if (active.current === controller) {
        active.current = null
        setRunning(false)
        if (signal.aborted) setNotice('Diagnostics stopped.')
      }
    }
  }

  return <section className="panel release-panel" aria-labelledby="network-diagnostics-title">
    <h2 id="network-diagnostics-title">Network diagnostics</h2>
    <p>Check WebRTC connectivity to configured STUN and TURN servers. The bandwidth estimate uses up to 256 KiB of test data and measures the relay path back to this browser.</p>
    <div className="release-row">
      <button className="primary" type="button" disabled={running || inCall} onClick={() => void start()}>Run diagnostics</button>
      {running && <button className="secondary" type="button" onClick={() => active.current?.abort()}>Stop diagnostics</button>}
      {inCall && <span>Finish your call before running diagnostics.</span>}
    </div>
    {running && <p role="status">Checking network paths…</p>}
    {notice && <p role="status">{notice}</p>}
    {error && <p role="alert" className="error">{error}</p>}
    {results && <dl aria-label="Network diagnostic results" className="release-row">
      <div className="release-board-item"><dt>STUN</dt><dd>{results.stun === 'passed' ? 'Server-reflexive address discovered' : display[results.stun]}</dd></div>
      {relayKinds.map(kind => <div className="release-board-item" key={kind}>
        <dt>{relayLabels[kind]}</dt><dd>{display[results.relays[kind]]}</dd>
      </div>)}
      <div className="release-board-item"><dt>Relay bandwidth estimate</dt><dd>{
        typeof results.bandwidth === 'object'
          ? results.bandwidth.mbps.toLocaleString(undefined, { maximumFractionDigits: 1 }) + ' Mbps via ' + relayLabels[results.bandwidth.transport]
          : results.bandwidth === 'not_configured' ? 'Not configured' : 'Could not estimate'
      }</dd></div>
    </dl>}
  </section>
}
