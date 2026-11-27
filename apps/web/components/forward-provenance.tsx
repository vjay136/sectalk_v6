'use client'

import { useEffect, useMemo, useState } from 'react'
import { db } from '../lib/data'
import { messageSafetyAction } from '../lib/message-safety-action.mjs'

type ForwardSummary = {
  message_id: string
  forwards: number
  forwarders: number
  original_sender: string | null
}
type Advisory = {
  message_id: string
  verdict: 'warning' | 'blocked_link' | 'cleared' | 'reported'
  category: string | null
}

export function useForwardSummaries(kind: 'direct' | 'room', scope: string, messages: {
  id: string; edited_at?: string | null
}[], hints?: EventTarget) {
  const selection = messages.slice(-100).map(message => message.id + ':' + (message.edited_at ?? '')).join(',')
  const [result, setResult] = useState<MessageSignals>()

  useEffect(() => {
    if (!db || !selection) return
    const client = db
    const controller = new AbortController()
    const ids = selection.split(',').map(item => item.split(':', 1)[0])
    let timer: number | undefined
    let version = 0
    async function load() {
      const request = ++version
      if (document.visibilityState === 'visible') {
        const [forward, advisory] = await Promise.all([
          client.rpc('st_forward_summary', {
            p_kind: kind, p_scope: scope, p_messages: ids,
          }).abortSignal(controller.signal),
          kind === 'direct' ? client.rpc('st_direct_message_advisories', {
            p_chat: scope, p_messages: ids,
          }).abortSignal(controller.signal) : null,
        ])
        if (!controller.signal.aborted && request === version) {
          const rows = (forward.data ?? []) as ForwardSummary[]
          const labels = (advisory?.data ?? []) as Advisory[]
          setResult(previous => {
            const retained = retainMessageSignals(previous, scope, selection)
            return { scope, selection,
              summaries: forward.error && retained ? retained.summaries : new Map(rows.map(row => [row.message_id, row])),
              advisories: advisory?.error && retained ? retained.advisories : new Map(labels.map(row => [row.message_id, row])),
              checked: new Set(advisory && !advisory.error ? ids : []),
            }
          })
        }
      }
      if (!controller.signal.aborted && request === version) timer = window.setTimeout(() => void load(), 7000)
    }
    const onHint = (event: Event) => {
      if ((event as MessageEvent).data !== scope) return
      version++
      window.clearTimeout(timer)
      timer = window.setTimeout(() => void load(), 100)
    }
    hints?.addEventListener('forward_lineage', onHint)
    void load()
    return () => {
      controller.abort()
      window.clearTimeout(timer)
      hints?.removeEventListener('forward_lineage', onHint)
    }
  }, [hints, kind, scope, selection])

  return retainMessageSignals(result, scope, selection)
}

type MessageSignals = { scope: string; selection: string; summaries: Map<string, ForwardSummary>;
  advisories: Map<string, Advisory>; checked: Set<string> }

function retainMessageSignals(result: MessageSignals | undefined, scope: string, selection: string): MessageSignals | undefined {
  if (result?.scope !== scope) return undefined
  if (result.selection === selection) return result
  const revisions = new Set(selection.split(','))
  const retained = new Set(result.selection.split(',').filter(revision => revisions.has(revision)).map(revision => revision.split(':',1)[0]))
  return { scope, selection,
    summaries: new Map([...result.summaries].filter(([id]) => retained.has(id))),
    advisories: new Map([...result.advisories].filter(([id]) => retained.has(id))),
    checked: new Set([...result.checked].filter(id => retained.has(id))),
  }
}

const categories: Record<string, string> = {
  spam: 'Spam', unwanted: 'Unwanted content', fake: 'False or misleading content', abuse: 'Abusive content',
  fraud: 'Fraud', gambling: 'Gambling solicitation', insecure_link: 'Unsafe link', other: 'Safety concern',
}

function useSafetyStatus(body: string, advisory?: Advisory, checked = false) {
  const caution = useMemo(() => Boolean(body && messageSafetyAction(body).level === 'warning'), [body])
  if (advisory?.verdict === 'warning') return {
    color: 'red', label: 'Confirmed warning · '+(categories[advisory.category ?? 'other'] ?? categories.other),
  }
  if (advisory?.verdict === 'blocked_link') return {color:'red',label:'Contains a link restricted by SecTalk'}
  if (advisory?.verdict === 'reported') return {color:'orange',label:'You reported this message · In review'}
  if (caution) return {color:'orange',label:'Possible safety concern'}
  return checked ? {color:'green',label:'No active warning'} : {color:'neutral',label:'Moderation status unavailable'}
}

export function MessageSafetyIndicator({ body, advisory, checked, open }: {
  body: string; advisory?: Advisory; checked?: boolean; open: () => void
}) {
  const status = useSafetyStatus(body, advisory, checked)
  return <button type="button" className="message-safety-dot" data-severity={status.color}
    aria-label={'Message safety: '+status.label} title={status.label} onClick={open}>
    <span aria-hidden="true" />
  </button>
}

export function LocalMessageSafety({ body, quarantined, details }: {
  body: string; quarantined?: boolean; details?: React.ReactNode
}) {
  const local = useSafetyStatus(body)
  const status = quarantined ? {color:'red',label:'Restricted after Safety review'}
    : body && local.color==='neutral' ? {color:'green',label:'No warning from the local check'} : local
  return <details className="local-message-safety">
    <summary className="message-safety-status" data-severity={status.color}>
      <span aria-hidden="true" />{status.label}
    </summary>
    {status.color === 'green' && <p className="muted">This message passed the on-device check. Always verify unfamiliar requests.</p>}
    {details}
  </details>
}

export function MessageAdvisory({ advisory }: { advisory: Advisory | undefined }) {
  if (!advisory) return null
  if (advisory.verdict === 'reported') return <span className="pill">You reported this message · In review</span>
  if (advisory.verdict === 'cleared') return <span className="pill">Reviewed · No issue confirmed</span>
  if (advisory.verdict === 'blocked_link') return <aside className="risk-warning" aria-label="Moderated message warning">
    <strong>Restricted link</strong><p>SecTalk blocked a link in this message under an active safety rule.</p>
  </aside>
  return <aside className="risk-warning" aria-label="Moderated message warning">
    <strong>Moderator warning · {categories[advisory.category ?? 'other'] ?? categories.other}</strong>
    <p>A moderator reviewed this content. Avoid forwarding it or opening its links.</p>
  </aside>
}

export function ForwardProvenance({ forwarded, summary }: {
  forwarded: boolean
  summary: ForwardSummary | undefined
}) {
  if (!summary) return forwarded ? <span className="pill">Forwarded</span> : null
  return <>
    {forwarded && <span className="pill">Forwarded</span>}
    <span className="pill">
      Shared {summary.forwards} {summary.forwards === 1 ? 'time' : 'times'} by {summary.forwarders}{' '}
      {summary.forwarders === 1 ? 'account' : 'accounts'}
      {summary.original_sender && <> · Original sender {summary.original_sender}</>}
    </span>
  </>
}

export function MessageForwardDetails({ sender, sentAt, summary, advisory, forwarded, body = '', checked }: {
  sender: string
  sentAt: string
  summary?: ForwardSummary
  advisory?: Advisory
  forwarded: boolean
  body?: string
  checked?: boolean
}) {
  const status = useSafetyStatus(body, advisory, checked)
  return <>
    <p className="message-safety-status" data-severity={status.color}><span aria-hidden="true" />{status.label}</p>
    {status.color === 'green' && <p className="muted">SecTalk found no current warning for this message. Always verify unfamiliar requests.</p>}
    <MessageAdvisory advisory={advisory}/>
    <dl className="profile-stats message-inspection">
      <div><dt>{forwarded ? 'Forwarded to this conversation by' : 'Sent by'}</dt><dd>{sender}</dd></div>
      <div><dt>Sent at</dt><dd><time dateTime={sentAt}>{new Date(sentAt).toLocaleString()}</time></dd></div>
      {summary?.original_sender && <div><dt>Original sender</dt><dd>{summary.original_sender}</dd></div>}
      <div><dt>Tracked forwards</dt><dd>{summary ? summary.forwards.toLocaleString() : 'None recorded'}</dd></div>
      <div><dt>Accounts that forwarded</dt><dd>{summary ? summary.forwarders.toLocaleString() : 'None recorded'}</dd></div>
    </dl>
    <p className="muted">Counts cover SecTalk’s Forward action. Safety staff can review names in other conversations when investigating a report.</p>
  </>
}
