'use client'

import { useEffect, useRef, useState } from 'react'
import { db } from '../lib/data'
import { dlpLabels } from './workspace-dlp'

function affected(error: { details?: unknown }) {
  if (typeof error.details !== 'string') return 'sensitive information'
  const labels = error.details.split(',').map(key => dlpLabels[key as keyof typeof dlpLabels]).filter(Boolean)
  return labels.length ? labels.join(', ') : 'sensitive information'
}

export function useDlpPublishWarning() {
  const [warning, setWarning] = useState('')
  const decision = useRef<((confirmed: boolean) => void) | null>(null)
  useEffect(() => () => { decision.current?.(false) }, [])

  async function publish(scopeType: 'room' | 'channel', scope: string, message: string, body: string, send: () => Promise<unknown>) {
    try { return await send() } catch (cause) {
      if (!cause || typeof cause !== 'object' || !('code' in cause)) throw cause
      const category = affected(cause as { details?: unknown })
      if (cause.code === 'PT422') throw new Error(`Workspace policy blocked this message because it may contain ${category}. Edit the message before sending.`)
      if (cause.code !== 'PT428' || decision.current) throw cause
      setWarning(category)
      const confirmed = await new Promise<boolean>(resolve => { decision.current = resolve })
      if (!confirmed) throw new Error('Message kept as a draft.')
      const result = await db!.rpc('st_v7_acknowledge_dlp', {
        p_scope_type: scopeType, p_scope: scope, p_message: message, p_body: body,
      })
      if (result.error) throw new Error('The workspace policy changed. Review and try sending again.')
      return send()
    }
  }

  function resolve(confirmed: boolean) {
    const next = decision.current
    decision.current = null
    setWarning('')
    next?.(confirmed)
  }

  const prompt = warning ? <section className="panel release-panel" role="alertdialog" aria-label="Sensitive information warning">
    <h3>Review before sharing</h3>
    <p>This message may contain {warning}. Anyone with access to this conversation could see it.</p>
    <div className="actions">
      <button type="button" className="primary" onClick={() => resolve(true)}>Send after warning</button>
      <button type="button" className="secondary" autoFocus onClick={() => resolve(false)}>Keep editing</button>
    </div>
  </section> : null
  return { publish, prompt }
}
