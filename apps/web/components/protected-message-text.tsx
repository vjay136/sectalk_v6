'use client'

import { useState } from 'react'
import { defangSafetyLinks, messageSafetyAction } from '../lib/message-safety-action.mjs'
import { EmojiText } from './emoji-text'

export function ProtectedMessageText({ value }: { value: string }) {
  const [revealed, setRevealed] = useState(false)
  const action = messageSafetyAction(value)
  const text = action.defang ? defangSafetyLinks(value) : value
  if (!action.hold && !action.blur) return <><EmojiText value={text}/>
    {action.defang && <small className="muted">Suspicious links shown as disabled text.</small>}</>
  return <div>
    {revealed ? <EmojiText value={text}/> : action.blur ?
      <span style={{ filter: 'blur(5px)' }} aria-hidden="true">Hidden message preview</span> :
      <span>Message held on this device for your review.</span>}
    <div><button type="button" className="text-button" onClick={() => setRevealed(!revealed)}>
      {revealed ? 'Hide message' : 'Reveal message'}
    </button></div>
    {revealed && action.defang && <small className="muted">Suspicious links shown as disabled text.</small>}
  </div>
}
