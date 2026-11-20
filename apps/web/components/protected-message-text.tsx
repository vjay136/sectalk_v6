'use client'

import { useState } from 'react'
import { defangSafetyLinks, messageSafetyAction } from '../lib/message-safety-action.mjs'
import { EmojiText } from './emoji-text'
import { RichMessage } from './rich-message'

export function ProtectedMessageText({ value, account }: { value: string; account?: string }) {
  const [revealed, setRevealed] = useState(false)
  const action = messageSafetyAction(value)
  const text = action.defang ? defangSafetyLinks(value) : value
  const render = account ? <RichMessage value={text} account={account} mode='managed' allowLinks={!action.defang && !action.hold && !action.blur}/> : <EmojiText value={text}/>
  if (!action.hold && !action.blur) return <>{render}
    {action.defang && <small className="muted">Suspicious links shown as disabled text.</small>}</>
  return <div>
    {revealed ? render : action.blur ?
      <span style={{ filter: 'blur(5px)' }} aria-hidden="true">Hidden message preview</span> :
      <span>Message held on this device for your review.</span>}
    <div><button type="button" className="text-button" onClick={() => setRevealed(!revealed)}>
      {revealed ? 'Hide message' : 'Reveal message'}
    </button></div>
    {revealed && action.defang && <small className="muted">Suspicious links shown as disabled text.</small>}
  </div>
}
