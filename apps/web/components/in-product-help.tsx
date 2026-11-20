'use client'

import { CircleHelp, Keyboard } from 'lucide-react'
import { LanguageSelect, useLocale } from './locale-provider'

const shortcuts = [
  { keys: [['Ctrl','K'],['Command','K']], action: 'openPalette' },
  { keys: [['↑'],['↓']], action: 'movePalette' },
  { keys: [['Enter']], action: 'runPalette' },
  { keys: [['Esc']], action: 'closePalette' },
  { keys: [['Enter']], action: 'sendMessage' },
  { keys: [['Shift','Enter']], action: 'addLineBreak' },
] as const

export function InProductHelp({ openFriends, openSafety }: {
  openFriends:()=>void; openSafety:()=>void
}) {
  const { t } = useLocale()
  return <div className="release-section">
    <section className="panel release-panel" aria-labelledby="help-getting-started">
      <div className="release-row"><CircleHelp size={19} aria-hidden="true"/><h2 id="help-getting-started">{t('gettingStarted')}</h2></div>
      <LanguageSelect />
      <details className="release-create">
        <summary>{t('connectWithSomeone')}</summary>
        <p>{t('connectHelp')}</p>
        <button type="button" className="secondary" onClick={openFriends}>{t('openFriends')}</button>
      </details>
      <details className="release-create">
        <summary>{t('blockOrReport')}</summary>
        <p>{t('blockOrReportHelp')}</p>
        <button type="button" className="secondary" onClick={openSafety}>{t('openSafety')}</button>
      </details>
      <details className="release-create">
        <summary>{t('findSaved')}</summary>
        <p>{t('findSavedHelp')}</p>
      </details>
    </section>
    <section className="panel release-panel" aria-labelledby="help-keyboard-shortcuts">
      <div className="release-row"><Keyboard size={19} aria-hidden="true"/><h2 id="help-keyboard-shortcuts">{t('keyboardShortcuts')}</h2></div>
      <p>{t('keyboardShortcutCount', { count: shortcuts.length })}</p>
      <dl>{shortcuts.map(({keys,action})=><div className="release-row" key={action}>
        <dt>{keys.map((combo,index)=><span key={combo.join('+')}>{index > 0 ? ` ${t('shortcutOr')} ` : ''}<bdi dir="ltr">{combo.map((key,position)=>
          <span key={key}>{position>0?' + ':''}<kbd>{key}</kbd></span>)}</bdi></span>)}</dt>
        <dd>{t(action)}</dd>
      </div>)}</dl>
    </section>
  </div>
}
