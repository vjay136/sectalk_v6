import { CircleHelp, Keyboard } from 'lucide-react'

const shortcuts = [
  { keys: [['Ctrl','K'],['Command','K']], action:'Open the command palette' },
  { keys: [['↑'],['↓']], action:'Move between commands in the palette' },
  { keys: [['Enter']], action:'Run the focused command or submit a palette search' },
  { keys: [['Esc']], action:'Close the command palette' },
  { keys: [['Enter']], action:'Send a message from the chat composer' },
  { keys: [['Shift','Enter']], action:'Add a line break in the chat composer' },
]

export function InProductHelp({ openFriends, openSafety }: {
  openFriends:()=>void; openSafety:()=>void
}) {
  return <div className="release-section">
    <section className="panel release-panel" aria-labelledby="help-getting-started">
      <div className="release-row"><CircleHelp size={19} aria-hidden="true"/><h2 id="help-getting-started">Getting started</h2></div>
      <details className="release-create">
        <summary>Connect with someone</summary>
        <p>Open Find Friends and enter a SecTalk handle, or browse people who enabled discovery. You can message or call after the other person accepts your request.</p>
        <button type="button" className="secondary" onClick={openFriends}>Open Find Friends</button>
      </details>
      <details className="release-create">
        <summary>Block a contact or report a message</summary>
        <p>Use Block contact in the conversation header to stop new messages and calls. Open a message’s actions menu to report it. Follow the report from Safety.</p>
        <button type="button" className="secondary" onClick={openSafety}>Open Safety</button>
      </details>
      <details className="release-create">
        <summary>Find a saved message</summary>
        <p>Choose Save message in the message actions menu. Open Saved messages from Inbox to see your saved items.</p>
      </details>
    </section>
    <section className="panel release-panel" aria-labelledby="help-keyboard-shortcuts">
      <div className="release-row"><Keyboard size={19} aria-hidden="true"/><h2 id="help-keyboard-shortcuts">Keyboard shortcuts</h2></div>
      <dl>{shortcuts.map(({keys,action})=><div className="release-row" key={action}>
        <dt>{keys.map((combo,index)=><span key={combo.join('+')}>{index>0?' or ':''}{combo.map((key,position)=>
          <span key={key}>{position>0?' + ':''}<kbd>{key}</kbd></span>)}</span>)}</dt>
        <dd>{action}</dd>
      </div>)}</dl>
    </section>
  </div>
}
