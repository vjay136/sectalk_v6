'use client'

import { useEffect, useId, useRef, useState, type KeyboardEvent } from 'react'
import { Search, X } from 'lucide-react'

export type Command = { label:string; keywords?:string; run:()=>void }

export function CommandPalette({ commands, onClose, onSearch }: {
  commands:Command[]; onClose:()=>void; onSearch:(query:string)=>void
}) {
  const titleId=useId()
  const dialog=useRef<HTMLDialogElement>(null)
  const input=useRef<HTMLInputElement>(null)
  const actions=useRef<HTMLDivElement>(null)
  const [query,setQuery]=useState('')
  const terms=query.trim()
  const words=terms.toLowerCase().split(/\s+/)
  const matching=commands.filter(command=>words.every(word=>
    (command.label+' '+(command.keywords||'')).toLowerCase().includes(word)))
  useEffect(()=>{
    const panel=dialog.current
    panel?.showModal()
    input.current?.focus()
    return ()=>panel?.close()
  },[])

  function run(action:()=>void) {
    dialog.current?.close()
    onClose()
    action()
  }

  function move(event:KeyboardEvent<HTMLDialogElement>) {
    if(event.key!=='ArrowDown'&&event.key!=='ArrowUp')return
    const buttons=Array.from(actions.current?.querySelectorAll('button')||[])
    if(!buttons.length)return
    const current=buttons.indexOf(event.target as HTMLButtonElement)
    if(current<0&&event.target!==input.current)return
    event.preventDefault()
    const next=current+(event.key==='ArrowDown'?1:-1)
    if(current<0&&event.key==='ArrowUp')buttons.at(-1)?.focus()
    else if(next<0||next>=buttons.length)input.current?.focus()
    else buttons[next].focus()
  }

  return <dialog ref={dialog} className="dialog command-palette" aria-labelledby={titleId}
    onCancel={event=>{event.preventDefault();dialog.current?.close();onClose()}} onKeyDown={move}>
    <div className="dialog-title">
      <h2 id={titleId}>Command palette</h2>
      <button type="button" className="icon" aria-label="Close command palette" onClick={()=>{dialog.current?.close();onClose()}}><X size={19}/></button>
    </div>
    <form onSubmit={event=>{event.preventDefault();if(terms.length>=2)run(()=>onSearch(terms))}}>
      <div className="input-icon"><Search size={17}/><input ref={input} aria-label="Find commands or search SecTalk"
        placeholder="Find commands or search SecTalk" value={query} maxLength={120}
        onChange={event=>setQuery(event.target.value)}/></div>
      <div className="command-list" ref={actions}>
        {terms.length>=2&&<button className="secondary" type="submit">Search SecTalk for “{terms}”</button>}
        {matching.map(command=><button key={command.label} type="button" className="secondary"
          onClick={()=>run(command.run)}>{command.label}</button>)}
      </div>
    </form>
  </dialog>
}
