'use client'

import { useMemo, useState } from 'react'
import { customEmoji, nativeEmoji } from '../lib/emoji-catalog'
import { EmojiText } from './emoji-text'
import { SectionTabs } from './section-tabs'

const pageSize=96

export default function ChatEmoji({onPick, allowCustom = true}: {onPick: (value:string) => void; allowCustom?: boolean}) {
  const [tab,setTab]=useState<'native'|'custom'>('native')
  const [query,setQuery]=useState('')
  const [page,setPage]=useState(0)
  const matches=useMemo(()=>{
    const words=query.trim().toLowerCase().split(/\s+/).filter(Boolean)
    return (tab==='native'?nativeEmoji:customEmoji).filter(item =>
      words.every(word => (item.label.toLowerCase()+' '+item.terms).includes(word)))
  },[query,tab])
  return <div className="emoji-picker">
    {allowCustom&&<SectionTabs label="Emoji collections" value={tab} options={ [['native','Emoji'],['custom','SecTalk combinations']] }
      onChange={value=>{setTab(value);setPage(0)}}/>}
    <label>Search emoji<input type="search" maxLength={100} value={query} onChange={event=>{setQuery(event.target.value);setPage(0)}}/></label>
    <p className="muted">{matches.length.toLocaleString()} available</p>
    {matches.length === 0 && <p>No matching emoji.</p>}
    <div className="emoji-grid">
      {matches.slice(page*pageSize,(page+1)*pageSize).map(item=><button className="emoji-choice" title={item.label}
        aria-label={item.label} type="button" key={item.value} onClick={()=>onPick(item.value)}>
        <EmojiText value={item.value}/>
      </button>)}
    </div>
    {(page>0||matches.length>pageSize)&&<div className="pagination">
      <button className="secondary" type="button" disabled={page===0} onClick={()=>setPage(page-1)}>Previous</button>
      <span aria-live="polite">Page {page+1} of {Math.ceil(matches.length/pageSize)}</span>
      <button className="secondary" type="button" disabled={(page+1)*pageSize>=matches.length} onClick={()=>setPage(page+1)}>Next</button>
    </div>}
  </div>
}
