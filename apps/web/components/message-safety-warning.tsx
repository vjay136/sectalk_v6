'use client'

import { useState } from 'react'
import { ShieldAlert } from 'lucide-react'
import { riskIndicators } from '../lib/safety.mjs'

export function MessageSafetyWarning({account,message,revision,body,onReport}:{
  account:string;message:string;revision:string;body:string;onReport:()=>void
}){
  const key='sectalk.safety-dismissal.v1:'+account+':'+message+':'+revision
  const [dismissed,setDismissed]=useState(()=>{
    try{return sessionStorage.getItem(key)==='1'}catch{return false}
  })
  const reasons=dismissed?[]:riskIndicators(body)
  if(!reasons.length)return null
  return <aside className="risk-warning" aria-label="Message safety warning">
    <div className="release-row"><ShieldAlert size={16} aria-hidden="true"/><strong>Possible safety concern</strong></div>
    <ul>{reasons.map(reason=><li key={reason}>{reason}</li>)}</ul>
    <div className="action-row">
      <button type="button" className="secondary" aria-label="Report from safety warning" onClick={onReport}>Report</button>
      <button type="button" className="text-button" onClick={()=>{
        try{sessionStorage.setItem(key,'1')}catch{/* The warning can still be dismissed in this view. */}
        setDismissed(true)
      }}>Dismiss warning</button>
    </div>
  </aside>
}
