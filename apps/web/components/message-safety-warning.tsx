'use client'

import { useState } from 'react'
import { ShieldAlert } from 'lucide-react'
import { evaluateMessageRisk, threatTaxonomy } from '../lib/safety.mjs'
import { db } from '../lib/data'

export function MessageSafetyWarning({account,message,revision,body,sender,onReport}:{
  account:string;message:string;revision:string;body:string;sender:string;onReport:()=>void
}){
  const key='sectalk.safety-dismissal.v1:'+account+':'+message+':'+revision
  const risk = evaluateMessageRisk(body)
  const categories = risk.reasons.map(reason => reason.category)
  const preference = 'sectalk.safety-feedback.v1:' + account + ':' + sender + ':'
  const [dismissed,setDismissed]=useState(()=>{
    try{return sessionStorage.getItem(key)==='1'}catch{return false}
  })
  const [feedback,setFeedback]=useState<'idle'|'sending'|'saved'|'error'>('idle')
  const [repeatedLowRisk] = useState(() => {
    try { return categories.length>0 && risk.severity==='low' &&
      categories.every(category => sessionStorage.getItem(preference+category)==='1') }
    catch { return false }
  })
  if(dismissed)return null
  if(!risk.reasons.length)return null
  async function submitFeedback(){
    setFeedback('sending')
    const {error}=await db!.rpc('st_v6_submit_risk_feedback',{
      p_message:message,p_revision:revision,p_categories:categories,
    })
    if(error){setFeedback('error');return}
    try{
      if(risk.severity==='low')for(const category of categories)sessionStorage.setItem(preference+category,'1')
    }catch{/* Feedback is already recorded. */}
    setFeedback('saved')
  }
  const reasons=<ul>{risk.reasons.map(({category,reason})=><li key={category}>{reason}</li>)}</ul>
  const evidence=<>
    <dl>
      <dt>Risk score</dt><dd>{risk.score} / 100</dd>
      <dt>Severity</dt><dd>{risk.severity}</dd>
      <dt>Rule confidence</dt><dd>{Math.round(risk.confidence*100)}%</dd>
      <dt>Categories</dt><dd>{categories.map(category=>threatTaxonomy[category]).join(', ')}</dd>
    </dl>
    <p>SecTalk checked this message on your device. The score reflects the patterns found.</p>
    <p>Feedback includes the warning categories and a message reference. It omits the message text.</p>
    <button type="button" className="secondary" disabled={feedback==='sending'||feedback==='saved'}
      onClick={()=>void submitFeedback()}>Mark warning as incorrect</button>
    {feedback==='saved'&&<p role="status">Feedback recorded.</p>}
    {feedback==='error'&&<p role="alert">Feedback could not be recorded.</p>}
  </>
  if(repeatedLowRisk)return <details className="risk-warning">
    <summary>Low-risk message warning</summary>
    {reasons}
    {evidence}
    <button type="button" className="secondary" onClick={onReport}>Report this message</button>
  </details>
  return <aside className="risk-warning" aria-label="Message safety warning">
    <div className="release-row"><ShieldAlert size={16} aria-hidden="true"/><strong>Possible safety concern</strong></div>
    {reasons}
    <details>
      <summary>Risk assessment</summary>
      {evidence}
    </details>
    <div className="action-row">
      <button type="button" className="secondary" aria-label="Report from safety warning" onClick={onReport}>Report</button>
      <button type="button" className="text-button" onClick={()=>{
        try{sessionStorage.setItem(key,'1')}catch{/* The warning can still be dismissed in this view. */}
        setDismissed(true)
      }}>Dismiss warning</button>
    </div>
  </aside>
}
