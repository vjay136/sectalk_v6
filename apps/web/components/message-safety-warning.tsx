'use client'

import { useState } from 'react'
import { ShieldAlert } from 'lucide-react'
import { threatTaxonomy } from '../lib/safety.mjs'
import { messageSafetyAction } from '../lib/message-safety-action.mjs'
import { db } from '../lib/data'

export function MessageSafetyWarning({account,message,revision,body,sender,onReport}:{
  account:string;message:string;revision:string;body:string;sender:string;onReport:()=>void
}){
  const key='sectalk.safety-dismissal.v1:'+account+':'+message+':'+revision
  const { risk, scam: scamMatches, level } = messageSafetyAction(body)
  const categories = risk.reasons.map(reason => reason.category)
  const preference = 'sectalk.safety-feedback.v1:' + account + ':' + sender + ':'
  const [dismissed,setDismissed]=useState(()=>{
    try{return sessionStorage.getItem(key)==='1'}catch{return false}
  })
  const [feedback,setFeedback]=useState<'idle'|'sending'|'saved'|'error'>('idle')
  const [repeatedLowRisk] = useState(() => {
    try { return scamMatches.length===0 && categories.length>0 && risk.severity==='low' &&
      categories.every(category => sessionStorage.getItem(preference+category)==='1') }
    catch { return false }
  })
  if(dismissed)return null
  if(!risk.reasons.length&&!scamMatches.length)return null
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
  const reasons=risk.reasons.length>0&&<ul>{risk.reasons.map(({category,reason})=><li key={category}>{reason}</li>)}</ul>
  const scamLabels = scamMatches.map(({category}) => threatTaxonomy[category]).join(', ')
  const evidence=<>
    {risk.reasons.length>0&&<dl>
      <dt>Risk score</dt><dd>{risk.score} / 100</dd>
      <dt>Severity</dt><dd>{risk.severity}</dd>
      <dt>Rule confidence</dt><dd>{Math.round(risk.confidence*100)}%</dd>
      <dt>Categories</dt><dd>{categories.map(category=>threatTaxonomy[category]).join(', ')}</dd>
    </dl>}
    {scamMatches.map(({category,confidence,reasons:signals})=><div key={category}>
      <strong>{threatTaxonomy[category]} · {Math.round(confidence*100)}% rule confidence</strong>
      <ul>{signals.map(signal=><li key={signal}>{signal}</li>)}</ul>
    </div>)}
    <p>SecTalk checked this message on your device. Rule confidence reflects how closely the text matches known patterns.</p>
    {risk.reasons.length>0&&<>
      <p>Feedback includes the scored warning categories and a message reference. It omits the message text.</p>
      <button type="button" className="secondary" disabled={feedback==='sending'||feedback==='saved'}
        onClick={()=>void submitFeedback()}>Mark warning as incorrect</button>
    </>}
    {feedback==='saved'&&<p role="status">Feedback recorded.</p>}
    {feedback==='error'&&<p role="alert">Feedback could not be recorded.</p>}
  </>
  if(repeatedLowRisk)return <details className="risk-warning">
    <summary>Low-risk message warning</summary>
    {reasons}
    {evidence}
    <button type="button" className="secondary" onClick={onReport}>Report this message</button>
  </details>
  return <aside className={level === 'hint' ? 'risk-warning risk-hint' : 'risk-warning'} aria-label="Message safety warning">
    <div className="release-row"><ShieldAlert size={16} aria-hidden="true"/><strong>{level === 'hint' ? 'Safety hint' : 'Possible safety concern'}</strong></div>
    {scamMatches.length>0&&<p>Possible classification · {scamLabels}</p>}
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
