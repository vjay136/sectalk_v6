'use client'

import {useCallback,useEffect,useState,type FormEvent,type ReactNode} from 'react'
import {Brand} from './entry'
import {db} from '../lib/data'

type Rules= {required:false}|{required:true;version:string;title:string;rules:string[]}

export function CommunityRulesGate({children}:{children:ReactNode}) {
  const [rules,setRules]=useState<Rules>()
  const [readError,setReadError]=useState(false)
  const [actionError,setActionError]=useState('')
  const [busy,setBusy]=useState(false)

  const load=useCallback(async(signal?:AbortSignal)=>{
    const request=db!.rpc('st_v8_community_rules_check')
    const result=await (signal?request.abortSignal(signal):request)
    if(signal?.aborted)return
    setReadError(Boolean(result.error)||typeof result.data?.required!=='boolean')
    setRules(result.error?undefined:result.data)
  },[])

  useEffect(()=>{
    const controller=new AbortController()
    void load(controller.signal)
    function refresh() {if(document.visibilityState==='visible')void load(controller.signal)}
    window.addEventListener('online',refresh)
    document.addEventListener('visibilitychange',refresh)
    return ()=>{
      controller.abort()
      window.removeEventListener('online',refresh)
      document.removeEventListener('visibilitychange',refresh)
    }
  },[load])

  async function accept(event:FormEvent<HTMLFormElement>) {
    event.preventDefault()
    if(!rules?.required||busy||!new FormData(event.currentTarget).has('accept-rules'))return
    setBusy(true);setActionError('')
    const {error}=await db!.rpc('st_v8_community_rules_check',{p_accept_version:rules.version})
    if(error)setActionError(error.code==='PT409'?'The rules changed. Review the latest version.':'Acceptance could not be saved. Try again.')
    await load()
    setBusy(false)
  }

  if(rules?.required===false&&!readError)return children
  return <main className="center-page"><Brand/>
    <section className="panel release-panel" aria-label="Community Rules">
      {readError?<>
        <p role="alert">The Community Rules could not be loaded.</p>
        <button type="button" className="primary" onClick={()=>void load()}>Retry</button>
      </>:rules?.required?<>
        <h1>{rules.title}</h1>
        <p>Review the rules before opening SecTalk. Version {rules.version}</p>
        <ol>{rules.rules.map((rule,index)=><li key={index}>{rule}</li>)}</ol>
        <form key={rules.version} className="release-form" onSubmit={accept}>
          <label><input type="checkbox" name="accept-rules" required disabled={busy}/> I accept the SecTalk Community Rules.</label>
          <button type="submit" className="primary" disabled={busy}>Accept and continue</button>
        </form>
        {actionError&&<p role="alert">{actionError}</p>}
      </>:<p role="status">Checking the Community Rules…</p>}
      <button type="button" className="secondary" onClick={()=>void db!.auth.signOut({scope:'local'})}>Sign out</button>
    </section>
  </main>
}
