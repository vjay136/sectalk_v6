'use client'

import { useEffect, useState, type FormEvent } from 'react'
import { Search, UserPlus, Users, X } from 'lucide-react'
import { db, formatError } from '../lib/data'
import { lifeStages, topicGroups, topicLabels } from '../lib/discovery-catalog'
import { SectionTabs } from './section-tabs'

type Stage = keyof typeof lifeStages
type Result = { handle:string;name:string;stage:Stage;categories:string[] }
const stageOptions=Object.entries(lifeStages).map(([value,label])=><option key={value} value={value}>{label}</option>)

function Topics({ choose }: {choose:(id:string)=>void}) {
  const [group,setGroup]=useState<keyof typeof topicGroups>('interest')
  const [query,setQuery]=useState('')
  const [page,setPage]=useState(0)
  const candidates=topicGroups[group].filter(item=>item.name.toLowerCase().includes(query.trim().toLowerCase()))
  return <div className="topic-picker">
    <SectionTabs label="Category type" value={group} onChange={next=>{setGroup(next);setPage(0)}} options={[
      ['interest','Interests'],['study','Study fields'],['work','Occupations'],
    ]}/>
    <label>Find a category<input type="search" maxLength={100} value={query} onChange={event=>{setQuery(event.target.value);setPage(0)}}/></label>
    <div className="topic-grid">{candidates.slice(page*18,(page+1)*18).map(topic=>
      <button type="button" className="secondary" key={topic.id} onClick={()=>choose(topic.id)}>{topic.name}</button>
    )}</div>
    {!candidates.length&&<p>No matching categories.</p>}
    {candidates.length>18&&<div className="pagination">
      <button type="button" className="secondary" disabled={!page} onClick={()=>setPage(page-1)}>Previous</button>
      <span>{page+1} / {Math.ceil(candidates.length/18)}</span>
      <button type="button" className="secondary" disabled={(page+1)*18>=candidates.length} onClick={()=>setPage(page+1)}>Next</button>
    </div>}
  </div>
}

export function DiscoverySettings({ user, complete }: {user:string;complete?:()=>void}) {
  const [stage,setStage]=useState<Stage>('other')
  const [topics,setTopics]=useState<string[]>([])
  const [publish,setPublish]=useState(false)
  const [adult,setAdult]=useState(false)
  const [busy,setBusy]=useState(false)
  const [loaded,setLoaded]=useState(false)
  const [message,setMessage]=useState('')
  const [error,setError]=useState('')
  useEffect(()=>{
    let live=true
    void db!.from('st_v5_discovery').select('stage,categories,discoverable').eq('user_id',user).maybeSingle().then(({data,error})=>{
      if(!live)return
      if(error){setError('Could not load your discovery settings.');return}
      if(data){setStage(data.stage as Stage);setTopics(data.categories.filter((id:string)=>topicLabels[id]));setPublish(data.discoverable);setAdult(data.discoverable)}
      setLoaded(true)
    })
    return ()=>{live=false}
  },[user])

  async function save(event:FormEvent<HTMLFormElement>){
    event.preventDefault()
    if(busy||!loaded)return
    setBusy(true);setError('');setMessage('')
    const result=await db!.rpc('st_v5_save_discovery',{p_stage:stage,p_categories:topics,p_discoverable:publish,p_adult:adult})
    setBusy(false)
    if(result.error){setError(formatError(result.error,'Could not save your settings.'));return}
    setMessage('Discovery settings saved.')
    complete?.()
  }

  return <form className="panel release-panel release-form discovery-settings" onSubmit={save}>
    <h2>{complete?'Choose your interests':'Discovery profile'}</h2>
    <p>Choose up to eight categories. You can change them anytime.</p>
    <label>Stage<select value={stage} onChange={event=>setStage(event.target.value as Stage)}>{stageOptions}</select></label>
    {topics.length>0&&<div className="topic-grid" aria-label="Selected categories">{topics.map(id=><button key={id} className="secondary" type="button"
      aria-label={'Remove '+topicLabels[id]} onClick={()=>setTopics(previous=>previous.filter(topic=>topic!==id))}>{topicLabels[id]} <X size={14}/></button>)}</div>}
    <Topics choose={id=>{
      if(topics.includes(id))return
      if(topics.length>=8){setError('Remove a category before adding another.');return}
      setError('');setTopics(previous=>[...previous,id])
    }}/>
    <label className="task-check"><input type="checkbox" checked={publish} onChange={event=>setPublish(event.target.checked)}/> Appear in Find Friends</label>
    {publish&&<><p>Other adults who opt in can see your name, handle, stage, and selected categories. They can send a contact request.</p>
      <label className="task-check"><input type="checkbox" checked={adult} required onChange={event=>setAdult(event.target.checked)}/> I am 18 or older</label></>}
    {error&&<p className="error" role="alert">{error}</p>}
    {message&&<p role="status">{message}</p>}
    <div className="action-row"><button className="primary" disabled={busy||!loaded}>{busy?'Saving…':complete?'Save and continue':'Save settings'}</button>
      {complete&&<button type="button" className="secondary" onClick={complete}>Skip for now</button>}</div>
    <p className="catalog-attribution">Occupation titles from the <a href="https://www.onetcenter.org/database.html">O*NET 31.0 Database</a>,
      U.S. Department of Labor, Employment and Training Administration. Codes and titles selected under <a href="https://creativecommons.org/licenses/by/4.0/">CC BY 4.0</a>.</p>
  </form>
}

export function Friends({user,pending,working,send,openRequests}: {
  user:string;pending:number;working:boolean;send:(handle:string)=>void;openRequests:()=>void
}) {
  const [tab,setTab]=useState<'find'|'handle'|'settings'>('find')
  const [category,setCategory]=useState('')
  const [results,setResults]=useState<Result[]|null>(null)
  const [busy,setBusy]=useState(false)
  const [error,setError]=useState('')

  async function search(event:FormEvent<HTMLFormElement>){
    event.preventDefault()
    if(busy)return
    const fields=new FormData(event.currentTarget)
    if(!category&&!fields.get('stage')&&String(fields.get('query')).trim().length<2){setError('Enter a name or select a filter.');return}
    setBusy(true);setError('')
    try{
      const {data,error}=await db!.rpc('st_v5_find_friends',{p_query:fields.get('query'),p_stage:fields.get('stage')||null,p_category:category||null})
      if(error)throw error
      setResults(data as Result[])
    }catch(error){setError(formatError(error,'Search is unavailable.'))}
    finally{setBusy(false)}
  }

  return <section className="content-page">
    <header className="content-title"><div className="card-icon"><Users size={22}/></div><div><h1>Find Friends</h1>
      <p>Discover people who share your interests or connect with someone by their SecTalk handle.</p></div></header>
    <button type="button" className="secondary" onClick={openRequests}>View contact requests{pending>0?' ('+pending+')':''}</button>
    <SectionTabs label="Find Friends sections" value={tab} onChange={next=>{setTab(next);setError('')}} options={[
      ['find','Discover'],['handle','Use a handle'],['settings','My discovery profile'],
    ]}/>
    {tab==='settings'?<DiscoverySettings user={user}/>:
      tab==='handle'?<form className="panel release-panel release-form" onSubmit={event=>{
        event.preventDefault();send(String(new FormData(event.currentTarget).get('handle')).trim())
      }}><label>SecTalk handle<input name="handle" required maxLength={24} pattern="[a-zA-Z0-9_]{3,24}" placeholder="e.g. avery_m"/></label>
        <button className="primary" disabled={working}><UserPlus size={16}/> Send request</button>
      </form>:<>
        <form className="panel release-panel release-form" onSubmit={search}>
          <label>Name or handle<input name="query" type="search" maxLength={64}/></label>
          <label>Stage<select name="stage"><option value="">Any stage</option>{stageOptions}</select></label>
          <details className="release-create"><summary>{category?'Category: '+topicLabels[category]:'Filter by category'}</summary>
            {category&&<button type="button" className="text-button" onClick={()=>setCategory('')}>Clear category</button>}
            <Topics choose={id=>setCategory(id)}/>
          </details>
          <button className="primary" disabled={busy}><Search size={16}/> {busy?'Searching…':'Find people'}</button>
        </form>
        {error&&<p role="alert" className="error">{error}</p>}
        {results?.length===0&&<p>No matching profiles. Try a different filter.</p>}
        {results?.map(person=><article className="panel release-panel" key={person.handle}>
          <h2>{person.name}</h2><p>@{person.handle} · {lifeStages[person.stage]}</p>
          <div className="topic-grid">{person.categories.filter(id=>topicLabels[id]).map(id=><span className="pill" key={id}>{topicLabels[id]}</span>)}</div>
          <button type="button" className="secondary" disabled={working} onClick={()=>send(person.handle)}><UserPlus size={16}/> Send request</button>
        </article>)}
      </>}
  </section>
}
