'use client'

import { useEffect, useRef, useState, type FormEvent } from 'react'
import { AtSign, ChevronDown, Inbox, MessageCircle, Search, ShieldCheck, SlidersHorizontal, Tags, UserPlus, Users, X } from 'lucide-react'
import { db, formatError, onReconnect } from '../lib/data'
import { lifeStages, topicGroups, topicLabels } from '../lib/discovery-catalog'
import { SectionTabs } from './section-tabs'
import styles from './friends.module.css'

type Stage = keyof typeof lifeStages
type Result = { handle:string;name:string;stage:Stage;categories:string[];online:boolean;chat_id:string|null }
const pageSize = 24
const refreshInterval = 15000
const stageOptions=Object.entries(lifeStages).map(([value,label])=><option key={value} value={value}>{label}</option>)
const browseStages:Record<Stage,string>={
  student:'Adult student',college:'College student',professional:'Professional',freelancer:'Freelancer',
  founder:'Business owner',career_change:'Career change',retired:'Retired',other:'Other',
}
const starterTopics=['study-cybersecurity','study-data-science','interest-photography','interest-fitness','interest-language-exchange']
const categoryIndex=Object.values(topicGroups).flat().map(topic=>({...topic,searchName:topic.name.toLocaleLowerCase()}))

function matchingCategories(query:string,limit:number) {
  const term=query.trim().toLocaleLowerCase()
  return categoryIndex.filter(topic=>topic.searchName.startsWith(term))
    .concat(categoryIndex.filter(topic=>!topic.searchName.startsWith(term)&&topic.searchName.includes(term))).slice(0,limit)
}

function initials(name:string) {
  return name.trim().split(/\s+/).slice(0,2).map(word=>Array.from(word)[0]).join('').toLocaleUpperCase()
}

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
  const [publishOnline,setPublishOnline]=useState(false)
  const [adult,setAdult]=useState(false)
  const [busy,setBusy]=useState(false)
  const [loaded,setLoaded]=useState(false)
  const [message,setMessage]=useState('')
  const [error,setError]=useState('')
  useEffect(()=>{
    let live=true
    void db!.from('st_v5_discovery').select('stage,categories,discoverable,online_discoverable').eq('user_id',user).maybeSingle().then(({data,error})=>{
      if(!live)return
      if(error){setError('Could not load your discovery settings.');return}
      if(data){setStage(data.stage as Stage);setTopics(data.categories.filter((id:string)=>topicLabels[id]));setPublish(data.discoverable);setAdult(data.discoverable);setPublishOnline(data.online_discoverable)}
      setLoaded(true)
    })
    return ()=>{live=false}
  },[user])

  async function save(event:FormEvent<HTMLFormElement>){
    event.preventDefault()
    if(busy||!loaded)return
    setBusy(true);setError('');setMessage('')
    const result=await db!.rpc('st_v6_save_discovery',{p_stage:stage,p_categories:topics,p_discoverable:publish,p_adult:adult,p_show_online:publishOnline})
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
    <label className="task-check"><input type="checkbox" checked={publish} onChange={event=>{
      setPublish(event.target.checked)
      if(!event.target.checked)setPublishOnline(false)
    }}/> Appear in Find Friends</label>
    {publish&&<><p>Other adults who opt in can see your name, handle, stage, and selected categories. They can send a contact request.</p>
      <label className="task-check"><input type="checkbox" checked={adult} required onChange={event=>setAdult(event.target.checked)}/> I am 18 or older</label>
      <label className="task-check"><input type="checkbox" checked={publishOnline} onChange={event=>setPublishOnline(event.target.checked)}/> Show me in Online now</label>
      <p>People browsing discovery can see when you’re online while availability sharing is on.</p></>}
    {error&&<p className="error" role="alert">{error}</p>}
    {message&&<p role="status">{message}</p>}
    <div className="action-row"><button className="primary" disabled={busy||!loaded}>{busy?'Saving…':complete?'Save and continue':'Save settings'}</button>
      {complete&&<button type="button" className="secondary" onClick={complete}>Skip for now</button>}</div>
    <p className="catalog-attribution">Occupation titles from the <a href="https://www.onetcenter.org/database.html">O*NET 31.0 Database</a>,
      U.S. Department of Labor, Employment and Training Administration. Codes and titles selected under <a href="https://creativecommons.org/licenses/by/4.0/">CC BY 4.0</a>.</p>
  </form>
}

export function Friends({user,pending,working,send,openRequests,openChat}: {
  user:string;pending:number;working:boolean;send:(handle:string)=>void;openRequests:()=>void;openChat:(id:string)=>void
}) {
  const [tab,setTab]=useState<'find'|'handle'|'settings'>('find')
  const [visibility,setVisibility]=useState<{user:string;enabled:boolean}|null>(null)
  const [query,setQuery]=useState('')
  const [stage,setStage]=useState('')
  const [category,setCategory]=useState('')
  const [categoryQuery,setCategoryQuery]=useState('')
  const [onlineOnly,setOnlineOnly]=useState(false)
  const [pagination,setPagination]=useState({criteria:'',page:0})
  const [byCategory,setByCategory]=useState(false)
  const [attempt,setAttempt]=useState(0)
  const [loadError,setLoadError]=useState('')
  const [searched,setSearched]=useState<{key:string;people:Result[];error:string;rateLimited:boolean}|null>(null)
  const searchInput=useRef<HTMLInputElement>(null)
  const categoryToggle=useRef<HTMLButtonElement>(null)
  const term=query.trim()
  const eligible=visibility?.user===user&&visibility.enabled
  const filtered=Boolean((term&&term!=='@')||stage||category||onlineOnly)
  const criteria=JSON.stringify([user,term,stage,category,onlineOnly])
  const page=pagination.criteria===criteria?pagination.page:0
  const key=JSON.stringify([criteria,page,attempt])
  const result=searched?.key===key?searched:null
  const suggestions=term.length>=2&&!term.startsWith('@')&&!category?matchingCategories(term,4):[]
  const categories=categoryQuery.trim()?matchingCategories(categoryQuery,12):starterTopics.map(id=>({id,name:topicLabels[id]}))

  useEffect(()=>{
    if(tab!=='find')return
    const request=new AbortController()
    void (async()=>{
      const {data,error}=await db!.from('st_v5_discovery').select('discoverable').eq('user_id',user)
        .abortSignal(request.signal).maybeSingle()
      if(request.signal.aborted)return
      setLoadError(error?'Could not load your discovery settings.':'')
      setVisibility(error?null:{user,enabled:data?.discoverable??false})
    })()
    return ()=>request.abort()
  },[user,tab,attempt])

  useEffect(()=>{
    if(tab!=='find'||!eligible||!filtered)return
    const request=new AbortController()
    let running=false
    async function refresh() {
      if(running||request.signal.aborted||document.visibilityState!=='visible')return
      running=true
      try {
        const {data,error}=await db!.rpc('st_v6_find_friends',{
          p_query:term,p_stage:stage||null,p_category:category||null,p_online_only:onlineOnly,p_page:page,
        }).abortSignal(request.signal)
        if(request.signal.aborted)return
        setSearched({key,people:(data as Result[]|null)??[],
          error:error?formatError(error,'Search is unavailable.'):'',rateLimited:error?.code==='PT429'})
      } catch {
        if(!request.signal.aborted)setSearched({key,people:[],error:'Search is unavailable.',rateLimited:false})
      } finally {running=false}
    }
    const initial=window.setTimeout(()=>void refresh(),450)
    const update=window.setInterval(()=>void refresh(),refreshInterval)
    const removeReconnect=onReconnect(()=>void refresh())
    return ()=>{removeReconnect();window.clearTimeout(initial);window.clearInterval(update);request.abort()}
  },[eligible,filtered,key,term,stage,category,onlineOnly,page,tab])

  function clearSearch() {
    setQuery('');setStage('');setCategory('');setCategoryQuery('');setOnlineOnly(false)
    setPagination({criteria:'',page:0})
    searchInput.current?.focus()
  }

  return <section className={`content-page ${styles.page}`}>
    <header className={styles.header}>
      <div className="content-title">
        <div className="card-icon"><Users size={22} aria-hidden="true"/></div>
        <div><h1>Find Friends</h1><p>Find someone you know or meet people who share your interests.</p></div>
      </div>
      <button type="button" className="secondary" onClick={openRequests}><Inbox size={17} aria-hidden="true"/> Contact requests{pending>0&&<span className={styles.count}>{pending}</span>}</button>
    </header>
    <SectionTabs label="Find Friends sections" value={tab} onChange={next=>{
      if(next===tab)return
      setVisibility(null);setLoadError('');setSearched(null);setTab(next)
    }} options={[
      ['find','Discover'],['handle','Use a handle'],['settings','My discovery profile'],
    ]}/>
    {tab==='settings'?<DiscoverySettings user={user}/>:
      tab==='handle'?<form className={`panel ${styles.handleForm}`} onSubmit={event=>{
        event.preventDefault()
        send(String(new FormData(event.currentTarget).get('handle')).trim().replace(/^@/,''))
      }}>
        <h2>Connect by handle</h2><p>Enter the exact handle they shared with you.</p>
        <label>SecTalk handle<input name="handle" required maxLength={25} pattern="@?[a-zA-Z0-9_]{3,24}" placeholder="@avery_m" autoCapitalize="none" autoComplete="off" spellCheck={false}/></label>
        <button className="primary" disabled={working}><UserPlus size={16} aria-hidden="true"/> Send request</button>
      </form>:
      loadError?<div className={`panel ${styles.state}`}>
        <p role="alert">{loadError}</p><button type="button" className="secondary" onClick={()=>setAttempt(n=>n+1)}>Try again</button>
      </div>:
      !visibility?<div className={`panel ${styles.state}`}><p role="status">Loading discovery…</p></div>:
      !eligible?<div className={`panel ${styles.state}`}>
        <div className="card-icon"><ShieldCheck size={22} aria-hidden="true"/></div>
        <h2>Discovery is off</h2>
        <p>To browse people, turn on discovery in your profile. You can still connect by exact handle.</p>
        <div className={styles.actions}>
          <button type="button" className="primary" onClick={()=>setTab('settings')}>Set up discovery</button>
          <button type="button" className="secondary" onClick={()=>setTab('handle')}><AtSign size={16} aria-hidden="true"/> Use a handle</button>
        </div>
      </div>:<>
        <div className={`panel ${styles.searchPanel}`}>
          <label htmlFor="friends-query">Search people</label>
          <div className={styles.searchField}>
            <Search size={18} aria-hidden="true"/>
            <input id="friends-query" ref={searchInput} type="search" value={query} maxLength={query.startsWith('@')?65:64}
              placeholder="Name, @handle, or category" autoComplete="off" autoCapitalize="none" spellCheck={false}
              onChange={event=>setQuery(event.target.value)}/>
          </div>
          {suggestions.length>0&&<div className={styles.chips} role="group" aria-label="Matching categories">
            {suggestions.map(topic=><button type="button" key={topic.id} className={styles.chip}
              onClick={()=>{setCategory(topic.id);setQuery('');searchInput.current?.focus()}}><Tags size={14} aria-hidden="true"/>{topic.name}</button>)}
          </div>}
          <div className={styles.filters}>
            <label className={styles.stage}><span className="visually-hidden">Stage</span>
              <select value={stage} onChange={event=>setStage(event.target.value)}>
                <option value="">Any stage</option>{Object.entries(browseStages).map(([value,label])=><option key={value} value={value}>{label}</option>)}
              </select>
            </label>
            <button ref={categoryToggle} type="button" className="secondary" aria-expanded={byCategory} aria-controls="friends-category"
              onClick={()=>setByCategory(open=>!open)}><SlidersHorizontal size={16} aria-hidden="true"/> Categories <ChevronDown size={14} aria-hidden="true"/></button>
            <button type="button" className={styles.chip} aria-pressed={onlineOnly} onClick={()=>setOnlineOnly(value=>!value)}>
              <span className={styles.onlineDot} aria-hidden="true"/> Online now
            </button>
            {category&&<button type="button" className={`${styles.chip} ${styles.selectedChip}`} aria-label={'Remove category '+topicLabels[category]}
              onClick={()=>{setCategory('');categoryToggle.current?.focus()}}>{topicLabels[category]} <X size={14} aria-hidden="true"/></button>}
            {filtered&&<button type="button" className={`text-button ${styles.clear}`} onClick={clearSearch}>Clear all</button>}
          </div>
          <div id="friends-category" hidden={!byCategory} className={styles.categoryPanel}>
            <label>Find a category<input type="search" maxLength={100} value={categoryQuery}
              placeholder="Search interests, studies, or occupations" onChange={event=>setCategoryQuery(event.target.value)}/></label>
            <div className={styles.chips}>{categories.map(topic=><button type="button" key={topic.id} className={styles.chip}
              aria-pressed={category===topic.id} onClick={()=>{
                setCategory(category===topic.id?'':topic.id);setByCategory(false);categoryToggle.current?.focus()
              }}>
              {topic.name}</button>)}</div>
            {!categories.length&&<p role="status">No matching categories.</p>}
          </div>
        </div>
        <section aria-label="People results" aria-busy={filtered&&!result}>
          {!filtered?<div className={`panel ${styles.state}`}>
            <h2>Browse by interest</h2>
            <div className={styles.chips}>{starterTopics.map(id=><button type="button" className={styles.chip} key={id}
              onClick={()=>{setCategory(id);searchInput.current?.focus()}}>{topicLabels[id]}</button>)}</div>
          </div>:!result?<p className={styles.resultStatus} role="status">Searching…</p>:
          result.error?<div className={`panel ${styles.state}`}>
            <p className="error" role="alert">{result.error}</p>
            {!result.rateLimited&&<button type="button" className="secondary" onClick={()=>setAttempt(n=>n+1)}>Try again</button>}
          </div>:result.people.length===0?<div className={`panel ${styles.state}`}>
            <Search size={23} aria-hidden="true"/>
            <h2>{onlineOnly?'No online matches':'No new people found'}</h2>
            <p>{onlineOnly?'Only people who choose to share their online status in discovery appear here.':'Try different words or remove a filter. Only people who turn on discovery are listed.'}</p>
            {page>0&&<button type="button" className="secondary" onClick={()=>setPagination({criteria,page:page-1})}>Previous</button>}
            <button type="button" className="secondary" onClick={clearSearch}>Clear search</button>
          </div>:<>
            <p className={styles.resultStatus} role="status">{page>0||result.people.length>pageSize
              ? `Showing ${page*pageSize+1}–${page*pageSize+Math.min(result.people.length,pageSize)}`
              : `${result.people.length} ${result.people.length===1?'match':'matches'}`}</p>
            <ul className={`panel ${styles.results}`}>{result.people.slice(0,pageSize).map(person=><li className={styles.person} key={person.handle}>
              <span className="avatar green" aria-hidden="true">{initials(person.name)}</span>
              <div className={styles.identity}>
                <h2>{person.name}</h2><p><bdi>@{person.handle}</bdi> · {lifeStages[person.stage]}</p>
                {person.online&&<span className={styles.online}><span className={styles.onlineDot} aria-hidden="true"/> Online</span>}
                {person.categories.some(id=>topicLabels[id])&&<div className={styles.personTopics}>{person.categories.filter(id=>topicLabels[id]).map(id=>
                  <span className="pill" key={id}>{topicLabels[id]}</span>)}</div>}
              </div>
              {person.chat_id?<button type="button" className="secondary" aria-label={'Message @'+person.handle}
                onClick={()=>openChat(person.chat_id!)}><MessageCircle size={16} aria-hidden="true"/> Message</button>:
                <button type="button" className="secondary" disabled={working} aria-label={'Send request to @'+person.handle}
                  onClick={()=>send(person.handle)}><UserPlus size={16} aria-hidden="true"/> Send request</button>}
            </li>)}</ul>
            {(page>0||result.people.length>pageSize)&&<div className={styles.pagination} aria-label="People results pages">
              <button type="button" className="secondary" disabled={page===0}
                onClick={()=>setPagination({criteria,page:page-1})}>Previous</button>
              <button type="button" className="secondary" disabled={result.people.length<=pageSize||page>=999}
                onClick={()=>setPagination({criteria,page:page+1})}>Next</button>
            </div>}
          </>}
        </section>
      </>}
  </section>
}
