export type OfflineText = {
  id:string; chat:string; body:string; reply:string|null; at:string
}
export type OfflineState = 'queued'|'retry'|'failed'
export type OfflineEntry = OfflineText & {state:OfflineState|'damaged'}
type SealedEntry = Omit<OfflineText,'body'|'reply'> & {
  owner:string; state:OfflineState; iv:Uint8Array<ArrayBuffer>; ciphertext:ArrayBuffer
}

const encoder=new TextEncoder()
const decoder=new TextDecoder()
let opened:Promise<IDBDatabase>|null=null

function database(){
  if(!opened)opened=new Promise<IDBDatabase>((resolve,reject)=>{
    const request=indexedDB.open('sectalk-offline-messages',1)
    request.onupgradeneeded=()=>{
      request.result.createObjectStore('keys')
      request.result.createObjectStore('messages',{keyPath:['owner','id']}).createIndex('owner','owner')
    }
    request.onsuccess=()=>{
      const db=request.result
      db.onversionchange=()=>{db.close();opened=null}
      resolve(db)
    }
    request.onerror=()=>{opened=null;reject(request.error)}
    request.onblocked=()=>{opened=null;reject(new Error('Offline storage is busy'))}
  })
  return opened
}

async function transaction<T>(store:string,mode:IDBTransactionMode,run:(table:IDBObjectStore,result:(value:T)=>void)=>void){
  const db=await database()
  return new Promise<T>((resolve,reject)=>{
    const tx=db.transaction(store,mode)
    let value:T
    tx.oncomplete=()=>resolve(value)
    tx.onabort=()=>reject(tx.error||new Error('Offline storage write was interrupted'))
    tx.onerror=()=>reject(tx.error)
    run(tx.objectStore(store),result=>{value=result})
  })
}

async function keyFor(owner:string,create=false){
  const existing=await transaction<CryptoKey|undefined>('keys','readonly',(store,save)=>{
    const request=store.get(owner)
    request.onsuccess=()=>save(request.result)
  })
  if(existing||!create)return existing
  const candidate=await crypto.subtle.generateKey({name:'AES-GCM',length:256},false,['encrypt','decrypt'])
  return transaction<CryptoKey>('keys','readwrite',(store,save)=>{
    const request=store.get(owner)
    request.onsuccess=()=>{
      const found=request.result as CryptoKey|undefined
      if(!found)store.add(candidate,owner)
      save(found||candidate)
    }
  })
}

function associatedData({owner,chat,id,at}:Pick<SealedEntry,'owner'|'chat'|'id'|'at'>){
  return encoder.encode(JSON.stringify(['sectalk-offline-message-v1',owner,chat,id,at]))
}

export async function queueOfflineText(owner:string,{id,chat,at,body,reply}:OfflineText){
  const key=await keyFor(owner,true)
  if(!key)throw new Error('Offline encryption is unavailable')
  const iv=crypto.getRandomValues(new Uint8Array(12))
  const address={owner,chat,id,at}
  const ciphertext=await crypto.subtle.encrypt({name:'AES-GCM',iv,additionalData:associatedData(address)},
    key,encoder.encode(JSON.stringify({body,reply})))
  await transaction('messages','readwrite',store=>{store.add({...address,state:'queued',iv,ciphertext})})
}

export async function readOfflineTexts(owner:string):Promise<OfflineEntry[]>{
  const rows=await transaction<SealedEntry[]>('messages','readonly',(store,save)=>{
    const request=store.index('owner').getAll(owner)
    request.onsuccess=()=>save(request.result)
  })
  if(!rows.length)return []
  const key=await keyFor(owner)
  const output=await Promise.all(rows.map(async (row):Promise<OfflineEntry>=>{
    const address={id:row.id,chat:row.chat,at:row.at}
    const damaged:OfflineEntry={...address,body:'Encrypted message unavailable',reply:null,state:'damaged'}
    if(!key)return damaged
    try{
      const plaintext=await crypto.subtle.decrypt({name:'AES-GCM',iv:row.iv,additionalData:associatedData(row)},key,row.ciphertext)
      const {body,reply}=JSON.parse(decoder.decode(plaintext))
      if(typeof body!=='string'||(reply!==null&&typeof reply!=='string'))return damaged
      return {...address,body,reply,state:row.state}
    }catch{return damaged}
  }))
  return output.sort((a,b)=>a.at.localeCompare(b.at)||a.id.localeCompare(b.id))
}

export async function setOfflineState(owner:string,id:string,state:OfflineState){
  await transaction('messages','readwrite',store=>{
    const request=store.get([owner,id])
    request.onsuccess=()=>{if(request.result)store.put({...request.result,state})}
  })
}

export async function removeOfflineText(owner:string,id:string){
  await transaction('messages','readwrite',store=>{store.delete([owner,id])})
}
