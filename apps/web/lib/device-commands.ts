'use client'

import { binaryToBase64url, deviceCommandTranscript } from './device-bundle'
import { openDeviceStore, deviceReceiptStore, keyStore, type LocalDevice } from './device-identity'

type Receipt={device:string;command:string;receipt:string}
type Command={id:string;kind:'revoke'|'lock'|'wipe';receipt:string}
type Poll={locked:boolean;wiped:boolean;blocked:boolean;command:Command|null}
export type DeviceProtection={device:string;locked:boolean;unavailable:boolean;wiped?:boolean;blocked?:boolean}|null

function requestResult<T>(request:IDBRequest<T>) {
  return new Promise<T>((resolve,reject)=>{
    request.onsuccess=()=>resolve(request.result)
    request.onerror=()=>reject(request.error)
  })
}

async function post(body:Record<string,unknown>) {
  return fetch('/api/account/devices/commands',{
    method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body),
    cache:'no-store',signal:AbortSignal.timeout(5000),
  })
}

async function removeReceipt(database:IDBDatabase,command:string) {
  return new Promise<void>((resolve,reject)=>{
    const transaction=database.transaction(deviceReceiptStore,'readwrite')
    transaction.objectStore(deviceReceiptStore).delete(command)
    transaction.oncomplete=()=>resolve()
    transaction.onabort=()=>reject(transaction.error)
  })
}

async function wipeIdentity(database:IDBDatabase,identity:LocalDevice,receipt?:Receipt) {
  return new Promise<void>((resolve,reject)=>{
    const transaction=database.transaction([keyStore,deviceReceiptStore],'readwrite')
    const store=transaction.objectStore(keyStore)
    const existing=store.get(identity.owner)
    existing.onsuccess=()=>{
      if (existing.result?.id===identity.id) store.delete(identity.owner)
      if (receipt) transaction.objectStore(deviceReceiptStore).put(receipt)
    }
    transaction.oncomplete=()=>resolve()
    transaction.onabort=()=>reject(transaction.error)
  })
}

async function acknowledge(database:IDBDatabase,receipt:Receipt) {
  const result=await post({mode:'ack',...receipt})
  if (result.ok) await removeReceipt(database,receipt.command)
}

async function receive(database:IDBDatabase,identity:LocalDevice):Promise<DeviceProtection> {
  try {
    const nonce=crypto.randomUUID()
    const at=new Date().toISOString()
    const proof=binaryToBase64url(await crypto.subtle.sign({name:'ECDSA',hash:'SHA-256'},
      identity.signing.privateKey,deviceCommandTranscript(identity.owner,identity.id,nonce,at)))
    const response=await post({mode:'poll',owner:identity.owner,device:identity.id,nonce,at,proof})
    if (response.status===404) return null
    if (!response.ok) throw new Error()
    const result=await response.json() as Poll
    if (result.command) {
      const receipt={device:identity.id,command:result.command.id,receipt:result.command.receipt}
      if (result.command.kind==='wipe') await wipeIdentity(database,identity,receipt)
      await acknowledge(database,receipt).catch(()=>undefined)
    }
    if (result.wiped) {
      if (!result.command) await wipeIdentity(database,identity)
      return {device:identity.id,locked:false,unavailable:false,wiped:true}
    }
    return {device:identity.id,locked:result.locked,unavailable:false,blocked:result.blocked}
  } catch {return {device:identity.id,locked:false,unavailable:true}}
}

export async function receiveDeviceCommands(owner?:string):Promise<DeviceProtection> {
  if (!window.isSecureContext||!crypto.subtle||!window.indexedDB) return null
  const database=await openDeviceStore()
  try {
    const receipts=await requestResult(database.transaction(deviceReceiptStore).objectStore(deviceReceiptStore).getAll(undefined,100)) as Receipt[]
    await Promise.allSettled(receipts.map(receipt=>acknowledge(database,receipt)))
    if (owner) {
      const identity=await requestResult(database.transaction(keyStore).objectStore(keyStore).get(owner)) as LocalDevice|undefined
      return identity?await receive(database,identity):null
    }
    const identities=await requestResult(database.transaction(keyStore).objectStore(keyStore).getAll(undefined,100)) as LocalDevice[]
    await Promise.allSettled(identities.map(identity=>receive(database,identity)))
    return null
  } finally {database.close()}
}
