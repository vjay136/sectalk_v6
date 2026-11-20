import { db } from './data'
import { binaryToBase64url, deviceBindingTranscript, deviceBundleTranscript, type DeviceChallenge } from './device-bundle'

export type LocalDevice = {
  id: string
  owner: string
  signing: CryptoKeyPair
  agreement: CryptoKeyPair
}
const storageName='sectalk-device-identity'
export const keyStore='identities'
export const deviceReceiptStore='command-receipts'

export function openDeviceStore(): Promise<IDBDatabase> {
  return new Promise((resolve,reject)=>{
    const request=indexedDB.open(storageName,2)
    request.onupgradeneeded=()=>{
      if (!request.result.objectStoreNames.contains(keyStore)) request.result.createObjectStore(keyStore,{keyPath:'owner'})
      if (!request.result.objectStoreNames.contains(deviceReceiptStore))
        request.result.createObjectStore(deviceReceiptStore,{keyPath:'command'})
    }
    request.onerror=()=>reject(request.error)
    request.onsuccess=()=>{
      request.result.onversionchange=()=>request.result.close()
      resolve(request.result)
    }
  })
}

async function readDevice(database: IDBDatabase, owner: string) {
  return new Promise<LocalDevice|undefined>((resolve,reject)=>{
    const request=database.transaction(keyStore).objectStore(keyStore).get(owner)
    request.onsuccess=()=>resolve(request.result)
    request.onerror=()=>reject(request.error)
  })
}

async function persistDevice(database: IDBDatabase, candidate: LocalDevice) {
  return new Promise<LocalDevice>((resolve,reject)=>{
    const transaction=database.transaction(keyStore,'readwrite')
    const store=transaction.objectStore(keyStore)
    const present=store.get(candidate.owner)
    let chosen=candidate
    present.onsuccess=()=>{
      if (present.result) chosen=present.result
      else store.add(candidate)
    }
    transaction.oncomplete=()=>resolve(chosen)
    transaction.onerror=()=>reject(transaction.error)
    transaction.onabort=()=>reject(transaction.error)
  })
}

async function localDevice(owner: string) {
  if (!window.isSecureContext || !crypto.subtle || !window.indexedDB) throw new Error('Secure device storage is unavailable')
  const database=await openDeviceStore()
  try {
    const existing=await readDevice(database,owner)
    if (existing) return existing
    const [signing,agreement]=await Promise.all([
      crypto.subtle.generateKey({name:'ECDSA',namedCurve:'P-256'},false,['sign','verify']),
      crypto.subtle.generateKey({name:'ECDH',namedCurve:'P-256'},false,['deriveBits']),
    ])
    return await persistDevice(database,{id:crypto.randomUUID(),owner,signing,agreement})
  } finally {database.close()}
}

export async function enrollCurrentDevice() {
  const session=await db!.auth.getSession()
  if (session.error || !session.data.session) throw new Error('Sign in to register this device')
  const local=await localDevice(session.data.session.user.id)
  const [signing,agreement]=await Promise.all([
    crypto.subtle.exportKey('raw',local.signing.publicKey).then(binaryToBase64url),
    crypto.subtle.exportKey('raw',local.agreement.publicKey).then(binaryToBase64url),
  ])
  const begin=await db!.rpc('st_v7_begin_device_bundle',{p_device:local.id,p_signing:signing,p_agreement:agreement})
  if (begin.error || !begin.data || begin.data.owner!==local.owner || begin.data.device!==local.id)
    throw new Error('Could not register this device')
  const challenge={...begin.data,signing,agreement} as DeviceChallenge
  const params={name:'ECDSA',hash:'SHA-256'}
  const [signature,binding]=await Promise.all([
    crypto.subtle.sign(params,local.signing.privateKey,deviceBundleTranscript(challenge)).then(binaryToBase64url),
    crypto.subtle.sign(params,local.signing.privateKey,deviceBindingTranscript(challenge)).then(binaryToBase64url),
  ])
  const result=await fetch('/api/account/devices/bundle',{
    method:'POST',headers:{'Content-Type':'application/json',Authorization:'Bearer '+session.data.session.access_token},
    body:JSON.stringify({challenge:challenge.challenge,signature,binding}),cache:'no-store',
  })
  if (!result.ok) throw new Error(result.status===409 ? 'This device is unavailable for registration' : 'Could not verify this device')
}
