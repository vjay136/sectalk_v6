import type {OlmMachine} from '@matrix-org/matrix-sdk-crypto-wasm'
import {db} from './data'
import {binaryToBase64url} from './device-bundle'
import {groupLocalDevice} from './group-chat-crypto'
import {matrixObject,matrixUser,olmDirectoryTranscript,olmPrekeysTranscript,type MatrixObject} from './olm-directory-proof'

type ApprovedOlmDevice={owner:string;device:string;session:string;bundle:MatrixObject|null}

let library:ReturnType<typeof loadLibrary>|undefined
async function loadLibrary() {
  const sdk=await import('@matrix-org/matrix-sdk-crypto-wasm')
  await sdk.initAsync()
  return sdk
}

async function storePhrase(name:string) {
  const database=await new Promise<IDBDatabase>((resolve,reject)=>{
    const request=indexedDB.open('sectalk-olm-settings',1)
    request.onupgradeneeded=()=>request.result.createObjectStore('stores')
    request.onsuccess=()=>resolve(request.result)
    request.onerror=()=>reject(request.error)
  })
  try {
    return await new Promise<string>((resolve,reject)=>{
      const transaction=database.transaction('stores','readwrite')
      const store=transaction.objectStore('stores')
      const read=store.get(name)
      let value:string
      read.onsuccess=()=>{
        value=typeof read.result==='string'?read.result:binaryToBase64url(crypto.getRandomValues(new Uint8Array(32)).buffer)
        if (read.result===undefined) store.add(value,name)
      }
      transaction.oncomplete=()=>resolve(value)
      transaction.onerror=()=>reject(transaction.error)
      transaction.onabort=()=>reject(transaction.error)
    })
  } finally {
    database.close()
  }
}

export async function getApprovedOlmDevice(owner:string) {
  const proof=await db!.rpc('st_v8_olm_device_proof')
  if (proof.error||!proof.data||proof.data.owner!==owner) return null
  return proof.data as ApprovedOlmDevice
}

export async function withApprovedOlm<T>(expectedOwner:string,run:(machine:OlmMachine,sdk:Awaited<ReturnType<typeof loadLibrary>>,
  approval:ApprovedOlmDevice,accessToken:string)=>Promise<T>) {
  if (!window.isSecureContext||!navigator.locks||!window.indexedDB) throw new Error('Secure browser storage is unavailable.')
  const approval=await getApprovedOlmDevice(expectedOwner)
  if (!approval) throw new Error('Sign in from an approved browser first.')
  const name=`sectalk-olm-${approval.owner}-${approval.device}`
  return navigator.locks.request(name,async()=>{
    const {data}=await db!.auth.getSession()
    if (data.session?.user.id!==approval.owner) throw new Error('Sign in again before preparing this browser.')
    const live=await getApprovedOlmDevice(expectedOwner)
    if (live?.session!==approval.session||live.device!==approval.device) throw new Error('The active browser changed. Try again.')
    library??=loadLibrary().catch(error=>{library=undefined;throw error})
    const sdk=await library
    const machine=await sdk.OlmMachine.initialize(new sdk.UserId(matrixUser(approval.owner)),new sdk.DeviceId(approval.device),
      name,await storePhrase(name))
    try {
      return await run(machine,sdk,live,data.session.access_token)
    } finally {
      machine.close()
    }
  })
}

export function prepareApprovedOlmDevice(expectedOwner:string) {
  return withApprovedOlm(expectedOwner,async(machine,sdk,approval,accessToken)=>{
      const local=await groupLocalDevice(approval.owner,approval.device)
      let bundle=approval.bundle
      for(const request of await machine.outgoingRequests()) {
        if (request.type!==sdk.RequestType.KeysUpload) continue
        const requestId=request.id
        if (!requestId) throw new Error('This browser could not identify its key upload attempt.')
        const material:unknown=JSON.parse(request.body)
        if (!matrixObject(material)) throw new Error('This browser could not prepare its encryption keys.')
        if (matrixObject(material.device_keys)) bundle=material.device_keys
        if (!bundle) throw new Error('Approve a replacement browser before continuing.')
        const prekeys=matrixObject(material.one_time_keys)?material.one_time_keys:{}
        const signature={name:'ECDSA',hash:'SHA-256'}
        const [bundleProof,uploadProof]=await Promise.all([
          crypto.subtle.sign(signature,local.signing.privateKey,olmDirectoryTranscript(approval.owner,approval.device,bundle)).then(binaryToBase64url),
          crypto.subtle.sign(signature,local.signing.privateKey,olmPrekeysTranscript(approval.owner,approval.device,approval.session,bundle,prekeys)).then(binaryToBase64url),
        ])
        const published=await fetch('/api/e2ee/device',{
          method:'POST',cache:'no-store',headers:{Authorization:`Bearer ${accessToken}`,'Content-Type':'application/json'},
          body:JSON.stringify({bundle,prekeys,bundleProof,uploadProof}),signal:AbortSignal.timeout(6000),
        })
        if (!published.ok) throw new Error(published.status===409?'Approve a replacement browser before continuing.':'Could not publish the browser encryption keys.')
        await machine.markRequestAsSent(requestId,request.type,await published.text())
      }
      return Boolean(bundle)
  })
}
