const encode=new TextEncoder()
const keyPattern=/^[A-Za-z0-9+/]{43}$/
const signaturePattern=/^[A-Za-z0-9+/]{86}$/
const prekeyName=/^signed_curve25519:[A-Za-z0-9_+/-]{1,64}$/

export type MatrixObject=Record<string,unknown>

export function matrixObject(value:unknown):value is MatrixObject {
  return value!==null && typeof value==='object' && !Array.isArray(value)
}

export function matrixUser(owner:string) {return `@${owner}:sectalk.invalid`}

function canonical(value:unknown):string {
  if (value===null || typeof value==='string' || typeof value==='boolean') return JSON.stringify(value)
  if (typeof value==='number' && Number.isSafeInteger(value)) return JSON.stringify(value)
  if (Array.isArray(value)) return `[${value.map(canonical).join(',')}]`
  if (matrixObject(value)) {
    return `{${Object.keys(value).sort().map(key=>`${JSON.stringify(key)}:${canonical(value[key])}`).join(',')}}`
  }
  throw new Error('Key material must use canonical JSON values.')
}

export function olmDirectoryTranscript(owner:string,device:string,bundle:MatrixObject) {
  return encode.encode(canonical(['sectalk-olm-device-v1',owner,device,bundle]))
}

export function olmPrekeysTranscript(owner:string,device:string,session:string,bundle:MatrixObject,prekeys:MatrixObject) {
  return encode.encode(canonical(['sectalk-olm-prekeys-v1',owner,device,session,bundle,prekeys]))
}

function raw(value:string) {
  return Uint8Array.from(atob(value),character=>character.charCodeAt(0))
}

async function validMatrixSignature(key:CryptoKey,owner:string,device:string,value:MatrixObject) {
  const signatures=value.signatures
  const user=matrixUser(owner)
  if (!matrixObject(signatures)) return false
  const author=signatures[user]
  if (!matrixObject(author)) return false
  const signature=author[`ed25519:${device}`]
  if (typeof signature!=='string'||!signaturePattern.test(signature)) return false
  const signed: MatrixObject={...value}
  delete signed.signatures
  delete signed.unsigned
  return crypto.subtle.verify('Ed25519',key,raw(signature),encode.encode(canonical(signed)))
}

export async function verifyOlmPublish(owner:string,device:string,bundle:MatrixObject,prekeys:MatrixObject) {
  if (bundle.user_id!==matrixUser(owner) || bundle.device_id!==device || !matrixObject(bundle.keys) ||
    !Array.isArray(bundle.algorithms) || !bundle.algorithms.includes('m.olm.v1.curve25519-aes-sha2')) return false
  const signing=bundle.keys[`ed25519:${device}`]
  const agreement=bundle.keys[`curve25519:${device}`]
  if (typeof signing!=='string'||typeof agreement!=='string'||!keyPattern.test(signing)||!keyPattern.test(agreement)) return false
  const entries=Object.entries(prekeys)
  if (entries.length>100) return false
  const verifier=await crypto.subtle.importKey('raw',raw(signing),'Ed25519',false,['verify'])
  if (!await validMatrixSignature(verifier,owner,device,bundle)) return false
  return (await Promise.all(entries.map(([name,value])=>prekeyName.test(name)&&matrixObject(value)&&
    typeof value.key==='string'&&keyPattern.test(value.key)&&value.fallback!==true&&
    validMatrixSignature(verifier,owner,device,value)))).every(Boolean)
}
