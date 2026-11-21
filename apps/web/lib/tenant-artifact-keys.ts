import { createCipheriv, createDecipheriv, createHash, randomBytes } from 'node:crypto'
import type { SupabaseClient } from '@supabase/supabase-js'

type Custody = 'managed' | 'byok'
type BoundKey = { workspace: string; version: number; custody: Custody; ref: string | null }
export type TenantRecordKey = BoundKey & { wrapped: string }
// Rewrapped records keep the original ciphertext version and use the new key only for the capsule.
export type TenantRecordEnvelope = { body: string; nonce: string; tag: string; wrapped_dek: string; data_version?: number }
type EnvelopeContext = {
  workspace: string; kind: 'evidence' | 'compliance'; sha256: string; bytes: number;
  version: number | null; custody: Custody | null; ref: string | null; wrapped: string | null;
  wrapped_dek: string | null; nonce: string | null; tag: string | null;
  data_version?: number | null;
  rewrap?: { source_revision: string; policy_revision: string; version: number; wrapped: string } | null;
}
const uuid = /^[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$/
const refPattern = /^[A-Za-z0-9_-]{1,96}$/
const b64 = /^[A-Za-z0-9_-]+$/
const encoded = (value: Buffer) => value.toString('base64url')
const associated = (...parts: (string | number)[]) => Buffer.from(JSON.stringify(parts),'utf8')
const externalMarker = 'external_v2_'
const externalKeyId = /^[A-Za-z0-9_.:/-]{1,200}$/

function decode(value: unknown, bytes: number) {
  if (typeof value!=='string' || !b64.test(value) || value.length!==Math.ceil(bytes*8/6)) throw new Error('Invalid key envelope')
  const result = Buffer.from(value,'base64url')
  if (result.length!==bytes || encoded(result)!==value) throw new Error('Invalid key envelope')
  return result
}

function seal(key: Buffer, plain: Buffer, data: Buffer) {
  const nonce = randomBytes(12)
  const cipher = createCipheriv('aes-256-gcm',key,nonce).setAAD(data)
  const ciphertext = Buffer.concat([cipher.update(plain),cipher.final()])
  return { nonce,ciphertext,tag:cipher.getAuthTag() }
}
function unseal(key: Buffer, nonce: Buffer, ciphertext: Buffer, tag: Buffer, data: Buffer) {
  const decipher = createDecipheriv('aes-256-gcm',key,nonce).setAAD(data).setAuthTag(tag)
  return Buffer.concat([decipher.update(ciphertext),decipher.final()])
}
function wrap(key: Buffer, target: Buffer, data: Buffer) {
  const value = seal(key,target,data)
  return encoded(Buffer.concat([value.nonce,value.tag,value.ciphertext]))
}
function unwrap(key: Buffer, value: string, data: Buffer) {
  const capsule=decode(value,60)
  return unseal(key,capsule.subarray(0,12),capsule.subarray(28),capsule.subarray(12,28),data)
}

function fixture(workspace: string, existingRef?: string) {
  const localBackend=URL.parse(process.env.NEXT_PUBLIC_SUPABASE_URL ?? '')
  const endpoint=URL.parse(process.env.SECTALK_KMS_BYOK_FIXTURE_URL ?? '')
  const token=process.env.SECTALK_KMS_BYOK_FIXTURE_TOKEN
  if (localBackend?.protocol!=='http:' || localBackend.hostname!=='127.0.0.1' || endpoint?.protocol!=='http:'
    || endpoint.hostname!=='127.0.0.1' || !endpoint.port || endpoint.pathname!=='/tenant-key'
    || endpoint.username || endpoint.password || endpoint.hash || endpoint.search
    || !token || !/^[A-Za-z0-9_-]{24,128}$/.test(token)) throw new Error('External key custody is unavailable')
  const entries=JSON.parse(process.env.SECTALK_KMS_BYOK_FIXTURE_REFS ?? '{}') as Record<string,string | string[]>
  const configured=Object.hasOwn(entries,workspace) ? entries[workspace] : null
  const references=Array.isArray(configured) ? configured : [configured]
  const ref=existingRef ?? references[0]
  if (typeof ref!=='string' || !refPattern.test(ref) || !references.includes(ref)) throw new Error('External key custody is unavailable')
  return { endpoint,token,ref }
}
async function provider(operation: 'wrap' | 'unwrap', key: BoundKey, value: string) {
  const target=fixture(key.workspace,key.ref ?? undefined)
  const response=await fetch(target.endpoint,{
    method:'POST',redirect:'error',cache:'no-store',signal:AbortSignal.timeout(2500),
    headers:{Authorization:'Bearer '+target.token,'Content-Type':'application/json'},
    body:JSON.stringify({operation,workspace:key.workspace,version:key.version,reference:target.ref,value}),
  })
  if (!response.ok || !response.body) throw new Error('External key custody is unavailable')
  const reader=response.body.getReader()
  const parts: Buffer[]=[]
  let total=0
  try {
    while (true) {
      const {done,value:part}=await reader.read()
      if (done) break
      total+=part.byteLength
      if (total>2200) { await reader.cancel(); throw new Error('Invalid key envelope') }
      parts.push(Buffer.from(part))
    }
  } finally { reader.releaseLock() }
  const result=JSON.parse(Buffer.concat(parts).toString('utf8')).value
  if (typeof result!=='string' || result.length<40 || result.length>2048 || !b64.test(result)) throw new Error('Invalid key envelope')
  return result
}
const keyContext = (key: BoundKey) => associated('sectalk/tenant-kek/v1',key.workspace,key.version,key.custody)

function externalConfiguration(workspace: string, version: number, pinnedRef?: string) {
  const endpoint=URL.parse(process.env.SECTALK_EXTERNAL_KMS_URL ?? '')
  const token=process.env.SECTALK_EXTERNAL_KMS_TOKEN
  const database=URL.parse(process.env.NEXT_PUBLIC_SUPABASE_URL ?? '')
  const loopback=!process.env.VERCEL && database?.origin==='http://127.0.0.1:55321'
    && endpoint?.protocol==='http:' && endpoint.hostname==='127.0.0.1' && !!endpoint.port
  if (!endpoint || (endpoint.protocol!=='https:' && !loopback) || endpoint.pathname!=='/v1/tenant-dek'
    || endpoint.username || endpoint.password || endpoint.search || endpoint.hash ||
    !token || !/^[A-Za-z0-9_-]{24,128}$/.test(token) || !uuid.test(workspace) ||
    !Number.isSafeInteger(version) || version<1) throw new Error('External key custody is unavailable')
  const mappings=JSON.parse(process.env.SECTALK_EXTERNAL_KMS_KEYS ?? '{}')
  const mapped=mappings && Object.hasOwn(mappings,workspace) ? mappings[workspace] : null
  const ref=pinnedRef ?? mapped?.active
  const keyId=mapped?.keys && typeof ref==='string' && Object.hasOwn(mapped.keys,ref) ? mapped.keys[ref] : null
  if (typeof ref!=='string' || !refPattern.test(ref) || typeof keyId!=='string' || !externalKeyId.test(keyId)) {
    throw new Error('External key custody is unavailable')
  }
  const pin=createHash('sha256').update(associated('sectalk/external-key-pin/v2',endpoint.origin,keyId)).digest('base64url')
  const binding=createHash('sha256').update(associated('sectalk/external-key/v2',pin,workspace,version,ref)).digest('base64url')
  const marker=externalMarker+pin+'_'+binding
  return { endpoint,token,ref,keyId,marker }
}

export function pinnedExternalTenantKey(workspace:string,version:number,reference:string,marker:string) {
  const target=externalConfiguration(workspace,version,reference)
  if (target.marker!==marker) throw new Error('External key reference has changed')
  return target.keyId
}

async function externalDek(target: ReturnType<typeof externalConfiguration>, key: BoundKey,
  aad: Buffer, operation: 'wrap' | 'unwrap', value: string) {
  const scopeDigest=createHash('sha256').update(aad).digest('base64url')
  const context=encoded(associated('sectalk/external-dek/v2',key.workspace,key.version,target.ref,target.keyId,scopeDigest))
  const response=await fetch(target.endpoint,{
    method:'POST',redirect:'error',cache:'no-store',signal:AbortSignal.timeout(2500),
    headers:{Authorization:'Bearer '+target.token,'Content-Type':'application/json'},
    body:JSON.stringify({operation,workspace:key.workspace,version:key.version,reference:target.ref,keyId:target.keyId,context,value}),
  })
  if (!response.ok || !response.body) {
    void response.body?.cancel().catch(()=>undefined)
    throw new Error('External key custody is unavailable')
  }
  const reader=response.body.getReader()
  const parts: Buffer[]=[]
  let total=0
  try {
    for (;;) {
      const {done,value:part}=await reader.read()
      if (done) break
      total+=part.byteLength
      if (total>8192) { void reader.cancel().catch(()=>undefined); throw new Error('Invalid key provider response') }
      parts.push(Buffer.from(part))
    }
  } finally { reader.releaseLock() }
  const result=JSON.parse(Buffer.concat(parts).toString('utf8'))
  if (result?.keyId!==target.keyId || result.context!==context ||
    typeof result.value!=='string' || !b64.test(result.value) ||
    result.value.length<(operation==='wrap'?80:43) || result.value.length>2048) throw new Error('Invalid key provider response')
  return result.value as string
}

export async function wrapFreshTenantKey(workspace: string, version: number, custody: Custody) {
  if (custody==='byok' && process.env.SECTALK_EXTERNAL_KMS_URL) {
    const target=externalConfiguration(workspace,version)
    const key={workspace,version,custody,ref:target.ref}
    const aad=associated('sectalk/external-rotation-probe/v2',workspace,version)
    const probe=randomBytes(32)
    let check: Buffer | undefined
    try {
      const capsule=await externalDek(target,key,aad,'wrap',encoded(probe))
      check=decode(await externalDek(target,key,aad,'unwrap',capsule),32)
      if (!probe.equals(check)) throw new Error('External custody rotation proof failed')
      return {ref:target.ref,wrapped:target.marker}
    } finally {probe.fill(0);check?.fill(0)}
  }
  const ref=custody==='byok' ? fixture(workspace).ref : null
  const target={workspace,version,custody,ref}
  const key=randomBytes(32)
  try {
    if (custody==='byok') return { ref,wrapped:await provider('wrap',target,encoded(key)) }
    const root=decode(process.env.SECTALK_KMS_WRAPPING_KEY,32)
    try { return { ref,wrapped:wrap(root,key,keyContext(target)) } } finally { root.fill(0) }
  } finally { key.fill(0) }
}

async function tenantKey(key: BoundKey, wrapped: string) {
  if (key.custody==='byok') return decode(await provider('unwrap',key,wrapped),32)
  const root=decode(process.env.SECTALK_KMS_WRAPPING_KEY,32)
  try { return unwrap(root,wrapped,keyContext(key)) } finally { root.fill(0) }
}

function withDek(key: TenantRecordKey, aad: Buffer, value: Buffer): Promise<string>
function withDek(key: TenantRecordKey, aad: Buffer, value: string): Promise<Buffer>
async function withDek(key: TenantRecordKey, aad: Buffer, value: Buffer | string): Promise<Buffer | string> {
  if (key.custody==='byok' && key.wrapped.startsWith(externalMarker)) {
    if (!key.ref) throw new Error('External key reference is unavailable')
    const target=externalConfiguration(key.workspace,key.version,key.ref)
    if (target.marker!==key.wrapped) throw new Error('External key reference has changed')
    return typeof value==='string' ? decode(await externalDek(target,key,aad,'unwrap',value),32) :
      externalDek(target,key,aad,'wrap',encoded(value))
  }
  const kek=await tenantKey(key,key.wrapped)
  try {return typeof value==='string' ? unwrap(kek,value,aad) : wrap(kek,value,aad)}
  finally {kek.fill(0)}
}

export async function sealTenantRecord(key: TenantRecordKey, scope: string, record: string, actor: string, plaintext: Buffer) {
  const dek=randomBytes(32)
  const aad=tenantRecordContext(key.workspace,scope,record,actor,key.version)
  try {
    const payload=seal(dek,plaintext,aad)
    return { body:encoded(payload.ciphertext),nonce:encoded(payload.nonce),tag:encoded(payload.tag),
      wrapped_dek:await withDek(key,Buffer.concat([aad,Buffer.from([1])]),dek) }
  } finally { dek.fill(0) }
}

const tenantRecordContext = (workspace: string, scope: string, record: string, actor: string, version: number) =>
  associated('sectalk/managed-channel/v1',workspace,scope,record,actor,version)

function managedCiphertext(body: string) {
  if (!b64.test(body) || body.length>24000) throw new Error('Invalid managed ciphertext')
  const ciphertext=Buffer.from(body,'base64url')
  if (encoded(ciphertext)!==body || ciphertext.length<1 || ciphertext.length>18000) throw new Error('Invalid managed ciphertext')
  return ciphertext
}

function recordDataVersion(key: TenantRecordKey, payload: TenantRecordEnvelope) {
  const version=payload.data_version ?? key.version
  if (!Number.isSafeInteger(version) || version<1 || version>key.version) throw new Error('Invalid managed data version')
  return version
}

export async function openTenantRecord(key: TenantRecordKey, scope: string, record: string, actor: string, payload: TenantRecordEnvelope) {
  const ciphertext=managedCiphertext(payload.body)
  const wrapping=tenantRecordContext(key.workspace,scope,record,actor,key.version)
  const data=tenantRecordContext(key.workspace,scope,record,actor,recordDataVersion(key,payload))
  let dek: Buffer | undefined
  try {
    dek=await withDek(key,Buffer.concat([wrapping,Buffer.from([1])]),payload.wrapped_dek)
    return unseal(dek,decode(payload.nonce,12),ciphertext,decode(payload.tag,16),data)
  } finally { dek?.fill(0) }
}

export async function rewrapManagedTenantRecord(source: TenantRecordKey,target: TenantRecordKey,scope: string,record: string,
  actor: string,payload: TenantRecordEnvelope) {
  if (source.workspace!==target.workspace || source.custody!=='managed' || target.custody!=='managed' ||
    source.ref!==null || target.ref!==null || target.version<=source.version) throw new Error('Invalid managed rewrap scope')
  const dataVersion=recordDataVersion(source,payload)
  const original=tenantRecordContext(source.workspace,scope,record,actor,source.version)
  const replacement=tenantRecordContext(target.workspace,scope,record,actor,target.version)
  const data=tenantRecordContext(source.workspace,scope,record,actor,dataVersion)
  const ciphertext=managedCiphertext(payload.body)
  const nonce=decode(payload.nonce,12), tag=decode(payload.tag,16)
  let dek: Buffer | undefined, originalContent: Buffer | undefined, verifiedContent: Buffer | undefined
  try {
    dek=await withDek(source,Buffer.concat([original,Buffer.from([1])]),payload.wrapped_dek)
    originalContent=unseal(dek,nonce,ciphertext,tag,data)
    const wrapped_dek=await withDek(target,Buffer.concat([replacement,Buffer.from([1])]),dek)
    verifiedContent=await openTenantRecord(target,scope,record,actor,{...payload,wrapped_dek,data_version:dataVersion})
    if (!originalContent.equals(verifiedContent)) throw new Error('Managed rewrap changed the authenticated content')
    return wrapped_dek
  } finally { dek?.fill(0); originalContent?.fill(0); verifiedContent?.fill(0) }
}

async function context(storage: SupabaseClient, ticket: string, artifact: string, operation: 'read' | 'write') {
  const result=await storage.rpc('st_v7_export_key_context',{p_ticket:ticket,p_artifact:artifact,p_mode:operation})
  if (result.error || !result.data) throw new Error('Artifact key unavailable')
  if (operation==='read' && result.data.legacy===true) return null
  const value=result.data as EnvelopeContext
  if (!uuid.test(value.workspace) || !['compliance','evidence'].includes(value.kind) || !/^[a-f0-9]{64}$/.test(value.sha256)
    || !Number.isInteger(value.bytes) || value.bytes<1 || value.bytes>1048576) throw new Error('Invalid artifact key context')
  return value
}

const artifactContext = (value: EnvelopeContext, artifact: string, label: string, version = value.version!) =>
  associated('sectalk/export/v1',label,value.workspace,artifact,value.kind,value.sha256,value.bytes,version)

function wrappedKey(value: EnvelopeContext) {
  if (value.version===null || !Number.isSafeInteger(value.version) || value.version<1 || !value.custody ||
    !['managed','byok'].includes(value.custody) || !value.wrapped) throw new Error('Artifact key unavailable')
  return {workspace:value.workspace,custody:value.custody,ref:value.ref,version:value.version,wrapped:value.wrapped}
}

export async function encryptManagedArtifact(storage: SupabaseClient, ticket: string, artifact: string, plaintext: Buffer) {
  let value=await context(storage,ticket,artifact,'write')
  if (!value) throw new Error('Artifact key unavailable')
  if (value.version===null) {
    const wrapped=await wrapFreshTenantKey(value.workspace,1,'managed')
    const provision=await storage.rpc('st_v7_provision_export_key',{p_ticket:ticket,p_artifact:artifact,p_wrapped:wrapped.wrapped})
    if (provision.error) throw new Error('Artifact key unavailable')
    value=await context(storage,ticket,artifact,'write')
  }
  if (!value || value.bytes!==plaintext.length) throw new Error('Invalid artifact size')
  const key=wrappedKey(value)
  const dek=randomBytes(32)
  try {
    const payload=seal(dek,plaintext,artifactContext(value,artifact,'data'))
    const envelope=await withDek(key,artifactContext(value,artifact,'data-key'),dek)
    const bound=await storage.rpc('st_v7_bind_export_envelope',{
      p_ticket:ticket,p_artifact:artifact,p_version:value.version,p_key:envelope,p_nonce:encoded(payload.nonce),p_tag:encoded(payload.tag),
    })
    if (bound.error || bound.data!==true) throw new Error('Artifact key unavailable')
    return payload.ciphertext
  } finally { dek.fill(0) }
}

export async function decryptManagedArtifact(storage: SupabaseClient, ticket: string, artifact: string, ciphertext: Buffer) {
  const value=await context(storage,ticket,artifact,'read')
  if (!value) return ciphertext
  if (value.bytes!==ciphertext.length || !value.wrapped_dek) throw new Error('Invalid artifact size')
  const key=wrappedKey(value)
  const dataVersion=value.data_version??key.version
  if (!Number.isSafeInteger(dataVersion) || dataVersion<1 || dataVersion>key.version) throw new Error('Invalid artifact data version')
  const data=artifactContext(value,artifact,'data',dataVersion)
  const nonce=decode(value.nonce,12), tag=decode(value.tag,16)
  let dek: Buffer | undefined
  try {
    dek=await withDek(key,artifactContext(value,artifact,'data-key'),value.wrapped_dek)
    const plaintext=unseal(dek,nonce,ciphertext,tag,data)
    const target=value.rewrap
    if (key.custody==='managed' && key.ref===null && target && Number.isSafeInteger(target.version) && target.version>key.version &&
      /^[a-f0-9]{64}$/.test(target.source_revision) && uuid.test(target.policy_revision) &&
      createHash('sha256').update(plaintext).digest('hex')===value.sha256) {
      let checkedDek:Buffer|undefined, checkedPlaintext:Buffer|undefined
      try {
        const replacement={...key,version:target.version,wrapped:target.wrapped}
        const wrapping=artifactContext(value,artifact,'data-key',target.version)
        const capsule=await withDek(replacement,wrapping,dek)
        checkedDek=await withDek(replacement,wrapping,capsule)
        checkedPlaintext=unseal(checkedDek,nonce,ciphertext,tag,data)
        if (plaintext.equals(checkedPlaintext)) {
          await storage.rpc('st_v8_commit_protected_artifact_rewrap',{
            p_ticket:ticket,p_artifact:artifact,p_policy_revision:target.policy_revision,p_source_revision:target.source_revision,
            p_previous:key.version,p_target:target.version,p_wrapped_dek:capsule,
          })
        }
      } catch {
        // The authenticated download can continue with the valid original envelope.
      } finally { checkedDek?.fill(0); checkedPlaintext?.fill(0) }
    }
    return plaintext
  } finally { dek?.fill(0) }
}
