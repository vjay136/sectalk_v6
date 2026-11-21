import type {OlmMachine,ToDeviceRequest} from '@matrix-org/matrix-sdk-crypto-wasm'
import {db} from './data'
import {base64urlToBinary} from './device-bundle'
import {contactKeyStorage,contactSafetyNumber,type ManifestEntry} from './contact-key-verification'
import {withApprovedOlm} from './olm-browser'
import {matrixObject,matrixUser,olmDirectoryTranscript,verifyOlmPublish,type MatrixObject} from './olm-directory-proof'

type PairState={enabled:boolean;optedIn:boolean;epoch:string|null;device:string}
type Device={owner:string;device:string;signing_key:string;agreement_key:string;bundle_signature:string;
  bundle:MatrixObject|null;proof:string|null}
type PairDirectory={members:string[];device:string;roster:Device[]}
type CipherEvent={id:string;sequence:string;actor:string;device:string;epoch:string;cipher:MatrixObject;sent:string}
type IncomingPacket={message:string;actor:string;packet:MatrixObject}
type Page={events:CipherEvent[];packets:IncomingPacket[];before:string|null}
export type SecureDirectMessage=Pick<CipherEvent,'id'|'sequence'|'actor'|'sent'>&{body:string|null}
export type SecureDelivery={message:string;epoch:string;cipher:MatrixObject;
  packets:Array<{recipient:string;packet:MatrixObject}>;receipts:Array<{id:string;type:ToDeviceRequest['type']}>}

const roomIdentifier=(chat:string,epoch:string)=>`!${chat}-${epoch}:sectalk.invalid`

export async function getSecurePair(chat:string,enable=false) {
  const result=await db!.rpc('st_v8_olm_pair_state',{p_chat:chat,p_enable:enable})
  if(result.error)throw result.error
  return result.data as PairState
}

async function trustedDirectory(chat:string,owner:string,peer:string) {
  const response=await db!.rpc('st_v8_olm_pair_directory',{p_chat:chat})
  if(response.error)throw response.error
  const roster=response.data as PairDirectory
  if(roster.members.length!==2||!roster.members.includes(owner)||!roster.members.includes(peer))throw new Error('The contact scope changed.')
  const manifests:ManifestEntry[]=roster.roster.map(item=>({owner_id:item.owner,device:item.device,
    signing_key:item.signing_key,agreement_key:item.agreement_key,bundle_signature:item.bundle_signature}))
  const comparison=await contactSafetyNumber(manifests,owner,peer)
  if(!comparison||window.localStorage.getItem(contactKeyStorage(owner,peer))!==comparison.fingerprint) {
    throw new Error('Compare and verify your contact’s current safety number before opening secure messages.')
  }
  const devices=await Promise.all(roster.roster.filter(item=>item.bundle&&item.proof).map(async item=>{
    const bundle=item.bundle!
    const signature=base64urlToBinary(item.proof!)
    const key=await crypto.subtle.importKey('raw',base64urlToBinary(item.signing_key),{name:'ECDSA',namedCurve:'P-256'},false,['verify'])
    const verified=await crypto.subtle.verify({name:'ECDSA',hash:'SHA-256'},key,signature,olmDirectoryTranscript(item.owner,item.device,bundle))
    if(!verified||!await verifyOlmPublish(item.owner,item.device,bundle,{})) {
      throw new Error('A signed secure browser key could not be verified.')
    }
    return {...item,bundle}
  }))
  return {devices,context:roster}
}

type Sdk=typeof import('@matrix-org/matrix-sdk-crypto-wasm')
type ReadyDevice=Awaited<ReturnType<typeof trustedDirectory>>['devices'][number]

async function syncTrustedKeys(machine:OlmMachine,sdk:Sdk,members:string[],devices:ReadyDevice[]) {
  const users=members.map(matrixUser)
  const query=machine.queryKeysForUsers(users.map(user=>new sdk.UserId(user)))
  if(!query.id)throw new Error('Could not identify the approved-device directory request.')
  const returned=Object.fromEntries(users.map(user=>[user,Object.fromEntries(
    devices.filter(device=>matrixUser(device.owner)===user).map(device=>[device.device,device.bundle])
  )]))
  await machine.markRequestAsSent(query.id,query.type,JSON.stringify({device_keys:returned,failures:{}}))
  for(const item of devices) {
    const registered=await machine.getDevice(new sdk.UserId(matrixUser(item.owner)),new sdk.DeviceId(item.device))
    if(!registered||!matrixObject(item.bundle.keys)||
      registered.ed25519Key?.toBase64()!==item.bundle.keys[`ed25519:${item.device}`]||
      registered.curve25519Key?.toBase64()!==item.bundle.keys[`curve25519:${item.device}`]) {
      throw new Error('Secure browser identity changed.')
    }
    await registered.setLocalTrust(sdk.LocalTrust.Verified)
  }
}

async function pairwiseSessions(machine:OlmMachine,sdk:Sdk,chat:string,members:string[],devices:ReadyDevice[]) {
  const pending=await machine.getMissingSessions(members.map(owner=>new sdk.UserId(matrixUser(owner))))
  if(!pending)return
  if(!pending.id)throw new Error('Could not identify the secure session request.')
  const request=JSON.parse(pending.body).one_time_keys as Record<string,Record<string,unknown>>
  const approved=new Set(devices.map(device=>matrixUser(device.owner)+':'+device.device))
  const sessions=await Promise.all(Object.entries(request).map(async([user,needed])=>[user,Object.fromEntries(
    await Promise.all(Object.keys(needed).map(async device=>{
      if(!approved.has(user+':'+device))throw new Error('Secure browser permissions changed.')
      const result=await db!.rpc('st_v8_olm_claim_prekey',{p_chat:chat,p_device:device})
      if(result.error)throw result.error
      if(!result.data)throw new Error('Ask your contact to refresh the keys on their approved browser.')
      return [device,result.data]
    }))
  )]))
  await machine.markRequestAsSent(pending.id,pending.type,JSON.stringify({one_time_keys:Object.fromEntries(sessions),failures:{}}))
}

export async function sendSecureDirect(chat:string,owner:string,peer:string,body:string,pending:SecureDelivery|undefined,
  prepared:(delivery:SecureDelivery)=>void) {
  if(!body.trim()||new TextEncoder().encode(body).length>4000)throw new Error('Enter a message of up to 4,000 UTF-8 bytes.')
  return withApprovedOlm(owner,async(machine,sdk,approval)=>{
    const state=await getSecurePair(chat)
    if(!state.enabled||!state.epoch)throw new Error('Both contacts need to enable secure messages from approved browsers.')
    const {devices,context}=await trustedDirectory(chat,owner,peer)
    if(context.device!==approval.device)throw new Error('The active approved browser changed.')
    let submission=pending
    if(!submission){
      await syncTrustedKeys(machine,sdk,context.members,devices)
      await pairwiseSessions(machine,sdk,chat,context.members,devices)
      const settings=new sdk.EncryptionSettings()
      settings.sharingStrategy=sdk.CollectStrategy.onlyTrustedDevices()
      const epoch=state.epoch
      const room=()=>new sdk.RoomId(roomIdentifier(chat,epoch))
      const keyShares=await machine.shareRoomKey(room(),context.members.map(member=>new sdk.UserId(matrixUser(member))),settings)
      const packets:SecureDelivery['packets']=[]
      for(const part of keyShares){
        if(part.event_type!=='m.room.encrypted')throw new Error('A secure browser is waiting for verified session keys.')
        const delivery=JSON.parse(part.body).messages as Record<string,Record<string,MatrixObject>>
        for(const [user,recipients] of Object.entries(delivery)){
          for(const [recipient,packet] of Object.entries(recipients)){
            if(!devices.some(item=>item.device===recipient&&matrixUser(item.owner)===user))throw new Error('Secure browser permissions changed.')
            packets.push({recipient,packet})
          }
        }
      }
      const cipher=JSON.parse(await machine.encryptRoomEvent(room(),'m.room.message',JSON.stringify({body,msgtype:'m.text'})))
      submission={message:crypto.randomUUID(),epoch,cipher,packets,receipts:keyShares.map(part=>({id:part.id,type:part.type}))}
      prepared(submission)
    }
    const result=await db!.rpc('st_v8_olm_direct_send',{p_chat:chat,p_message:submission.message,p_epoch:submission.epoch,
      p_cipher:submission.cipher,p_packets:submission.packets})
    if(result.error)throw result.error
    await Promise.allSettled(submission.receipts.map(delivery=>machine.markRequestAsSent(delivery.id,delivery.type,'{}')))
  })
}

export async function openSecureDirect(chat:string,owner:string,peer:string,before?:string) {
  return withApprovedOlm(owner,async(machine,sdk,approval)=>{
    const {devices,context}=await trustedDirectory(chat,owner,peer)
    if(context.device!==approval.device)throw new Error('The active approved browser changed.')
    const response=await db!.rpc('st_v8_olm_direct_read',{p_chat:chat,p_before:before??null})
    if(response.error)throw response.error
    const page=response.data as Page
    if(page.events.length)await syncTrustedKeys(machine,sdk,context.members,devices)
    await machine.receiveSyncChangesMsc4186(JSON.stringify(page.packets.map(item=>({
      sender:matrixUser(item.actor),type:'m.room.encrypted',content:item.packet,
    }))),new sdk.DeviceLists(),new Map())
    const messages:SecureDirectMessage[]=[]
    for(const item of page.events) {
      const author=devices.find(device=>device.owner===item.actor&&device.device===item.device)
      let body:string|null=null
      if(author&&matrixObject(author.bundle.keys)){
        try{
          const event=await machine.decryptRoomEvent(JSON.stringify({type:'m.room.encrypted',event_id:'$'+item.id,
            sender:matrixUser(item.actor),origin_server_ts:Date.parse(item.sent),content:item.cipher}),
            new sdk.RoomId(roomIdentifier(chat,item.epoch)),new sdk.DecryptionSettings(sdk.TrustRequirement.Untrusted))
          const message=JSON.parse(event.event)
          if(event.senderDevice?.toString()===author.device&&event.senderClaimedEd25519Key===author.bundle.keys[`ed25519:${author.device}`]&&
            message.type==='m.room.message'&&message.content?.msgtype==='m.text'&&typeof message.content.body==='string')body=message.content.body
        }catch { /* Unverified history stays unavailable in the interface. */ }
      }
      messages.push({id:item.id,sequence:item.sequence,actor:item.actor,sent:item.sent,body})
    }
    return {messages,before:page.before}
  })
}
