import type {LocalDevice} from './device-identity'
import {base64urlToBinary,binaryToBase64url} from './device-bundle'
import {decryptGroupMessage,openGroupSenderExport,sealGroupSenderExport,signGroupMessage,verifyGroupMessage,
  type GroupCiphertext} from './group-chat-crypto'
import {withApprovedOlm} from './olm-browser'
import {matrixObject,matrixUser} from './olm-directory-proof'

const marker='sk2.'
const encoder=new TextEncoder()
const decoder=new TextDecoder('utf-8',{fatal:true})
const senderRoom=(group:string,epoch:number)=>`!group-${group}-${epoch}:sectalk.invalid`
export const usesGroupSenderKey=(payload:string)=>payload.startsWith(marker)

export async function encryptGroupSenderMessage(group:string,epoch:number,device:LocalDevice,key:CryptoKey,message:string) {
  if(!message.trim()||encoder.encode(message).length>4000)throw new Error('Enter a message of up to 4,000 UTF-8 bytes.')
  return withApprovedOlm(device.owner,async(machine,sdk,approval)=>{
    if(approval.device!==device.id)throw new Error('The active browser changed. Refresh approved devices.')
    const address=senderRoom(group,epoch)
    const room=()=>new sdk.RoomId(address)
    const shared=await machine.shareRoomKey(room(),[],new sdk.EncryptionSettings())
    if(shared.length)throw new Error('The secure sender session could not be initialized.')
    const cipher=JSON.parse(await machine.encryptRoomEvent(room(),'m.room.message',JSON.stringify({msgtype:'m.text',body:message})))
    const keys=await machine.exportRoomKeys(session=>session.roomId.toString()===address&&session.sessionId===cipher.session_id)
    if(JSON.parse(keys).length!==1)throw new Error('Could not prepare this approved browser’s sender key.')
    const sealed=await sealGroupSenderExport(key,group,epoch,device.owner,device.id,cipher.session_id,keys)
    const payload=marker+binaryToBase64url(encoder.encode(JSON.stringify({cipher,sealed})).buffer)
    return signGroupMessage(group,epoch,device,crypto.randomUUID(),payload)
  })
}

export async function withGroupSenderReader<T>(owner:string,device:string,required:boolean,
  read:(open:typeof decryptGroupMessage)=>Promise<T>) {
  if(!required)return read(decryptGroupMessage)
  return withApprovedOlm(owner,async(machine,sdk,approval)=>{
    if(approval.device!==device)throw new Error('The active browser changed. Refresh approved devices.')
    return read(async(group,key,record)=>{
      if(!usesGroupSenderKey(record.payload))return decryptGroupMessage(group,key,record)
      return decryptSenderMessage(group,key,record,machine,sdk)
    })
  })
}

async function decryptSenderMessage(group:string,key:CryptoKey,record:GroupCiphertext,machine:import('@matrix-org/matrix-sdk-crypto-wasm').OlmMachine,
  sdk:typeof import('@matrix-org/matrix-sdk-crypto-wasm')) {
  await verifyGroupMessage(group,record)
  const packet:unknown=JSON.parse(decoder.decode(base64urlToBinary(record.payload.slice(marker.length))))
  if(!matrixObject(packet)||!matrixObject(packet.cipher)||typeof packet.sealed!=='string'||
    typeof packet.cipher.session_id!=='string'||typeof packet.cipher.sender_key!=='string') {
    throw new Error('Invalid sender-key message.')
  }
  const address=senderRoom(group,record.epoch)
  const exported=await openGroupSenderExport(key,group,record.epoch,record.actor,record.device,packet.cipher.session_id,packet.sealed)
  const keys=JSON.parse(exported)
  if(!Array.isArray(keys)||keys.length!==1||keys[0].room_id!==address||keys[0].session_id!==packet.cipher.session_id||
    keys[0].sender_key!==packet.cipher.sender_key||typeof keys[0].sender_claimed_keys?.ed25519!=='string') {
    throw new Error('Sender key does not belong to this conversation.')
  }
  await machine.importExportedRoomKeys(exported,()=>{})
  const opened=await machine.decryptRoomEvent(JSON.stringify({type:'m.room.encrypted',event_id:'$'+record.id,
    sender:matrixUser(record.actor),origin_server_ts:Date.parse(record.sent),content:packet.cipher}),new sdk.RoomId(address),
    new sdk.DecryptionSettings(sdk.TrustRequirement.Untrusted))
  const result=JSON.parse(opened.event)
  if(result.type!=='m.room.message'||result.content?.msgtype!=='m.text'||typeof result.content.body!=='string') {
    throw new Error('Unsupported sender-key message.')
  }
  return result.content.body
}
