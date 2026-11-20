import {base64urlToBinary,binaryToBase64url} from './device-bundle'

const prefix='sectalk-encrypted-file-v1:'
const encoder=new TextEncoder()
const decoder=new TextDecoder('utf-8',{fatal:true})
const uuid=/^[a-f\d]{8}(?:-[a-f\d]{4}){3}-[a-f\d]{12}$/i
const safeName=/^[^/\\\x00-\x1f\x7f]{1,120}$/u
export const maxGroupFileBytes=4*1024*1024
export const groupFileOverhead=28

export type GroupFileDescriptor={id:string;name:string;size:number;key:string}

function fileContext(group:string,epoch:number,descriptor:Omit<GroupFileDescriptor,'key'>){
  return encoder.encode(JSON.stringify(['sectalk-group-file-v1',group,epoch,descriptor.id,descriptor.name,descriptor.size]))
}

export function readGroupFileDescriptor(message:string):GroupFileDescriptor|null {
  if(!message.startsWith(prefix))return null
  let value
  try{value=JSON.parse(decoder.decode(base64urlToBinary(message.slice(prefix.length))))}
  catch{throw new Error('The encrypted attachment description could not be verified.')}
  if(!value||typeof value.id!=='string'||!uuid.test(value.id)||typeof value.name!=='string'||!safeName.test(value.name)||
    value.name==='.'||value.name==='..'||!Number.isSafeInteger(value.size)||value.size<1||value.size>maxGroupFileBytes||
    typeof value.key!=='string'||!/^[A-Za-z0-9_-]{43}$/.test(value.key)){
    throw new Error('The encrypted attachment description could not be verified.')
  }
  return {id:value.id,name:value.name,size:value.size,key:value.key}
}

export async function sealGroupFile(group:string,epoch:number,id:string,file:File){
  const name=file.name.trim()
  if(!uuid.test(id)||!safeName.test(name)||name==='.'||name==='..'||file.size<1||file.size>maxGroupFileBytes){
    throw new Error('Choose an attachment with a valid name and a size up to 4 MiB.')
  }
  const descriptor={id,name,size:file.size}
  const raw=crypto.getRandomValues(new Uint8Array(32))
  const bytes=await file.arrayBuffer()
  try{
    const key=await crypto.subtle.importKey('raw',raw,'AES-GCM',false,['encrypt'])
    const iv=crypto.getRandomValues(new Uint8Array(12))
    const sealed=await crypto.subtle.encrypt({name:'AES-GCM',iv,additionalData:fileContext(group,epoch,descriptor)},key,bytes)
    const ciphertext=new Uint8Array(iv.byteLength+sealed.byteLength)
    ciphertext.set(iv)
    ciphertext.set(new Uint8Array(sealed),iv.length)
    const serialized=encoder.encode(JSON.stringify({...descriptor,key:binaryToBase64url(raw.buffer)}))
    try{return {ciphertext,message:prefix+binaryToBase64url(serialized.buffer)}}
    finally{serialized.fill(0)}
  }finally{
    raw.fill(0)
    new Uint8Array(bytes).fill(0)
  }
}

export async function openGroupFile(group:string,epoch:number,descriptor:GroupFileDescriptor,ciphertext:ArrayBuffer){
  if(ciphertext.byteLength!==descriptor.size+groupFileOverhead)throw new Error('The encrypted attachment is incomplete.')
  const raw=base64urlToBinary(descriptor.key)
  try{
    const key=await crypto.subtle.importKey('raw',raw,'AES-GCM',false,['decrypt'])
    const frame=new Uint8Array(ciphertext)
    return await crypto.subtle.decrypt({name:'AES-GCM',iv:frame.subarray(0,12),additionalData:fileContext(group,epoch,descriptor)},
      key,frame.subarray(12))
  }catch{throw new Error('The encrypted attachment could not be verified.')}
  finally{raw.fill(0)}
}
