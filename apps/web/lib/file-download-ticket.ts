import { createHmac, randomUUID, timingSafeEqual } from 'node:crypto'

type FileTicket={file:string;actor:string;nonce:string;expires:number}
export const fileTicketSeconds=30
const uuid=/^[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$/i
export const validFileId=(id:unknown):id is string=>typeof id==='string'&&uuid.test(id)

function sign(payload:string,secret:string){
  return createHmac('sha256',secret).update('sectalk-file-download-v6:').update(payload).digest()
}

export function issueFileTicket(file:string,actor:string,secret:string,now=Date.now()){
  const payload=Buffer.from(JSON.stringify({file,actor,nonce:randomUUID(),expires:now+fileTicketSeconds*1000})).toString('base64url')
  return payload+'.'+sign(payload,secret).toString('base64url')
}

export function readFileTicket(ticket:string,actor:string,secret:string,now=Date.now()):FileTicket|null{
  const match=/^([A-Za-z0-9_-]{1,384})\.([A-Za-z0-9_-]{43})$/.exec(ticket)
  if(!match)return null
  const received=Buffer.from(match[2],'base64url')
  if(received.toString('base64url')!==match[2]||!timingSafeEqual(sign(match[1],secret),received))return null
  try{
    const payload=JSON.parse(Buffer.from(match[1],'base64url').toString('utf8'))
    if(!validFileId(payload.file)||!validFileId(payload.nonce)||payload.actor!==actor||
      !Number.isSafeInteger(payload.expires)||payload.expires<=now)return null
    return payload
  }catch{return null}
}
