import {createHash} from 'node:crypto'

type SealedRoomPost={
  room:string
  id:string
  sender:string
  key:{workspace:string;version:number}
  envelope:{body:string;nonce:string;tag:string;wrapped_dek:string}
}

export function managedRoomRevision({room,id,sender,key,envelope}:SealedRoomPost){
  const {body,nonce,tag,wrapped_dek}=envelope
  return createHash('sha256').update([room,id,key.workspace,sender,key.version,body,nonce,tag,wrapped_dek].join(':')).digest('hex')
}
