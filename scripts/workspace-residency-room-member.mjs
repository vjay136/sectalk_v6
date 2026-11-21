import {randomBytes} from 'node:crypto'
import {pathToFileURL} from 'node:url'
import {parseArgs} from 'node:util'
import {residencyDatabaseOrigins,residencyMemberKeys,request} from './workspace-residency-files.mjs'

const uuid=/^[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$/

async function roomMemberRequest(origin,key,token,procedure,payload) {
  const response=await request(origin,'/rest/v1/rpc/'+procedure,{
    method:'POST',headers:{apikey:key,Authorization:'Bearer '+token,'Content-Type':'application/json'},body:JSON.stringify(payload),
  })
  if(!response.ok){
    await response.body?.cancel()
    throw new Error(`Room membership operation ${procedure} was declined (${response.status}).`)
  }
  return response.json()
}

export async function inviteResidencyRoomMember({sourceDatabase,sourceProject,sourceKey,sourceMemberSession,targetDatabase,targetProject,targetKey,
  targetMemberSession,targetOwnerSession,workspace,approval,room}) {
  const [source,target]=residencyDatabaseOrigins(sourceDatabase,targetDatabase,sourceProject,targetProject)
  const sessions=[sourceMemberSession,targetMemberSession,targetOwnerSession]
  if(source===target||!residencyMemberKeys(source,sourceKey,targetKey)||new Set(sessions).size!==3||
    sessions.some(session=>typeof session!=='string'||!session)||
    ![workspace,approval,room].every(value=>typeof value==='string'&&uuid.test(value))) {
    throw new Error('Provide separate projects, three distinct sessions and the exact approved workspace, manifest and room.')
  }

  const scope={p_workspace:workspace,p_approval:approval,p_room:room}
  const attestation=await roomMemberRequest(source,sourceKey,sourceMemberSession,'st_v8_residency_room_member_proof',{
    ...scope,p_challenge:randomBytes(32).toString('hex'),
  })
  if(typeof attestation?.payload!=='string'||attestation.payload.length>1600||
    !/^[0-9a-f]{64}$/.test(attestation.signature??''))throw new Error('Source room membership proof is unavailable.')
  const claim=await roomMemberRequest(target,targetKey,targetMemberSession,'st_v8_residency_room_member_claim',{
    ...scope,p_payload:attestation.payload,p_signature:attestation.signature,
  })
  if(!uuid.test(claim??''))throw new Error('The destination did not confirm a matched room member.')
  const invitation=await roomMemberRequest(target,targetKey,targetOwnerSession,'st_v8_residency_room_member_invite',{
    p_workspace:workspace,p_claim:claim,p_confirmation:workspace,
  })
  if(invitation?.claim!==claim||invitation.room!==room||!['pending','accepted'].includes(invitation.status)||
    typeof invitation.invitedAt!=='string')throw new Error('The destination did not confirm the native room invitation.')
  return invitation
}

if(process.argv[1]&&pathToFileURL(process.argv[1]).href===import.meta.url){
  try{
    const {values}=parseArgs({options:{workspace:{type:'string'},approval:{type:'string'},room:{type:'string'}}})
    console.log(JSON.stringify(await inviteResidencyRoomMember({...values,
      sourceDatabase:process.env.SECTALK_RESIDENCY_SOURCE_DATABASE,sourceKey:process.env.SECTALK_RESIDENCY_SOURCE_PUBLIC_KEY,
      sourceProject:process.env.SECTALK_RESIDENCY_SOURCE_PROJECT,targetProject:process.env.SECTALK_RESIDENCY_TARGET_PROJECT,
      sourceMemberSession:process.env.SECTALK_RESIDENCY_SOURCE_MEMBER_SESSION,
      targetDatabase:process.env.SECTALK_RESIDENCY_TARGET_DATABASE,targetKey:process.env.SECTALK_RESIDENCY_TARGET_PUBLIC_KEY,
      targetMemberSession:process.env.SECTALK_RESIDENCY_TARGET_MEMBER_SESSION,targetOwnerSession:process.env.SECTALK_RESIDENCY_TARGET_SESSION,
    })))
  }catch(error){console.error(error.message);process.exitCode=1}
}
