import { randomBytes } from 'node:crypto'
import { pathToFileURL } from 'node:url'
import { parseArgs } from 'node:util'
import { residencyDatabaseOrigins, residencyMemberKeys, request } from './workspace-residency-files.mjs'

const id = /^[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$/

async function call(origin, key, token, procedure, body) {
  const response = await request(origin, '/rest/v1/rpc/' + procedure, {method:'POST',
    headers:{apikey:key,Authorization:'Bearer '+token,'Content-Type':'application/json'},body:JSON.stringify(body),
  })
  if(!response.ok){
    await response.body?.cancel()
    throw new Error(`Residency member operation ${procedure} was declined (${response.status}).`)
  }
  return response.json()
}

export async function inviteResidencyMember({sourceDatabase,sourceProject,sourceKey,sourceMemberSession,
  targetDatabase,targetProject,targetKey,targetOwnerSession,targetMemberSession,workspace,approval}) {
  const [source,target]=residencyDatabaseOrigins(sourceDatabase,targetDatabase,sourceProject,targetProject)
  const sessions=[sourceMemberSession,targetOwnerSession,targetMemberSession]
  if(source===target||!residencyMemberKeys(source,sourceKey,targetKey)||sessions.some(token=>typeof token!=='string'||!token)||new Set(sessions).size!==3||
    !id.test(workspace??'')||!id.test(approval??'')||!/^[a-z0-9-]{1,80}$/.test(sourceProject??'')) {
    throw new Error('Provide separate projects, three distinct sessions and the exact approved workspace and manifest.')
  }
  const p_challenge=randomBytes(32).toString('hex')
  const [member,destination]=await Promise.all([
    call(source,sourceKey,sourceMemberSession,'st_v8_residency_member_proof',{p_challenge,p_workspace:workspace}),
    call(target,targetKey,targetMemberSession,'st_v8_residency_member_proof',{p_challenge}),
  ])
  if(!id.test(member?.account??'')||!id.test(destination?.account??'')||
    !/^[0-9a-f]{64}$/.test(member.identity??'')||member.identity!==destination.identity) {
    throw new Error('The two verified sessions do not belong to the same confirmed email.')
  }
  const invitation=await call(target,targetKey,targetOwnerSession,'st_v8_residency_member_invite',{
    p_workspace:workspace,p_approval:approval,p_source:sourceProject,p_destination:destination.account,
    p_challenge,p_identity:member.identity,
  })
  if(!id.test(invitation??''))throw new Error('The destination did not confirm a pending invitation.')
  return {status:'destination_invitation_ready',invitation}
}

export async function restoreResidencyPost({sourceDatabase,sourceProject,sourceKey,sourceMemberSession,targetDatabase,targetProject,targetKey,
  targetMemberSession,workspace,approval,channel,room,post}) {
  const [source,target]=residencyDatabaseOrigins(sourceDatabase,targetDatabase,sourceProject,targetProject)
  const kind=room===undefined?'channel':'room'
  if(source===target||!residencyMemberKeys(source,sourceKey,targetKey)||
    [sourceMemberSession,targetMemberSession].some(token=>typeof token!=='string'||!token)||sourceMemberSession===targetMemberSession||
    (room===undefined)===(channel===undefined)||
    ![workspace,approval,room??channel,post].every(value=>typeof value==='string'&&id.test(value))) {
    throw new Error('Provide two distinct member sessions, one approved room or channel, and an exact message.')
  }
  const scope={p_workspace:workspace,p_approval:approval,['p_'+kind]:room??channel,p_post:post}
  const witness=await call(source,sourceKey,sourceMemberSession,`st_v8_residency_${kind}_author_proof`,{
    ...scope,p_challenge:randomBytes(32).toString('hex'),
  })
  if(typeof witness?.payload!=='string'||witness.payload.length>1600||!/^[0-9a-f]{64}$/.test(witness?.signature??'')) {
    throw new Error('The source did not confirm authorship for that message.')
  }
  const receipt=await call(target,targetKey,targetMemberSession,`st_v8_residency_publish_${kind}_history`,{
    ...scope,p_payload:witness.payload,p_signature:witness.signature,
  })
  if(receipt?.post!==post||typeof receipt.importedAt!=='string') throw new Error('The destination did not issue a message receipt.')
  return {post:receipt.post,importedAt:receipt.importedAt}
}

export {restoreResidencyPost as restoreResidencyChannelPost}

if(process.argv[1]&&pathToFileURL(process.argv[1]).href===import.meta.url){
  try{
    const {values}=parseArgs({options:{workspace:{type:'string'},approval:{type:'string'},channel:{type:'string'},room:{type:'string'},post:{type:'string'}}})
    const action=[values.room,values.channel,values.post].some(value=>value!==undefined) ? restoreResidencyPost : inviteResidencyMember
    console.log(JSON.stringify(await action({...values,
      sourceDatabase:process.env.SECTALK_RESIDENCY_SOURCE_DATABASE,sourceProject:process.env.SECTALK_RESIDENCY_SOURCE_PROJECT,
      sourceKey:process.env.SECTALK_RESIDENCY_SOURCE_PUBLIC_KEY,sourceMemberSession:process.env.SECTALK_RESIDENCY_SOURCE_MEMBER_SESSION,
      targetDatabase:process.env.SECTALK_RESIDENCY_TARGET_DATABASE,targetKey:process.env.SECTALK_RESIDENCY_TARGET_PUBLIC_KEY,
      targetProject:process.env.SECTALK_RESIDENCY_TARGET_PROJECT,
      targetOwnerSession:process.env.SECTALK_RESIDENCY_TARGET_SESSION,targetMemberSession:process.env.SECTALK_RESIDENCY_TARGET_MEMBER_SESSION,
    })))
  }catch(error){console.error(error.message);process.exitCode=1}
}
