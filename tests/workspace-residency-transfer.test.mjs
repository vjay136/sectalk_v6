import assert from 'node:assert/strict'
import {createHash,randomUUID} from 'node:crypto'
import test from 'node:test'
import {stageWorkspaceContent} from '../scripts/workspace-residency-content.mjs'
import {publishWorkspaceFiles} from '../scripts/workspace-residency-files.mjs'
import {inviteResidencyMember} from '../scripts/workspace-residency-member.mjs'

const sourceProject='a'.repeat(20), targetProject='b'.repeat(20)
const sourceDatabase=`https://${sourceProject}.supabase.co`, targetDatabase=`https://${targetProject}.supabase.co`
const options={sourceDatabase,targetDatabase,sourceProject,targetProject,sourceKey:'sb_publishable_fixture',
  sourceSession:'synthetic-owner-session-fixture',targetKey:'sb_secret_fixture',cell:randomUUID(),
  installationNonce:randomUUID(),workspace:randomUUID(),approval:randomUUID()}

test('hosted content staging scopes the owner session and destination key to separate exact origins',async t=>{
  const manifestSha256='a'.repeat(64), json='{"test":"synthetic fixture"}'
  const record={position:1,kind:'workspace_task',id:randomUUID(),scope:options.workspace,json,
    sha256:createHash('sha256').update(json).digest('hex')}
  const requests=[]
  t.mock.method(globalThis,'fetch',async (address,request)=>{
    const url=new URL(address), body=JSON.parse(request.body)
    requests.push(url.origin)
    assert.equal(request.redirect,'error')
    if(url.origin===sourceDatabase){
      assert.equal(request.headers.apikey,options.sourceKey)
      assert.equal(request.headers.Authorization,'Bearer '+options.sourceSession)
      assert.ok(!JSON.stringify(request.headers).includes(options.targetKey))
      assert.equal(url.pathname,'/rest/v1/rpc/st_v8_offboarding_content')
      return Response.json({id:options.approval,role:'owner',manifestSha256,
        expiresAt:new Date(Date.now()+60000).toISOString(),next:null,records:body.p_action==='page'?[record]:1})
    }
    assert.equal(url.origin,targetDatabase)
    assert.equal(request.headers.apikey,options.targetKey)
    assert.equal(request.headers.Authorization,undefined)
    assert.equal(url.pathname,'/rest/v1/rpc/st_v8_stage_residency_content')
    assert.deepEqual(body,{p_cell:options.cell,p_nonce:options.installationNonce,p_source:sourceProject,
      p_workspace:options.workspace,p_approval:options.approval,p_records:[record]})
    return Response.json({manifestSha256,count:1,staged:true})
  })
  assert.deepEqual(await stageWorkspaceContent(options),{manifestSha256,count:1,staged:true})
  assert.deepEqual(requests,[sourceDatabase,sourceDatabase,sourceDatabase,sourceDatabase,targetDatabase])
})

test('content staging rejects wrong references, mixed modes and privileged source keys before sending anything',async t=>{
  const outbound=t.mock.method(globalThis,'fetch',()=>assert.fail('Unexpected outbound request'))
  for(const changed of [
    {sourceProject:targetProject},{targetDatabase:'http://127.0.0.1:56801'},
    {targetDatabase:targetDatabase+'/rest/v1'},{targetDatabase:targetDatabase+'.example.invalid'},
    {targetProject:undefined},{sourceKey:'sb_secret_fixture_source'},{sourceKey:'legacy-service-fixture'},{targetKey:options.sourceKey},
  ])await assert.rejects(stageWorkspaceContent({...options,...changed}))
  assert.equal(outbound.mock.callCount(),0)
})

const sourceApp='https://source.sectalk.example.com',targetApp='https://destination.sectalk.example.com'
const file=randomUUID(), room=randomUUID()
const publication={...options,sourceApp,targetApp,approvedAppOrigins:{[sourceProject]:sourceApp,[targetProject]:targetApp},
  authorization:options.sourceSession,targetSession:'synthetic-destination-owner',targetPublicKey:'sb_publishable_destination_fixture',
  exportId:options.approval,files:[file]}

for(const scope of ['workspace','room'])test(`hosted ${scope} file publication verifies its destination before sending bytes`,async t=>{
  const fileBytes=Buffer.from('synthetic private file'),sha256=createHash('sha256').update(fileBytes).digest('hex')
  const calls=[]
  t.mock.method(globalThis,'fetch',async (address,request)=>{
    const url=new URL(address)
    calls.push([url.origin,request.method||'GET'])
    assert.equal(request.redirect,'error')
    if(url.origin===targetDatabase){
      assert.equal(request.headers.Authorization,undefined)
      assert.equal(request.headers.apikey,publication.targetPublicKey)
      assert.equal(url.pathname,'/rest/v1/rpc/st_v8_residency_target_ready')
      assert.deepEqual(JSON.parse(request.body),{p_cell:options.cell,p_project:targetProject,p_installation_nonce:options.installationNonce})
      return Response.json(true)
    }
    if(url.origin===targetApp){
      assert.equal(request.headers.Authorization,'Bearer '+publication.targetSession)
      assert.equal(request.headers.apikey,undefined)
      assert.equal(url.searchParams.get(scope),scope==='room'?room:options.workspace)
      if(request.method==='POST'){
        assert.deepEqual(request.body,fileBytes)
        assert.equal(url.searchParams.get('residency-import'),options.approval)
        return Response.json({id:file})
      }
      return url.searchParams.has('file')?new Response(fileBytes):Response.json([])
    }
    assert.equal(request.headers.Authorization,'Bearer '+options.sourceSession)
    assert.ok(!JSON.stringify(request.headers).includes(publication.targetSession))
    if(url.origin===sourceApp)return new Response(fileBytes,{headers:{'X-SecTalk-File-SHA256':sha256}})
    assert.equal(url.origin,sourceDatabase)
    assert.equal(request.headers.apikey,options.sourceKey)
    if(url.pathname==='/rest/v1/st_v6_rooms')return Response.json([{id:room}])
    assert.equal(JSON.parse(request.body).p_hash,sha256)
    return Response.json({file,bytes:fileBytes.length,filename:'synthetic.txt',...(scope==='room'?{room,sha256}:{})})
  })
  const result=await publishWorkspaceFiles({...publication,...(scope==='room'?{room}:{})})
  assert.equal(result.count,1)
  assert.deepEqual(calls.slice(0,2),[[targetDatabase,'POST'],[targetApp,'GET']])
  assert.deepEqual(calls.slice(-2),[[targetApp,'POST'],[targetApp,'GET']])
})

test('hosted publication never sends a session when the destination installation or application origin differs',async t=>{
  const outbound=t.mock.method(globalThis,'fetch',async (url,request)=>{
    assert.ok(url.startsWith(targetDatabase+'/'))
    assert.equal(request.headers.Authorization,undefined)
    return Response.json(false)
  })
  await assert.rejects(publishWorkspaceFiles({...publication,targetApp:'https://elsewhere.example.com'}),/exact HTTPS application origins/)
  assert.equal(outbound.mock.callCount(),0)
  await assert.rejects(publishWorkspaceFiles(publication),/installation could not be verified/)
  assert.equal(outbound.mock.callCount(),1)
})

test('hosted member invitations use separate, exact project origins and distinct native sessions',async t=>{
  const accounts=[randomUUID(),randomUUID()], invitation=randomUUID(), identity='1'.repeat(64)
  const sourceMemberSession='synthetic-source-member',targetMemberSession='synthetic-target-member'
  const targetOwnerSession='synthetic-target-owner',targetKey=publication.targetPublicKey
  const outbound=t.mock.method(globalThis,'fetch',async (address,request)=>{
    const url=new URL(address)
    assert.equal(request.redirect,'error')
    if(url.origin===sourceDatabase){
      assert.equal(request.headers.Authorization,'Bearer '+sourceMemberSession)
      assert.equal(request.headers.apikey,options.sourceKey)
      return Response.json({account:accounts[0],identity})
    }
    assert.equal(url.origin,targetDatabase)
    assert.equal(request.headers.apikey,targetKey)
    if(url.pathname.endsWith('_proof')){
      assert.equal(request.headers.Authorization,'Bearer '+targetMemberSession)
      return Response.json({account:accounts[1],identity})
    }
    assert.ok(url.pathname.endsWith('_invite'))
    assert.equal(request.headers.Authorization,'Bearer '+targetOwnerSession)
    assert.equal(JSON.parse(request.body).p_destination,accounts[1])
    return Response.json(invitation)
  })
  const input={...options,sourceMemberSession,targetMemberSession,targetOwnerSession,targetKey}
  await assert.rejects(inviteResidencyMember({...input,targetProject:'c'.repeat(20)}),/exact HTTPS Supabase origins/)
  assert.equal(outbound.mock.callCount(),0)
  assert.deepEqual(await inviteResidencyMember(input),{status:'destination_invitation_ready',invitation})
  assert.equal(outbound.mock.callCount(),3)
})
