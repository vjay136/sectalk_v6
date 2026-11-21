import assert from 'node:assert/strict'
import {createHmac,randomBytes,randomUUID} from 'node:crypto'
import {execFileSync} from 'node:child_process'
import {setTimeout} from 'node:timers/promises'
import {createClient} from '@supabase/supabase-js'
import {liveRpcInventory,rpcInventory} from '../scripts/rpc-permission-inventory.mjs'

const origin=new URL(process.env.SECTALK_STORAGE_TEST_URL).origin
const targets=new Map([
  ['http://127.0.0.1:55321','supabase_db_v4-auth-qa'],
  ['http://127.0.0.1:56651','supabase_db_v6-i232-qa'],
  ['http://127.0.0.1:56801','supabase_db_v6-bundle243-qa'],
])
const qaContainer=targets.get(origin)
assert.ok(qaContainer,'Use a disposable Supabase QA project')
assert.equal(process.env.SECTALK_RPC_QA_CONTAINER??'supabase_db_v4-auth-qa',qaContainer,
  'Use the RPC inventory and REST service from the same local project')

const expected=rpcInventory()
const live=liveRpcInventory()
const approved=new Map(expected.map(entry=>[entry.rpc,entry]))
const missing=new Set(approved.keys())
for(const entry of live) {
  assert.ok(approved.has(entry.rpc),'Unmapped live RPC: '+entry.rpc)
  assert.deepEqual(entry,approved.get(entry.rpc),'Authorize and review changed native RPC: '+entry.rpc)
  missing.delete(entry.rpc)
}
assert.deepEqual([...missing],[],'Inventory contains functions no longer exposed')
assert.ok(live.every(entry=>entry.gate!=='Unclassified'))

const key=process.env.SECTALK_STORAGE_TEST_PUBLIC_KEY
const options={auth:{persistSession:false,autoRefreshToken:false}}
const anon=createClient(origin,key,options)
const service=createClient(origin,process.env.SECTALK_STORAGE_TEST_SERVICE_KEY,options)
const accounts=[]
const password=randomUUID()+'!zQ'
const suffix=randomUUID().slice(0,8)
const chat=randomUUID()
const identifier=randomBytes(32).toString('hex')
let workspace
function data(result){if(result.error)throw new Error(result.error.message);return result.data}
function sql(input){
  return execFileSync('docker',['exec','-i',qaContainer,'psql','-X','-v','ON_ERROR_STOP=1','-U','postgres','-d','postgres'],
    {input,encoding:'utf8'}).trim()
}
async function account(label){
  const handle='rpc_'+label+'_'+suffix
  const email=handle+'@example.org'
  const {user}=data(await service.auth.admin.createUser({email,password,email_confirm:true}))
  accounts.push(user.id)
  const client=createClient(origin,key,options)
  const {session}=data(await client.auth.signInWithPassword({email,password}))
  data(await client.rpc('st_save_profile',{p_handle:handle,p_name:'RPC fixture'}))
  return {user,handle,client,session}
}
function totp(secret) {
  const alphabet='ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'
  const bits=[...secret.replace(/=+$/,'')].map(c=>alphabet.indexOf(c).toString(2).padStart(5,'0')).join('')
  const bytes=Buffer.from(bits.match(/.{8}/g).map(x=>Number.parseInt(x,2)))
  const counter=Buffer.alloc(8)
  counter.writeBigUInt64BE(BigInt(Math.floor(Date.now()/30000)))
  const mac=createHmac('sha1',bytes).update(counter).digest()
  return String((mac.readUInt32BE(mac.at(-1)&15)&0x7fffffff)%1000000).padStart(6,'0')
}
try {
  assert.equal(typeof data(await anon.rpc('st_v6_ready')),'boolean')
  assert.ok((await anon.rpc('st_v7_permission_catalog')).error)
  assert.ok((await anon.rpc('st_v7_before_signup',{event:{}})).error)
  const admission={p_identifier:identifier,p_ip:'192.0.2.244'}
  assert.ok((await anon.rpc('st_v7_admit_password_request',admission)).error)
  assert.equal(data(await service.rpc('st_v7_admit_password_request',admission)),0)

  const [owner,member,outsider]=await Promise.all([account('owner'),account('member'),account('outside')])
  assert.ok((await owner.client.rpc('st_v7_admit_password_request',admission)).error)
  workspace=data(await owner.client.rpc('st_v2_create_workspace',{p_name:'RPC role fixture'}))
  data(await owner.client.rpc('st_v2_invite',{p_workspace:workspace,p_handle:member.handle}))
  const invitation=data(await member.client.from('st_v2_invites').select('id').eq('workspace_id',workspace).single())
  data(await member.client.rpc('st_v2_reply_invite',{p_invite:invitation.id,p_accept:true}))
  const rehearsal={p_workspace:workspace,p_confirmation:workspace,p_reconciliation:randomUUID(),p_sha256:'a'.repeat(64)}
  assert.ok((await anon.rpc('st_v8_offboarding_root_rehearsal',rehearsal)).error)
  assert.ok((await service.rpc('st_v8_offboarding_root_rehearsal',rehearsal)).error)
  assert.equal((await outsider.client.rpc('st_v8_offboarding_root_rehearsal',rehearsal)).status,403)
  const outsiderView=data(await outsider.client.rpc('st_v7_permission_catalog',{p_workspace:workspace}))
  assert.equal(outsiderView.workspace_role,null)
  assert.deepEqual(outsiderView.workspaces,[])

  const [a,b]=[owner.user.id,member.user.id].sort()
  sql(`insert into public.st_chats(id,member_a,member_b,requester,status)
    values('${chat}','${a}','${b}','${owner.user.id}','accepted');`)
  data(await owner.client.rpc('st_send',{p_chat:chat,p_id:randomUUID(),p_body:'Only the two authorized participants can read this.'}))
  const search={p_chat:chat,p_query:'authorized participants'}
  assert.equal(data(await member.client.rpc('st_v2_search_messages',search)).length,1)
  assert.deepEqual(data(await outsider.client.rpc('st_v2_search_messages',search)),[])

  const change={p_workspace:workspace,p_member:member.user.id,p_role:'admin'}
  assert.equal((await owner.client.rpc('st_v2_set_member',change)).error?.code,'42501')
  const device=data(await owner.client.auth.mfa.enroll({factorType:'totp'}))
  if(Date.now()%30000>27000)await setTimeout(4000)
  data(await owner.client.auth.mfa.challengeAndVerify({factorId:device.id,code:totp(device.totp.secret)}))
  const stale=createClient(origin,key,{...options,accessToken:async()=>owner.session.access_token})
  assert.equal((await stale.rpc('st_v2_set_member',change)).status,403)
  data(await owner.client.rpc('st_v2_set_member',change))
  assert.equal(data(await member.client.rpc('st_v7_permission_catalog',{p_workspace:workspace})).workspace_role,'admin')

  console.log(live.length+' live native signatures matched; real public, service, role mutation and invoker RLS probes passed.')
} finally {
  sql(`delete from public.st_messages where chat_id='${chat}'; delete from public.st_chats where id='${chat}';`)
  if(workspace)sql("delete from public.st_v2_workspaces where id='"+workspace+"';")
  await Promise.all(accounts.map(id=>service.auth.admin.deleteUser(id)))
}
