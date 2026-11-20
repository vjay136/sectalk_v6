import assert from 'node:assert/strict'
import {createHmac,randomUUID} from 'node:crypto'
import {execFileSync} from 'node:child_process'
import {setTimeout} from 'node:timers/promises'
import {createClient} from '@supabase/supabase-js'

const origin=new URL(process.env.SECTALK_STORAGE_TEST_URL).origin
assert.equal(origin,'http://127.0.0.1:55321')
const key=process.env.SECTALK_STORAGE_TEST_PUBLIC_KEY
const options={auth:{persistSession:false,autoRefreshToken:false}}
const admin=createClient(origin,process.env.SECTALK_STORAGE_TEST_SERVICE_KEY,options)
const native=createClient(origin,key,options)
function data(result) {if (result.error) throw new Error(result.error.message); return result.data}
function sql(input) {
  return execFileSync('docker',['exec','-i','supabase_db_v4-auth-qa','psql','-X','-At','-v','ON_ERROR_STOP=1',
    '-U','postgres','-d','postgres'],{input,encoding:'utf8'}).trim()
}
function totp(secret) {
  const alphabet='ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'
  const bits=[...secret.replace(/=+$/,'')].map(character=>alphabet.indexOf(character).toString(2).padStart(5,'0')).join('')
  const bytes=Buffer.from(bits.match(/.{8}/g).map(value=>parseInt(value,2)))
  const counter=Buffer.alloc(8)
  counter.writeBigUInt64BE(BigInt(Math.floor(Date.now()/30000)))
  const digest=createHmac('sha1',bytes).update(counter).digest()
  return String((digest.readUInt32BE(digest.at(-1)&15)&0x7fffffff)%1e6).padStart(6,'0')
}
const handle='totp_api_'+randomUUID().slice(0,8)
const email=handle+'@example.org'
const password=randomUUID()+'!zQ'
const {user}=data(await admin.auth.admin.createUser({email,password,email_confirm:true}))
const bucket='sectalk-avatars'
const object=user.id+'.jpg'
const scoped=token=>createClient(origin,key,{...options,accessToken:async()=>token})
const track=[]
function subscribe(client,channel) {
  track.push([client,channel])
  return Promise.race([
    new Promise(resolve=>channel.subscribe(result=>{if(result!=='CLOSED') resolve(result)})),
    setTimeout(8000).then(()=>{throw new Error('Realtime did not acknowledge the join')}),
  ])
}
async function eventually(test) {
  for(let index=0;index<100;index++) {
    if(test()) return
    await setTimeout(100)
  }
  throw new Error('Expected verified listener to receive its event')
}
let workspace
try {
  const {session:passwordSession}=data(await native.auth.signInWithPassword({email,password}))
  const low=scoped(passwordSession.access_token)
  data(await low.rpc('st_save_profile',{p_handle:handle,p_name:'TOTP assurance QA'}))
  const image=new Uint8Array([255,216,255,217])
  data(await low.storage.from(bucket).upload(object,image,{contentType:'image/jpeg'}))
  const factor=data(await native.auth.mfa.enroll({factorType:'totp'}))
  assert.equal(data(await low.rpc('st_v7_login_risk_status')),'clear','An abandoned setup cannot block existing access')
  if(Date.now()%30000>27000) await setTimeout(4000)
  const proof=data(await native.auth.mfa.challengeAndVerify({factorId:factor.id,code:totp(factor.totp.secret)}))
  const high=scoped(proof.access_token)

  assert.equal(data(await low.rpc('st_v7_login_risk_status')),'authenticator')
  assert.equal(data(await low.rpc('st_v7_account_recovery_status')),'missing')
  assert.equal(data(await high.rpc('st_v7_login_risk_status')),'clear')
  assert.equal((await low.from('st_profiles').select('id').eq('id',user.id).single()).status,403)
  assert.equal((await low.rpc('st_save_profile',{p_handle:handle,p_name:'Unverified profile write'})).status,403)
  assert.equal(data(await high.from('st_profiles').select('id').eq('id',user.id).single()).id,user.id)
  assert.ok((await low.storage.from(bucket).download(object)).error)
  assert.ok((await low.storage.from(bucket).createSignedUrl(object,30)).error)
  assert.ok((await low.storage.from(bucket).update(object,image,{contentType:'image/jpeg'})).error)
  data(await high.storage.from(bucket).update(object,image,{contentType:'image/jpeg'}))
  assert.equal((await data(await high.storage.from(bucket).download(object)).arrayBuffer()).byteLength,4)
  assert.ok(data(await high.storage.from(bucket).createSignedUrl(object,30)).signedUrl)

  workspace=data(await high.rpc('st_v2_create_workspace',{p_name:'TOTP assurance QA'}))
  assert.match(workspace,/^[0-9a-f-]{36}$/)
  const topic='st:account:'+user.id
  let lowBroadcasts=0, highBroadcasts=0, lowNotices=0, highNotices=0
  const lowBroadcast=low.channel(topic,{config:{private:true}}).on('broadcast',{event:'totp_fixture'},()=>lowBroadcasts++)
  const highBroadcast=high.channel(topic,{config:{private:true}}).on('broadcast',{event:'totp_fixture'},()=>highBroadcasts++)
  const changes={event:'*',schema:'public',table:'st_v3_notifications',filter:'recipient=eq.'+user.id}
  const lowChanged=low.channel('totp-low-'+user.id).on('postgres_changes',changes,()=>lowNotices++)
  const highChanged=high.channel('totp-high-'+user.id).on('postgres_changes',changes,()=>highNotices++)
  const [lowJoin,highJoin,lowChangeJoin,highChangeJoin]=await Promise.all([
    subscribe(low,lowBroadcast),subscribe(high,highBroadcast),subscribe(low,lowChanged),subscribe(high,highChanged),
  ])
  assert.equal(lowJoin,'CHANNEL_ERROR')
  assert.equal(highJoin,'SUBSCRIBED')
  assert.equal(lowChangeJoin,'SUBSCRIBED')
  assert.equal(highChangeJoin,'SUBSCRIBED')
  await setTimeout(1000)
  sql("select realtime.send('{}','totp_fixture','"+topic+"',true); insert into public.st_v3_notifications(recipient,workspace_id,kind) values ('"+user.id+"','"+workspace+"','meeting.scheduled');")
  await eventually(()=>highBroadcasts===1&&highNotices===1).catch(()=>{
    assert.deepEqual({highBroadcasts,highNotices},{highBroadcasts:1,highNotices:1})
  })
  sql("update public.st_v3_notifications set read_at=clock_timestamp() where recipient='"+user.id+"' and workspace_id='"+workspace+"';")
  await eventually(()=>highNotices===2)
  await setTimeout(700)
  assert.equal(lowBroadcasts,0)
  assert.equal(lowNotices,0)
  console.log('Native TOTP assurance passed verified-only Data API, private Storage, private Realtime Broadcast and Postgres Changes; the same pre-MFA JWT stayed blocked after verification.')
} finally {
  await Promise.all(track.map(([client,channel])=>client.removeChannel(channel)))
  await admin.storage.from(bucket).remove([object])
  if (workspace) sql("delete from public.st_v2_workspaces where id='"+workspace+"';")
  await admin.auth.admin.deleteUser(user.id)
}
