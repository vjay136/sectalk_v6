import assert from 'node:assert/strict'
import { execFileSync } from 'node:child_process'
import { createHash, createHmac, createPublicKey, randomUUID, verify } from 'node:crypto'
import { setTimeout } from 'node:timers/promises'
import { createClient } from '@supabase/supabase-js'

const app = new URL(process.env.SECTALK_STORAGE_TEST_APP)
const supabase = new URL(process.env.SECTALK_STORAGE_TEST_URL)
assert.equal(app.hostname, '127.0.0.1')
assert.equal(supabase.origin, 'http://127.0.0.1:55321')
const purgeKey = process.env.SECTALK_FILE_PURGE_SECRET
assert.ok(purgeKey?.length >= 32)
const options = { auth: { persistSession: false, autoRefreshToken: false } }
const storage = createClient(supabase.origin, process.env.SECTALK_STORAGE_TEST_SERVICE_KEY, options)
const bucket = 'sectalk-exports'
const password = randomUUID() + '1!Q'
const suffix = randomUUID().slice(0, 8)
const artifacts = []
const actors = []
let workspace

function data(result) {
  if (result.error) throw result.error
  return result.data
}
function sql(statement) {
  return execFileSync('docker', ['exec', '-i', 'supabase_db_v4-auth-qa', 'psql', '-X', '-At', '-v', 'ON_ERROR_STOP=1',
    '-U', 'postgres', '-d', 'postgres'], { input: statement, encoding: 'utf8', windowsHide: true }).trim()
}
async function account(role) {
  const handle = 'exstorage_' + role + '_' + suffix
  const email = handle + '@example.invalid'
  const { user } = data(await storage.auth.admin.createUser({ email, password, email_confirm: true }))
  actors.push(user.id)
  const client = createClient(supabase.origin, process.env.SECTALK_STORAGE_TEST_PUBLIC_KEY, options)
  const { session } = data(await client.auth.signInWithPassword({ email, password }))
  data(await client.rpc('st_save_profile', { p_handle: handle, p_name: 'Export Storage QA' }))
  return { id: user.id, client, token: session.access_token }
}
async function currentCode(secret) {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'
  const bits = [...secret.toUpperCase().replace(/=+$/, '')]
    .map(character => alphabet.indexOf(character).toString(2).padStart(5, '0')).join('')
  const key = Buffer.from(bits.match(/.{8}/g).map(part => Number.parseInt(part, 2)))
  const timeLeft = 30000 - Date.now() % 30000
  if (timeLeft < 2000) await setTimeout(timeLeft + 50)
  const counter = Buffer.alloc(8)
  counter.writeBigUInt64BE(BigInt(Math.floor(Date.now() / 30000)))
  const mac = createHmac('sha1', key).update(counter).digest()
  return String((mac.readUInt32BE(mac.at(-1) & 15) & 0x7fffffff) % 1_000_000).padStart(6, '0')
}
const request = (path, bearer, input) => fetch(new URL(path, app), {
  method: input ? 'POST' : 'GET',
  headers: { ...(bearer ? { Authorization: 'Bearer ' + bearer } : {}), ...(input ? { 'Content-Type': 'application/json' } : {}) },
  body: input ? JSON.stringify(input) : undefined,
})
const cleanup = bearer => fetch(new URL('/api/exports/purge', app), {
  method: 'POST', headers: { Authorization: 'Bearer ' + bearer },
})

try {
  const owner = await account('owner')
  const outsider = await account('other')
  workspace = data(await owner.client.rpc('st_v2_create_workspace', { p_name: 'Storage export ' + suffix }))
  const run = randomUUID()
  const room = randomUUID()
  sql(`
    insert into public.st_v6_rooms(id,workspace_id,name,kind,template,creator)
      values ('${room}','${workspace}','Private audit fixture','private','blank','${owner.id}');
    insert into public.st_v6_room_members(room_id,user_id,role) values ('${room}','${owner.id}','moderator');
    insert into public.st_v6_room_audit(room_id,actor,action) values ('${room}','${owner.id}','room.qa.fixture');
    insert into sectalk_private.staff(user_id) values ('${owner.id}');
    insert into sectalk_private.st_v6_operational_report_schedules(owner,cadence,active,next_at)
      values ('${owner.id}','daily',false,now()+interval '1 day');
    insert into sectalk_private.st_v6_operational_report_runs(id,owner,scheduled_at,period_end,cadence,rows,state)
      values ('${run}','${owner.id}',now(),date_trunc('day',now()),'daily','[]','sent');
  `)
  const factor = data(await owner.client.auth.mfa.enroll({ factorType: 'totp' }))
  const token = data(await owner.client.auth.mfa.challengeAndVerify({
    factorId: factor.id, code: await currentCode(factor.totp.secret),
  })).access_token
  const auditPath = '/api/audit/export'
  const signing = await (await request(auditPath)).json()
  const publicKey = createPublicKey({ key: Buffer.from(signing.public_key_spki, 'base64url'), type: 'spki', format: 'der' })
  const sources = [
    [auditPath, 'application/json', { workspace, query: '', source: 'workspace', from: null, before: null }],
    ['/api/operational-reports/export?run=' + run, 'text/csv; charset=utf-8'],
    ['/api/security-reports/export?period=daily&format=csv', 'text/csv; charset=utf-8'],
    ['/api/security-reports/export?period=weekly&format=pdf', 'application/pdf'],
    [auditPath, 'application/json', { workspace, query: '', source: 'room', from: null, before: null }],
  ]
  for (const [path, mime, body] of sources) {
    const response = await request(path, token, body)
    assert.equal(response.status, 200, path)
    const locator = response.headers.get('x-sectalk-export-location')
    assert.match(locator ?? '', /^\/api\/exports\/[0-9a-f-]{36}$/)
    const id = locator.split('/').at(-1)
    artifacts.push(id)
    assert.equal(response.headers.get('content-type'), mime)
    const bytes = Buffer.from(await response.arrayBuffer())
    const stored = data(await storage.storage.from(bucket).download(id))
    assert.deepEqual(Buffer.from(await stored.arrayBuffer()), bytes)
    const reread = await request(locator, token)
    assert.equal(reread.status, 200)
    assert.equal(reread.headers.get('content-disposition'), response.headers.get('content-disposition'))
    assert.equal(reread.headers.get('content-type'), mime)
    assert.deepEqual(Buffer.from(await reread.arrayBuffer()), bytes)
    assert.equal((await request(locator, outsider.token)).status, 404)
    assert.equal((await request(locator, owner.token)).status, 404)
    assert.equal((await request(locator)).status, 401)
    assert.ok((await owner.client.storage.from(bucket).download(id)).error, 'direct authorized-account Storage download must be denied')
    assert.ok((await outsider.client.storage.from(bucket).createSignedUrl(id, 60)).error)
    const publicPath = new URL('/storage/v1/object/public/' + bucket + '/' + id, supabase)
    assert.ok(!(await fetch(publicPath)).ok, 'the export bucket must stay private')
    if (mime === 'application/json') {
      const envelope = JSON.parse(bytes)
      assert.equal(verify(null, Buffer.from(envelope.payload), publicKey, Buffer.from(envelope.signature, 'base64url')), true)
      assert.ok(JSON.parse(envelope.payload).entries.some(entry => entry.source === body.source))
    }
    if (mime === 'application/pdf') assert.equal(bytes.subarray(0, 5).toString(), '%PDF-')
  }
  sql(`delete from sectalk_private.staff where user_id='${owner.id}';`)
  assert.equal((await request('/api/exports/' + artifacts[1], token)).status, 404)
  assert.equal((await request('/api/exports/' + artifacts[3], token)).status, 404)
  sql(`delete from public.st_v6_room_members where room_id='${room}' and user_id='${owner.id}';`)
  assert.equal((await request('/api/exports/' + artifacts[4], token)).status, 404)
  assert.equal((await request('/api/exports/' + artifacts[0], token)).status, 200)

  const pendingBytes = Buffer.from('{"test":true}')
  const attempted = randomUUID()
  artifacts.push(attempted)
  assert.ok((await owner.client.storage.from(bucket).upload(attempted, pendingBytes, { contentType: 'application/json' })).error)
  artifacts.pop()
  const pending = data(await storage.rpc('st_v6_begin_export_object', {
    p_actor: owner.id, p_kind: 'audit', p_scope: workspace, p_period: null, p_filename: 'pending.json',
    p_media: 'application/json', p_bytes: pendingBytes.length, p_sha256: createHash('sha256').update(pendingBytes).digest('hex'),
  }))
  artifacts.push(pending)
  data(await storage.storage.from(bucket).upload(pending, pendingBytes, { contentType: 'application/json' }))
  assert.equal((await request('/api/exports/' + pending, token)).status, 404)

  const ids = artifacts.map(id => "'" + id + "'").join(',')
  sql(`update sectalk_private.st_v6_export_objects set expires_at=now()-interval '1 second' where id in (${ids});`)
  assert.equal((await request('/api/exports/' + artifacts[0], token)).status, 404)
  const lease = data(await storage.rpc('st_v6_claim_export_cleanup')).find(row => row.id === pending)
  assert.ok(lease)
  assert.equal(data(await storage.rpc('st_v6_finish_export_cleanup', { p_artifact: pending, p_lease: lease.lease })), false)
  sql(`update sectalk_private.st_v6_export_objects set lease_until=now()-interval '1 second' where id in (${ids});`)
  assert.equal((await cleanup(owner.token)).status, 401)
  const purged = await cleanup(purgeKey)
  assert.equal(purged.status, 200)
  assert.ok((await purged.json()).purged >= artifacts.length)
  for (const id of artifacts) assert.ok((await storage.storage.from(bucket).download(id)).error)
  assert.equal(sql(`select count(*) from sectalk_private.st_v6_export_objects where id in (${ids});`), '0')
  console.log('Private export storage passed for signed audit, operational CSV and security CSV/PDF. Verified exact bytes, source access, expiry and physical cleanup.')
} finally {
  if (artifacts.length) {
    data(await storage.storage.from(bucket).remove(artifacts))
    sql(`delete from sectalk_private.st_v6_export_objects where id in (${artifacts.map(id => "'" + id + "'").join(',')});`)
  }
  if (workspace) sql(`delete from public.st_v2_workspaces where id='${workspace}';`)
  for (const id of actors) {
    sql(`delete from sectalk_private.staff where user_id='${id}';`)
    data(await storage.auth.admin.deleteUser(id))
  }
}
