import assert from 'node:assert/strict'
import { execFileSync } from 'node:child_process'
import { randomUUID } from 'node:crypto'
import { setTimeout as delay } from 'node:timers/promises'
import { createClient } from '@supabase/supabase-js'

const backend = new URL(process.env.SECTALK_STORAGE_TEST_URL)
assert.equal(backend.origin, 'http://127.0.0.1:56801')
const publicKey = process.env.SECTALK_STORAGE_TEST_PUBLIC_KEY
const serviceKey = process.env.SECTALK_STORAGE_TEST_SERVICE_KEY
assert.ok(publicKey && serviceKey)
const options = { auth: { persistSession: false, autoRefreshToken: false } }
const service = createClient(backend.origin, serviceKey, options)
const email = 'reaction-policy-' + randomUUID().slice(0, 12) + '@example.invalid'
const password = randomUUID() + '!3q'
const fixture = randomUUID().slice(0, 8)
const domain = 'reaction-policy-' + fixture + '.example.invalid'
const provider = 'custom:reaction-policy-' + fixture
const channels = []
let owner, workspace, control

const sql = input => execFileSync('docker', ['exec','-i','supabase_db_v6-bundle243-qa','psql','-Xq','-U','postgres',
  '-d','postgres','-v','ON_ERROR_STOP=1'], { input, windowsHide: true })
function data(result) {
  if (result.error) throw result.error
  return result.data
}
async function signIn() {
  const client = createClient(backend.origin, publicKey, options)
  const { session } = data(await client.auth.signInWithPassword({ email, password }))
  return { client, session }
}
async function subscribe(session) {
  const client = createClient(backend.origin, publicKey, { accessToken: async () => session.access_token })
  channels.push(client)
  await client.realtime.setAuth(session.access_token)
  const seen = []
  const channel = client.channel('reaction-policy-' + randomUUID())
    .on('postgres_changes', {schema:'public', table:'st_v6_workspace_reaction_policy', event:'UPDATE'}, change => {
      if ([workspace, control].includes(change.new.workspace_id)) seen.push(change.new)
    })
  await new Promise((resolve, reject) => {
    const timeout = setTimeout(() => reject(new Error('Reaction policy subscription did not join')), 15000)
    channel.subscribe((state, error) => {
      if (state === 'SUBSCRIBED' || state === 'CHANNEL_ERROR' || state === 'TIMED_OUT') {
        clearTimeout(timeout)
        if (state === 'SUBSCRIBED') resolve()
        else reject(error ?? new Error(state))
      }
    })
  })
  return seen
}
async function waitFor(events, predicate, description) {
  const deadline = Date.now() + 15000
  while (!events.some(predicate)) {
    if (Date.now() >= deadline) throw new Error(`Expected reaction policy update did not arrive: ${description}`)
    await delay(100)
  }
}

try {
  owner = data(await service.auth.admin.createUser({ email, password, email_confirm:true })).user.id
  const signed = await signIn()
  const passwordOnly = await signIn()
  data(await signed.client.rpc('st_save_profile',{p_handle:'rp_'+fixture,p_name:'Synthetic reaction policy owner'}))
  sql(`insert into public.st_v2_subscriptions(user_id,plan,status,period_end)
    values('${owner}','enterprise','active',now()+interval '1 day');`)
  workspace = data(await signed.client.rpc('st_v2_create_workspace',{p_name:'Protected reaction policy '+fixture}))
  control = data(await signed.client.rpc('st_v2_create_workspace',{p_name:'Control reaction policy '+fixture}))
  const nativeSession = JSON.parse(Buffer.from(signed.session.access_token.split('.')[1],'base64url').toString()).session_id
  assert.match(nativeSession, /^[a-f0-9-]{36}$/)
  sql(`begin;
    insert into auth.custom_oauth_providers(provider_type,identifier,name,client_id,client_secret,issuer,scopes,enabled)
      values('oidc','${provider}','Synthetic provider','fixture','fixture','https://${domain}',array['openid','email'],true);
    insert into sectalk_private.st_v7_oidc_domain_approvals values('${domain}','${provider}');
    insert into sectalk_private.st_v7_org_domains(workspace,domain,verified_at) values('${workspace}','${domain}',now());
    insert into sectalk_private.st_v7_workspace_sso(workspace,domain,protocol,provider)
      values('${workspace}','${domain}','oidc','${provider}');
    insert into sectalk_private.st_v7_workspace_sso_sessions(session,workspace,principal,protocol,provider)
      values('${nativeSession}','${workspace}','${owner}','oidc','${provider}');
    insert into sectalk_private.st_v8_workspace_entry_sso values('${workspace}','oidc','${provider}');
    insert into public.st_v6_workspace_reaction_policy(workspace_id,emoji_set,per_person)
      values('${workspace}','native',2),('${control}','native',2); commit;`)
  const rows = async person => data(await person.client.from('st_v6_workspace_reaction_policy')
    .select('workspace_id').in('workspace_id',[workspace,control])).map(row => row.workspace_id).sort()
  assert.deepEqual(await rows(passwordOnly), [control])
  assert.deepEqual(await rows(signed), [workspace,control].sort())
  const [plainEvents, signedEvents] = await Promise.all([subscribe(passwordOnly.session),subscribe(signed.session)])
  // Joining the channel can precede initialization of a local logical replication slot.
  for (let attempt = 0; attempt < 20; attempt++) {
    if (plainEvents.length && signedEvents.length) break
    sql(`update public.st_v6_workspace_reaction_policy set per_person=2 where workspace_id='${control}';`)
    await delay(500)
  }
  assert.ok(plainEvents.length && signedEvents.length, 'Both Realtime subscribers must receive the control workspace')
  for (const revision of [3,4]) {
    sql(`begin;
      ${revision === 4 ? "update auth.custom_oauth_providers set enabled=false where identifier='"+provider+"';" : ''}
      update public.st_v6_workspace_reaction_policy set per_person=${revision} where workspace_id='${workspace}';
      update public.st_v6_workspace_reaction_policy set per_person=${revision} where workspace_id='${control}'; commit;`)
    const controlReached = row => row.workspace_id === control && row.per_person === revision
    await Promise.all([waitFor(plainEvents,controlReached,`password control revision ${revision}`),
      waitFor(signedEvents,controlReached,`signed control revision ${revision}`)])
    assert.equal(plainEvents.some(row => row.workspace_id === workspace),false)
    assert.equal(signedEvents.some(row => row.workspace_id === workspace && row.per_person === revision),revision === 3)
  }
  assert.deepEqual(await rows(signed), [control])
  console.log('Passed live policy SELECT and Realtime with isolated workspace scope and provider revocation.')
} finally {
  await Promise.all(channels.map(client => client.removeAllChannels()))
  if (owner) sql(`begin; set local session_replication_role=replica;
    delete from public.st_v2_workspace_audit
      where workspace_id in (select id from public.st_v2_workspaces where owner='${owner}');
    delete from sectalk_private.st_v8_workspace_audit_custody
      where workspace in (select id from public.st_v2_workspaces where owner='${owner}');
    set local session_replication_role=origin;
    delete from public.st_v2_workspaces where owner='${owner}';
    delete from sectalk_private.st_v7_oidc_domain_approvals where domain='${domain}';
    delete from auth.custom_oauth_providers where identifier='${provider}'; commit;`)
  if (owner) data(await service.auth.admin.deleteUser(owner))
}
