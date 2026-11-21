import assert from 'node:assert/strict'
import { execFileSync } from 'node:child_process'
import { randomUUID } from 'node:crypto'
import { setTimeout as delay } from 'node:timers/promises'
import { createClient } from '@supabase/supabase-js'

const origin = process.env.SECTALK_STORAGE_TEST_URL
const container = new Map([
  ['http://127.0.0.1:56651', 'supabase_db_v6-i232-qa'],
  ['http://127.0.0.1:55321', 'supabase_db_v4-auth-qa'],
]).get(origin)
assert.ok(container, 'Use a disposable local SecTalk database')
const key = process.env.SECTALK_STORAGE_TEST_PUBLIC_KEY
const serviceKey = process.env.SECTALK_STORAGE_TEST_SERVICE_KEY
assert.ok(key && serviceKey, 'Local fixture credentials are required')
const options = { auth: { persistSession: false, autoRefreshToken: false } }
const admin = createClient(origin, serviceKey, options)
const accounts = []
const sockets = []
const sendTimes = new Map()
const deliveries = new Map()
const apiMs = []
let chat

function data(result) {
  if (result.error) throw new Error(result.error.message)
  return result.data
}

async function account() {
  const handle = 'load_' + randomUUID().slice(0, 8)
  const email = handle + '@example.org'
  const password = randomUUID() + '!zQ'
  const { user } = data(await admin.auth.admin.createUser({ email, password, email_confirm: true }))
  accounts.push(user.id)
  const signin = createClient(origin, key, options)
  const { session } = data(await signin.auth.signInWithPassword({ email, password }))
  const client = createClient(origin, key, { ...options, accessToken: async () => session.access_token })
  data(await client.rpc('st_save_profile', { p_handle: handle, p_name: 'Synthetic delivery fixture' }))
  return { client, handle, id: user.id }
}

async function join(client, channel, expected) {
  sockets.push(client)
  const subscription = Promise.withResolvers()
  const timer = setTimeout(() => subscription.reject(new Error('Realtime join timed out')), 8000)
  try {
    channel.subscribe(status => {
      if (['SUBSCRIBED', 'CHANNEL_ERROR', 'TIMED_OUT'].includes(status)) subscription.resolve(status)
    })
    assert.equal(await subscription.promise, expected)
  } finally {
    clearTimeout(timer)
  }
}

function listen({ client, id }, record) {
  let frontier = 0
  let inFlight = false
  let pending = false
  let failure
  async function pull() {
    pending = true
    if (inFlight) return
    inFlight = true
    try {
      while (pending) {
        pending = false
        const posts = data(await client.from('st_messages').select('id,sender,sequence').eq('chat_id', chat)
          .gt('sequence', frontier).order('sequence').limit(50))
        for (const post of posts) {
          frontier = post.sequence
          if (post.sender !== id && sendTimes.has(post.id)) record(post.id)
        }
        if (posts.length === 50) pending = true
      }
    } catch (error) {
      failure = error
    } finally {
      inFlight = false
    }
  }
  const channel = client.channel('st:account:' + id, { config: { private: true } })
    .on('broadcast', { event: 'inbox' }, ({ payload }) => {
      if (payload.chat_id === chat) void pull()
    })
  return { ready: join(client, channel, 'SUBSCRIBED'), assertHealthy: () => assert.ifError(failure) }
}

async function send({ client }, chat) {
  const id = randomUUID()
  const started = performance.now()
  sendTimes.set(id, started)
  data(await client.rpc('st_send', { p_chat: chat, p_id: id, p_body: 'Synthetic delivery sample' }))
  apiMs.push(performance.now() - started)
}

function p95(samples) {
  return samples.toSorted((a, b) => a - b)[Math.ceil(samples.length * 0.95) - 1]
}

try {
  const [first, second, outside] = await Promise.all([account(), account(), account()])
  chat = data(await first.client.rpc('st_request', { p_handle: second.handle }))
  data(await second.client.rpc('st_respond', { p_chat: chat, p_accept: true }))
  let outsiderEvents = 0
  let duplicates = 0
  const record = id => {
    if (deliveries.has(id)) duplicates++
    else deliveries.set(id, performance.now() - sendTimes.get(id))
  }
  const recipients = [listen(first, record), listen(second, record)]
  const outsider = outside.client.channel('st:account:' + first.id, { config: { private: true } })
    .on('broadcast', { event: 'inbox' }, () => outsiderEvents++)
  await Promise.all([...recipients.map(recipient => recipient.ready), join(outside.client, outsider, 'CHANNEL_ERROR')])
  await delay(200)
  // Six short bursts of eight sends keep individual accounts under the normal quota.
  for (let burst = 0; burst < 6; burst++) {
    await Promise.all(Array.from({ length: 8 }, (_, index) => send(index % 2 ? first : second, chat)))
    await delay(100)
  }
  const deadline = performance.now() + 5000
  while (deliveries.size !== sendTimes.size && performance.now() < deadline) await delay(25)
  for (const recipient of recipients) recipient.assertHealthy()
  assert.equal(deliveries.size, 48, 'Every send must make it to the other account')
  assert.equal(duplicates, 0)
  assert.equal(outsiderEvents, 0)
  assert.deepEqual(data(await outside.client.from('st_messages').select('id').eq('chat_id', chat)), [])
  const apiP95 = p95(apiMs)
  const deliveryP95 = p95([...deliveries.values()])
  console.log(JSON.stringify({ samples: sendTimes.size, apiP95ms: Math.round(apiP95), deliveryP95ms: Math.round(deliveryP95), outsiderEvents }))
  assert.ok(apiP95 < 300, 'Message write API p95 must stay below 300 ms')
  assert.ok(deliveryP95 < 400, 'Peer delivery p95 must stay below 400 ms')
} finally {
  await Promise.all(sockets.map(client => client.removeAllChannels()))
  if (chat) {
    assert.match(chat, /^[0-9a-f-]{36}$/)
    execFileSync('docker', ['exec', '-i', container, 'psql', '-U', 'postgres', '-d', 'postgres', '-Xq', '-v', 'ON_ERROR_STOP=1'], {
      input: `begin; delete from public.st_messages where chat_id='${chat}'; delete from public.st_chats where id='${chat}'; commit;`,
    })
  }
  for (const accountId of accounts) data(await admin.auth.admin.deleteUser(accountId))
}
