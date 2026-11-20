import assert from 'node:assert/strict'
import { execFileSync } from 'node:child_process'
import { createHmac, randomUUID } from 'node:crypto'
import { createClient } from '@supabase/supabase-js'

const app = new URL(process.env.SECTALK_STORAGE_TEST_APP)
const supabase = new URL(process.env.SECTALK_STORAGE_TEST_URL)
assert.equal(app.hostname, '127.0.0.1')
assert.equal(supabase.origin, 'http://127.0.0.1:55321')
const options = { auth: { persistSession: false, autoRefreshToken: false } }
const admin = createClient(supabase.origin, process.env.SECTALK_STORAGE_TEST_SERVICE_KEY, options)
const client = createClient(supabase.origin, process.env.SECTALK_STORAGE_TEST_PUBLIC_KEY, options)
const { chromium } = await import(process.env.SECTALK_PLAYWRIGHT_MODULE || 'playwright')
const run = randomUUID().slice(0, 8)
const testQuality = process.env.SECTALK_TEST_QOS === '1'
const testAdvancedQuality = process.env.SECTALK_TEST_ANL_02 === '1'
const handle = 'analytics_' + run
const email = handle + '@example.org'
const password = randomUUID() + '1!Q'
const cohort = Array.from({ length: 5 }, () => ({ actor: randomUUID(), chat: randomUUID() }))
let staffId
let browser
const analyticsFrames = []

function data(result) {
  if (result.error) throw result.error
  return result.data
}

function sql(statement) {
  execFileSync('docker', ['exec', '-i', 'supabase_db_v4-auth-qa', 'psql', '-X', '-v', 'ON_ERROR_STOP=1',
    '-U', 'postgres', '-d', 'postgres'], { input: statement, windowsHide: true })
}

function totp(secret) {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'
  const bits = [...secret.toUpperCase().replace(/=+$/, '')]
    .map(character => alphabet.indexOf(character).toString(2).padStart(5, '0')).join('')
  const key = Buffer.from(bits.match(/.{8}/g).map(part => Number.parseInt(part, 2)))
  const counter = Buffer.alloc(8)
  counter.writeBigUInt64BE(BigInt(Math.floor(Date.now() / 30_000)))
  const mac = createHmac('sha1', key).update(counter).digest()
  return String((mac.readUInt32BE(mac.at(-1) & 15) & 0x7fffffff) % 1_000_000).padStart(6, '0')
}

function writeMessages(latency, publish) {
  const past = latency ? Math.max(120, Math.ceil(latency / 1000) + 10) : 5
  sql(`
    begin;
    insert into public.st_messages(id,chat_id,sender,body,created_at,delivered_at)
      select gen_random_uuid(),f.chat,f.actor,'Private synthetic analytics fixture',t.created,
        ${latency ? `t.created+interval '${latency} milliseconds'` : 'null'}
      from (values ${cohort.map(({ chat, actor }) => `('${chat}'::uuid,'${actor}'::uuid)`).join(',')}) f(chat,actor)
      cross join generate_series(1,4)
      cross join (select date_trunc('minute',now(),'UTC')-interval '${past} seconds' as created) t;
    ${publish ? `
      update sectalk_private.st_v6_analytics_viewers set last_sent_at=null where user_id='${staffId}';
      select sectalk_private.st_v6_publish_analytics_refresh();
    ` : ''}
    commit;
  `)
}

function waitForAggregate(page, rpc, predicate = () => true) {
  return page.waitForResponse(async response => {
    if (!response.url().endsWith('/rpc/' + rpc) || response.status() !== 200) return false
    return predicate(await response.json())
  }, { timeout: 15000 })
}

function readRealtimeFrame(message) {
  if (typeof message === 'string') {
    const frame = JSON.parse(message)
    return Array.isArray(frame) ? { topic: frame[2], event: frame[4] } : { topic: frame.topic, event: frame.payload }
  }
  // Realtime uses compact binary headers for JSON broadcast frames.
  if (message[0] !== 4 || message[4] !== 1) return {}
  const topicEnd = 5 + message[1]
  const eventEnd = topicEnd + message[2]
  return {
    topic: message.toString('utf8', 5, topicEnd),
    event: { event: message.toString('utf8', topicEnd, eventEnd),
      payload: JSON.parse(message.toString('utf8', eventEnd + message[3])) },
  }
}

try {
  const { user } = data(await admin.auth.admin.createUser({ email, password, email_confirm: true }))
  staffId = user.id
  data(await client.auth.signInWithPassword({ email, password }))
  data(await client.rpc('st_save_profile', { p_handle: handle, p_name: 'Live Analytics QA' }))
  sql(`
    begin;
    insert into sectalk_private.staff(user_id) values('${staffId}');
    insert into auth.users(id,email) values
      ${cohort.map(({ actor }) => `('${actor}','${actor}@example.invalid')`).join(',')};
    insert into public.st_profiles(id,handle,name) values
      ${cohort.map(({ actor }) => `('${actor}','anaqa_${actor.slice(0, 12).replace('-', '')}','Analytics fixture')`).join(',')};
    insert into public.st_chats(id,member_a,member_b,requester,status) values
      ${cohort.map(({ chat, actor }) => `('${chat}',least('${actor}'::uuid,'${staffId}'::uuid),
        greatest('${actor}'::uuid,'${staffId}'::uuid),'${actor}','accepted')`).join(',')};
    commit;
  `)
  assert.equal((await client.rpc('st_v6_usage_metrics', { p_window: '7d', p_live: true })).error?.code, '42501')
  browser = await chromium.launch({ executablePath: process.env.SECTALK_TEST_BROWSER })
  const page = await browser.newPage()
  let socket
  let connected = 0
  let blocked = false
  const liveHints = []
  await page.routeWebSocket(url => url.pathname === '/realtime/v1/websocket', ws => {
    if (blocked) return ws.close({ code: 1011, reason: 'QA disconnect' })
    socket = ws
    connected++
    const server = ws.connectToServer()
    server.onMessage(message => {
      const { topic, event } = readRealtimeFrame(message)
      if (topic?.includes('st:analytics:')) analyticsFrames.push(event?.status || event?.event)
      if (event?.event === 'analytics_refresh') liveHints.push(event.payload)
      ws.send(message)
    })
  })

  await page.goto(app.href)
  await page.getByLabel('Email address', { exact: true }).fill(email)
  await page.getByLabel('Password', { exact: true }).fill(password)
  await page.locator('button.submit-auth').click()
  await page.getByRole('navigation', { name: 'SecTalk features' }).getByRole('button', { name: 'Safety', exact: true }).click()
  await page.getByRole('button', { name: 'Staff console', exact: true }).click()
  await page.getByRole('button', { name: 'Set up authenticator' }).click()
  const secret = (await page.locator('.mfa-setup code').textContent()).trim()
  await page.getByLabel('Authenticator code', { exact: true }).fill(totp(secret))
  await page.getByRole('button', { name: 'Verify access', exact: true }).click()

  const latencyInitial = waitForAggregate(page, 'st_v6_delivery_latency')
  await page.getByRole('button', { name: 'Delivery metrics', exact: true }).click()
  const latencyBaseline = await (await latencyInitial).json()
  const target = Math.max(2000, (latencyBaseline.p99 ?? 0) + 2000)
  const latencyUpdated = waitForAggregate(page, 'st_v6_delivery_latency', result => result.available && result.p99 >= target)
  writeMessages(target, true)
  const latency = await (await latencyUpdated).json()
  const deliveryPanel = page.getByRole('region', { name: 'Message delivery latency' })
  await deliveryPanel.locator('time[datetime="' + latency.through + '"]').waitFor()
  assert.deepEqual(Object.keys(latency).sort(), ['available', 'p50', 'p95', 'p99', 'through'])

  const usageInitial = waitForAggregate(page, 'st_v6_usage_metrics')
  if (testQuality) sql(`
    insert into sectalk_private.st_v6_call_qos (day,event_key,reporter_key,mode,metric,bucket)
    select (now() at time zone 'UTC')::date-1, extensions.digest('qos-ui-event-${run}-'||n,'sha256'),
      extensions.digest('qos-ui-reporter-${run}-'||(n%5),'sha256'), 'meeting', 'setup', 'fast'
    from generate_series(1,10) n;
  `)
  if (testAdvancedQuality) sql(`
    insert into sectalk_private.st_v6_call_qos (day,event_key,reporter_key,mode,metric,bucket)
    select (now() at time zone 'UTC')::date-1, extensions.digest('qos-anl-${run}-'||metric||n,'sha256'),
      extensions.digest('qos-anl-person-${run}-'||(n%5),'sha256'), mode,metric,bucket
    from (values ('meeting','join','connected'), ('meeting','relay','relayed'), ('meeting','mos','4_or_more'),
      ('direct','ice_restart','not_requested')) as fixture(mode,metric,bucket) cross join generate_series(1,10) n;
  `)
  await page.getByRole('button', { name: 'Usage metrics', exact: true }).click()
  const usageSnapshot = await (await usageInitial).json()
  const usageBaseline = usageSnapshot.metrics.messages ?? 0
  if (testQuality) {
    assert.ok(usageSnapshot.qos.metrics['meeting:setup:fast'] >= 10)
    await page.getByRole('region', { name: 'Call quality' })
      .getByText('Connected in under 2 seconds', { exact: true }).waitFor()
  }
  if (testAdvancedQuality) {
    const quality = page.getByRole('region', { name: 'Call quality' })
    for (const label of ['Join success', 'TURN relay use', 'Application ICE restart rate', 'Audio MOS proxy of 4 or above']) {
      await quality.getByText(label, { exact: true }).first().waitFor()
    }
    assert.equal(usageSnapshot.qos.rates['meeting:join'].positive, usageSnapshot.qos.rates['meeting:join'].sampled)
    assert.ok(usageSnapshot.qos.rates['meeting:relay'].sampled >= 10)
    assert.equal(usageSnapshot.qos.rates['direct:ice_restart'].percent, 0)
  }
  const usageUpdated = waitForAggregate(page, 'st_v6_usage_metrics', result => result.metrics.messages >= usageBaseline + 20)
  writeMessages(null, true)
  const updatedUsage = (await (await usageUpdated).json()).metrics.messages
  const usagePanel = page.getByRole('region', { name: 'Product usage' })
  const count = usagePanel.locator('.release-board-item').filter({ hasText: 'Direct messages sent' }).locator('dd')
  await count.filter({ hasText: updatedUsage.toLocaleString() }).waitFor()
  assert.ok(liveHints.length >= 2 && liveHints.every(hint => Object.keys(hint ?? {}).every(key => key === 'id')))

  const initialConnections = connected
  const reconnected = waitForAggregate(page, 'st_v6_usage_metrics', result => result.metrics.messages >= updatedUsage + 20)
  blocked = true
  await socket.close({ code: 1011, reason: 'QA disconnect' })
  writeMessages(null, false)
  blocked = false
  const reconnectedUsage = (await (await reconnected).json()).metrics.messages
  assert.ok(connected > initialConnections)
  await count.filter({ hasText: reconnectedUsage.toLocaleString() }).waitFor()
  console.log('Live analytics browser passed with real TOTP, private aggregate refreshes, empty hints, and reconnect catch-up.')
} catch (error) {
  console.error('Analytics Realtime responses:', analyticsFrames)
  throw error
} finally {
  await browser?.close()
  const actors = cohort.map(({ actor }) => "'" + actor + "'").join(',')
  const chats = cohort.map(({ chat }) => "'" + chat + "'").join(',')
  sql(`delete from public.st_messages where chat_id in (${chats});
    delete from public.st_chats where id in (${chats});
    delete from auth.users where id in (${actors});
    ${testQuality ? `delete from sectalk_private.st_v6_call_qos where event_key in (
      select extensions.digest('qos-ui-event-${run}-'||n,'sha256') from generate_series(1,10) n
    );` : ''}
    ${testAdvancedQuality ? `delete from sectalk_private.st_v6_call_qos where event_key in (
      select extensions.digest('qos-anl-${run}-'||metric||n,'sha256')
      from (values ('join'), ('relay'), ('mos'), ('ice_restart')) as fixture(metric) cross join generate_series(1,10) n
    );` : ''}
    ${staffId ? `delete from realtime.messages where topic='st:analytics:${staffId}';
      delete from sectalk_private.staff where user_id='${staffId}';` : ''}`)
  if (staffId) data(await admin.auth.admin.deleteUser(staffId))
}
