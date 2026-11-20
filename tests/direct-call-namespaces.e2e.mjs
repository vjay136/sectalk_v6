// Start the private Chromium networks with node tests/helpers/call-namespace-fixture.mjs start.
// Use the local Supabase gateway on 55321 and an isolated app on 3492 with:
// TURN_SHARED_SECRET=direct-namespace-local-fixture
// TURN_URLS=turn:call-turn:3478?transport=udp
// STUN_URL=stun:call-turn:3478
// Set the same SECTALK_STORAGE_TEST_* and SECTALK_PLAYWRIGHT_MODULE values as other local E2E tests.
// End the fixture with node tests/helpers/call-namespace-fixture.mjs stop.
import assert from 'node:assert/strict'
import { execFileSync } from 'node:child_process'
import { randomUUID } from 'node:crypto'
import { createClient } from '@supabase/supabase-js'

const app = new URL(process.env.SECTALK_STORAGE_TEST_APP)
const supabase = new URL(process.env.SECTALK_STORAGE_TEST_URL)
assert.equal(app.href, 'http://127.0.0.1:3492/')
assert.equal(supabase.hostname, '127.0.0.1')
const { SECTALK_STORAGE_TEST_PUBLIC_KEY: key, SECTALK_STORAGE_TEST_SERVICE_KEY: serviceKey } = process.env
assert.ok(key && serviceKey)
const options = { auth: { persistSession:false, autoRefreshToken:false } }
const admin = createClient(supabase.href, serviceKey, options)
const suffix = randomUUID().slice(0, 8)
const password = randomUUID()+'1!Q'

function data(result) {
  if (result.error) throw new Error(result.error.message)
  return result.data
}

function docker(...args) {
  return execFileSync('docker', args, { encoding:'utf8', timeout:10000 }).trim()
}

for (const [side, own, peer] of [['a','241','242'], ['b','242','241']]) {
  const container = 'sectalk-v6-direct-browser-'+side
  const network = 'sectalk-v6-direct-'+side
  const result = JSON.parse(docker('inspect', '--format', '{{json .NetworkSettings.Networks}}', container))
  assert.deepEqual(Object.keys(result), [network])
  assert.equal(result[network].IPAddress, '172.29.'+own+'.20')
  assert.equal(docker('network','inspect','--format','{{.Internal}}',network),'true')
  const probes = JSON.parse(docker('exec',container,'node','-e',`
    const urls=['http://127.0.0.1:3492/api/health','http://127.0.0.1:55321/auth/v1/health',
      'http://172.29.${peer}.20:9222/json/version'];
    Promise.all(urls.map(url=>fetch(url,{signal:AbortSignal.timeout(2000)})
      .then(response=>response.status).catch(error=>error.cause?.code||error.name)))
      .then(results=>console.log(JSON.stringify(results)));
  `))
  assert.equal(probes[0],200)
  assert.equal(probes[1],200)
  assert.equal(probes[2],'ENETUNREACH')
}

const accounts = []
async function provision(name) {
  const handle = name.toLowerCase()+'_'+suffix
  const email = handle+'@example.org'
  const user = data(await admin.auth.admin.createUser({ email,password,email_confirm:true })).user
  const client = createClient(supabase.href,key,options)
  const person = { name, handle, email, client, id:user.id }
  accounts.push(person)
  data(await client.auth.signInWithPassword({email,password}))
  data(await client.rpc('st_save_profile',{p_handle:handle,p_name:name}))
  return person
}

const { chromium } = await import(process.env.SECTALK_PLAYWRIGHT_MODULE || 'playwright')
const browsers = []
async function launch(port, person) {
  const browser = await chromium.connectOverCDP('http://127.0.0.1:'+port)
  browsers.push(browser)
  const context = await browser.newContext({locale:'en-US',permissions:['camera','microphone']})
  const page = await context.newPage()
  await page.addInitScript(() => {
    const Peer = window.RTCPeerConnection
    window.testDirectPeers = []
    window.RTCPeerConnection = class extends Peer {
      constructor(config) {
        super(config)
        window.testDirectPeers.push(this)
      }
    }
  })
  await page.goto(app.href)
  await page.getByLabel('Email address',{exact:true}).fill(person.email)
  await page.getByLabel('Password',{exact:true}).fill(password)
  await page.locator('button.submit-auth').click()
  return page
}

async function verifyMedia(page, mode) {
  const kinds = mode==='Video' ? ['audio','video'] : ['audio']
  const sample = () => page.evaluate(async kinds => {
    const peer = window.testDirectPeers.findLast(candidate=>candidate.connectionState==='connected')
    if (!peer) return null
    const stats = await peer.getStats()
    const transport = [...stats.values()].find(record=>record.type==='transport' && record.selectedCandidatePairId)
    const pair = transport && stats.get(transport.selectedCandidatePairId)
    const local = pair && stats.get(pair.localCandidateId)
    const remote = pair && stats.get(pair.remoteCandidateId)
    const tracks = {}
    for (const kind of kinds) {
      const inbound = [...stats.values()].find(record=>record.type==='inbound-rtp' && record.kind===kind)
      const outbound = [...stats.values()].find(record=>record.type==='outbound-rtp' && record.kind===kind)
      tracks[kind] = { received:inbound?.bytesReceived, sent:outbound?.bytesSent, frames:inbound?.framesDecoded,
        energy:inbound?.totalAudioEnergy, samples:inbound?.totalSamplesReceived }
    }
    return { policy:peer.getConfiguration().iceTransportPolicy, local:local?.candidateType,
      remote:remote?.candidateType, relayProtocol:local?.relayProtocol, tracks }
  },kinds)

  let initial
  let latest
  const deadline = Date.now()+15000
  while (Date.now()<deadline) {
    const current = await sample()
    if (current?.local==='relay' && current.remote==='relay' &&
        kinds.every(kind=>current.tracks[kind].received>0 && current.tracks[kind].sent>0)) {
      initial ??= current
      if (kinds.every(kind=>current.tracks[kind].received>initial.tracks[kind].received &&
          current.tracks[kind].sent>initial.tracks[kind].sent) &&
          current.tracks.audio.energy>initial.tracks.audio.energy &&
          current.tracks.audio.samples>initial.tracks.audio.samples &&
          (mode==='Audio' || current.tracks.video.frames>initial.tracks.video.frames)) {
        latest = current
        break
      }
    }
    await new Promise(resolve=>setTimeout(resolve,350))
  }
  assert.ok(latest, mode+' media did not progress bidirectionally through a relay-only candidate pair')
  assert.equal(latest.policy,'relay')
  assert.equal(latest.relayProtocol,'udp')
  await page.waitForFunction(video => {
    const remote = document.querySelector('video[aria-label="Remote participant"]')
    return remote?.srcObject?.getAudioTracks().length===1 &&
      (video ? remote.videoWidth>0 && remote.srcObject.getVideoTracks().length===1 : !remote.srcObject.getVideoTracks().length)
  }, mode==='Video')
}

const panel = (page,mode) => page.getByRole('region',{name:mode+' call',exact:true})

try {
  const [one,two] = [await provision('NamespaceCaller'),await provision('NamespaceCallee')]
  const chat = data(await one.client.rpc('st_request',{p_handle:two.handle}))
  data(await two.client.rpc('st_respond',{p_chat:chat,p_accept:true}))
  const [left,right] = await Promise.all([launch(3493,one),launch(3494,two)])
  await Promise.all([left.locator('.chat-item').filter({hasText:two.name}).click(),
    right.locator('.chat-item').filter({hasText:one.name}).click()])
  const calls = [
    { mode:'Audio', entry:'Inbox', source:left, destination:right, origin:one, target:two },
    { mode:'Video', entry:'Calls', source:right, destination:left, origin:two, target:one },
    { mode:'Video', entry:'Inbox', source:left, destination:right, origin:one, target:two },
    { mode:'Audio', entry:'Calls', source:right, destination:left, origin:two, target:one },
  ]
  const seenCalls = new Set()
  for (const { mode,entry,source,destination,origin,target } of calls) {
    const label = mode.toLowerCase()
    if (entry==='Calls') {
      await source.getByRole('button',{name:'Calls',exact:true}).click()
      await source.getByRole('heading',{name:'Calls',exact:true}).waitFor()
      await source.getByRole('button',{name:'Start '+label+' call with '+target.name,exact:true}).first().click()
    } else await source.getByRole('button',{name:'Start '+label+' call',exact:true}).click()
    await panel(destination,mode).getByRole('button',{name:'Answer',exact:true}).click()
    await Promise.all([source,destination].map(page=>panel(page,mode).getByText(mode+' · Connected',{exact:true}).waitFor()))
    const active = data(await origin.client.from('st_calls').select('id,caller,callee,video')
      .eq('chat_id',chat).eq('status','active').single())
    assert.equal(active.caller,origin.id)
    assert.equal(active.callee,target.id)
    assert.equal(active.video,mode==='Video')
    assert.ok(!seenCalls.has(active.id))
    seenCalls.add(active.id)
    await Promise.all([source,destination].map(page=>verifyMedia(page,mode)))
    await panel(source,mode).getByRole('button',{name:'Hang up',exact:true}).click()
    await Promise.all([source,destination].map(page=>panel(page,mode).waitFor({state:'hidden'})))
    assert.equal(data(await origin.client.from('st_calls').select('status').eq('id',active.id).single()).status,'ended')
    console.log(mode+' via '+entry+' passed. Both isolated browsers used UDP TURN and decoded incoming media.')
  }
} finally {
  await Promise.allSettled(browsers.map(browser=>browser.close()))
  await Promise.allSettled(accounts.map(person=>admin.auth.admin.deleteUser(person.id)))
}
