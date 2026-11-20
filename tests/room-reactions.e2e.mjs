// Run against the isolated loopback app and Supabase stack.
import assert from 'node:assert/strict'
import { randomUUID } from 'node:crypto'
import { createClient } from '@supabase/supabase-js'

const app = new URL(process.env.SECTALK_STORAGE_TEST_APP)
const supabase = new URL(process.env.SECTALK_STORAGE_TEST_URL)
assert.equal(app.hostname,'127.0.0.1')
assert.equal(supabase.hostname,'127.0.0.1')
const key = process.env.SECTALK_STORAGE_TEST_PUBLIC_KEY
const serviceKey = process.env.SECTALK_STORAGE_TEST_SERVICE_KEY
assert.ok(key && serviceKey)
const { chromium } = await import(process.env.SECTALK_PLAYWRIGHT_MODULE || 'playwright')
const options = {auth:{persistSession:false,autoRefreshToken:false}}
const admin = createClient(supabase.href,serviceKey,options)
const suffix = randomUUID().slice(0,8)
const password = randomUUID() + '1!Q'

function data(result) {
  if(result.error)throw new Error(result.error.message)
  return result.data
}

async function account(label) {
  const handle = label.toLowerCase() + '_' + suffix
  const email = handle + '@example.org'
  data(await admin.auth.admin.createUser({email,password,email_confirm:true}))
  const client = createClient(supabase.href,key,options)
  data(await client.auth.signInWithPassword({email,password}))
  data(await client.rpc('st_save_profile',{p_handle:handle,p_name:label}))
  return {client,email,handle}
}

const [owner,member] = await Promise.all([account('ReactionOwner'),account('ReactionMember')])
const workspace = data(await owner.client.rpc('st_v2_create_workspace',{p_name:'Reaction workspace '+suffix}))
data(await owner.client.rpc('st_v2_invite',{p_workspace:workspace,p_handle:member.handle}))
const invite = data(await member.client.from('st_v2_invites').select('id').eq('workspace_id',workspace).single())
data(await member.client.rpc('st_v2_reply_invite',{p_invite:invite.id,p_accept:true}))
const room = randomUUID()
const post = randomUUID()
const reply = randomUUID()
const roomName = 'Reaction room ' + suffix
data(await owner.client.rpc('st_v6_room_create',{p_id:room,p_workspace:workspace,p_name:roomName,p_kind:'public',p_template:'blank'}))
data(await owner.client.rpc('st_v6_room_post',{p_room:room,p_id:post,p_body:'Test this room post'}))
data(await owner.client.rpc('st_v6_room_post',{p_room:room,p_id:reply,p_parent:post,p_body:'Test this thread reply'}))

const browser = await chromium.launch({executablePath:process.env.SECTALK_TEST_BROWSER})
try {
  async function open(person) {
    const page = await browser.newPage()
    await page.goto(new URL('/#account',app).href)
    await page.getByLabel('Email address',{exact:true}).fill(person.email)
    await page.getByLabel('Password',{exact:true}).fill(password)
    await page.locator('button.submit-auth').click()
    await page.getByRole('navigation',{name:'SecTalk features'}).getByRole('button',{name:'Rooms',exact:true}).click()
    return page.getByRole('region',{name:'Room directory',exact:true})
  }
  const [ownerDirectory,memberDirectory] = await Promise.all([open(owner),open(member)])
  async function openRoom(directory) {
    await directory.getByRole('button',{name:new RegExp(roomName)}).click()
    return directory.getByRole('region',{name:roomName,exact:true})
  }
  const [ownerRoom,memberRoom] = await Promise.all([openRoom(ownerDirectory),openRoom(memberDirectory)])
  await memberRoom.getByRole('button',{name:'Join room',exact:true}).click()
  const postCard = panel=>panel.locator('article').filter({hasText:'Test this room post'})
  const add = card=>card.getByRole('button',{name:'Add room reaction',exact:true})
  const ownerCard = postCard(ownerRoom)
  const memberCard = postCard(memberRoom)
  await add(memberCard).waitFor()
  assert.equal(await memberDirectory.getByText('Room reaction settings',{exact:true}).count(),0)

  await ownerDirectory.getByText('Room reaction settings',{exact:true}).click()
  await ownerDirectory.getByLabel('Room emoji set').selectOption('essential')
  await ownerDirectory.getByLabel('Reactions per person per message').selectOption('1')
  const save = ownerDirectory.getByRole('button',{name:'Save reaction settings',exact:true})
  await save.click()
  await ownerDirectory.getByText('Room reaction settings saved.',{exact:true}).waitFor()

  await add(memberCard).click()
  await memberCard.getByRole('button',{name:'Thumbs up',exact:true}).click({timeout:5000})
  await memberCard.getByRole('button',{name:'Reaction 👍, 1',exact:true}).waitFor()
  await ownerCard.getByLabel('Reaction 👍, 1',{exact:true}).waitFor({timeout:5000})
  await memberCard.getByText('You reached the reaction limit for this message.').waitFor()
  assert.equal(await add(memberCard).isDisabled(),true)

  await add(ownerCard).click()
  await ownerCard.getByRole('button',{name:'Thumbs up',exact:true}).click()
  await memberCard.getByRole('button',{name:'Reaction 👍, 2',exact:true}).waitFor({timeout:5000})
  await memberCard.getByRole('button',{name:'Reaction 👍, 2',exact:true}).click()
  await ownerCard.getByRole('button',{name:'Reaction 👍, 1',exact:true}).waitFor({timeout:5000})
  await memberCard.getByLabel('Reaction 👍, 1',{exact:true}).waitFor()
  assert.equal(await memberCard.getByRole('button',{name:'Reaction 👍, 1',exact:true}).count(),0)

  await memberCard.getByRole('button',{name:/^Open thread/}).click()
  const replyCard = memberRoom.locator('article').filter({hasText:'Test this thread reply'})
  await add(replyCard).click()
  await replyCard.getByRole('button',{name:'Check mark',exact:true}).click()
  await replyCard.getByRole('button',{name:'Reaction ✅, 1',exact:true}).waitFor()

  await ownerDirectory.getByLabel('Room emoji set').selectOption('off')
  await save.click()
  await ownerDirectory.getByText('Room reaction settings saved.',{exact:true}).waitFor()
  await add(replyCard).waitFor({state:'hidden',timeout:5000})
  await replyCard.getByRole('button',{name:'Reaction ✅, 1',exact:true}).click()
  await replyCard.getByRole('button',{name:'Reaction ✅, 1',exact:true}).waitFor({state:'hidden'})
  assert.deepEqual(data(await owner.client.rpc('st_v6_room_reaction_counts',{p_room:room,p_posts:[post,reply]})),
    [{post_id:post,emoji:'👍',amount:1,mine:true}])
  console.log('Passed workspace reaction controls, open-session policy updates, live add/removal, per-message cap and thread reply reactions.')
} finally {
  await browser.close()
}
