// Run against the isolated loopback app and Supabase stack.
import assert from 'node:assert/strict'
import { randomUUID } from 'node:crypto'
import { createClient } from '@supabase/supabase-js'

const app = new URL(process.env.SECTALK_STORAGE_TEST_APP)
const supabase = new URL(process.env.SECTALK_STORAGE_TEST_URL)
assert.equal(app.hostname, '127.0.0.1')
assert.equal(supabase.origin, 'http://127.0.0.1:55321')
const options = { auth: { persistSession: false, autoRefreshToken: false } }
const publicKey = process.env.SECTALK_STORAGE_TEST_PUBLIC_KEY
const serviceKey = process.env.SECTALK_STORAGE_TEST_SERVICE_KEY
const { chromium } = await import(process.env.SECTALK_PLAYWRIGHT_MODULE || 'playwright')
const admin = createClient(supabase.origin, serviceKey, options)
const password = randomUUID() + '1!Q'
const suffix = randomUUID().slice(0, 8)

function data(result) {
  if (result.error) throw new Error(result.error.message)
  return result.data
}

async function account(handlePrefix) {
  const handle = handlePrefix + '_' + suffix
  const email = handle + '@example.org'
  const { user } = data(await admin.auth.admin.createUser({ email, password, email_confirm: true }))
  const client = createClient(supabase.origin, publicKey, options)
  data(await client.auth.signInWithPassword({ email, password }))
  data(await client.rpc('st_save_profile', { p_handle: handle, p_name: handle }))
  return { id: user.id, handle, email, client }
}
const manager = await account('school_main')
const teacher = await account('school_teacher')
const student = await account('school_student')
const outsider = await account('school_other')
const workspace = data(await manager.client.rpc('st_v6_create_typed_workspace', {
  p_id: randomUUID(), p_name: 'Synthetic School ' + suffix, p_type: 'school',
}))
for (const person of [teacher, student, outsider]) {
  data(await manager.client.rpc('st_v2_invite', { p_workspace: workspace, p_handle: person.handle }))
  const invite = data(await person.client.from('st_v2_invites').select('id').eq('workspace_id', workspace).single())
  data(await person.client.rpc('st_v2_reply_invite', { p_invite: invite.id, p_accept: true }))
}
const browser = await chromium.launch({ executablePath: process.env.SECTALK_TEST_BROWSER })
const nav = page => page.getByRole('navigation', { name: 'SecTalk features' })
const button = (scope, name) => scope.getByRole('button', { name, exact: true })
const school = page => page.getByRole('region', { name: 'School classrooms' })
const className = 'Synthetic Physics ' + suffix
const otherClassName = 'Synthetic History ' + suffix

async function open(person) {
  const page = await browser.newPage()
  await page.goto(new URL('/#account', app).href, { waitUntil: 'domcontentloaded' })
  await page.getByLabel('Email address', { exact: true }).fill(person.email)
  await page.getByLabel('Password', { exact: true }).fill(password)
  await page.locator('button.submit-auth').click()
  await button(nav(page), 'Workspaces').click()
  await button(page, 'School').click()
  await school(page).waitFor()
  return page
}
async function create(page, name) {
  await school(page).getByLabel('Classroom name', { exact: true }).fill(name)
  await button(school(page), 'Create classroom').click()
  await school(page).getByRole('heading', { name, exact: true }).waitFor()
}
async function enroll(page, person, role) {
  const panel = school(page)
  await panel.getByRole('combobox', { name: /Workspace account/ }).selectOption(person.id)
  if (role) await panel.getByRole('combobox', { name: /Classroom role/ }).selectOption(role)
  await button(panel, 'Save classroom enrollment').click()
  await panel.getByRole('listitem').filter({ hasText: person.handle + ' · ' + (role === 'teacher' ? 'Teacher' : 'Student') }).waitFor()
}

try {
  const adminPage = await open(manager)
  await create(adminPage, className)
  await enroll(adminPage, teacher, 'teacher')
  await create(adminPage, otherClassName)
  const classes = data(await manager.client.rpc('st_v7_school_classes', { p_workspace: workspace }))
  const classroom = classes.find(item => item.name === className)
  const other = classes.find(item => item.name === otherClassName)
  assert.ok(classroom.room && other.room)
  assert.deepEqual(data(await teacher.client.from('st_v6_room_posts').select('body').eq('room_id', other.room)), [])
  assert.equal((await teacher.client.rpc('st_v7_school_classes', {
    p_workspace: workspace, p_action: 'enroll', p_class: other.id, p_person: student.id, p_role: 'student',
  })).error?.code, '42501')
  const [staffPage, studentPage, otherPage] = await Promise.all([open(teacher), open(student), open(outsider)])
  await school(staffPage).getByRole('heading', { name: className, exact: true }).waitFor()
  assert.equal(await school(staffPage).getByText(otherClassName, { exact: true }).count(), 0)
  assert.equal(await school(staffPage).getByRole('combobox', { name: /Classroom role/ }).count(), 0)
  assert.equal((await teacher.client.rpc('st_v7_school_classes', {
    p_workspace: workspace, p_action: 'enroll', p_class: classroom.id, p_person: outsider.id, p_role: 'teacher',
  })).error?.code, '42501')
  await enroll(staffPage, student)
  await button(school(studentPage), 'Refresh classrooms').click()
  await button(school(studentPage), 'Open supervised room').click()
  const room = studentPage.getByRole('region', { name: className, exact: true })
  await room.getByText(/Class starter/).waitFor()
  await room.getByLabel('Write a room message', { exact: true }).fill('Synthetic supervised room message')
  await button(room, 'Send').click()
  await room.getByText('Synthetic supervised room message', { exact: true }).waitFor()
  await button(school(staffPage), 'Open supervised room').click()
  await staffPage.getByRole('region', { name: className, exact: true }).getByText('Synthetic supervised room message', { exact: true }).waitFor()
  await school(otherPage).getByText('No classrooms are assigned to you.', { exact: true }).waitFor()
  assert.deepEqual(data(await outsider.client.from('st_v6_room_posts').select('body').eq('room_id', classroom.room)), [])
  assert.deepEqual(data(await outsider.client.from('st_v6_workspace_groups').select('id').eq('id', classroom.id)), [])
  await button(staffPage, 'Back to School').click()
  await school(staffPage).getByRole('button', { name: 'Remove ' + student.handle + ' from classroom', exact: true }).click()
  await school(staffPage).getByText('Classroom access removed.', { exact: true }).waitFor()
  assert.deepEqual(data(await student.client.from('st_v6_room_posts').select('body').eq('room_id', classroom.room)), [])
  await button(studentPage, 'Back to School').click()
  await school(studentPage).getByText('No classrooms are assigned to you.', { exact: true }).waitFor()
  console.log('Passed actual class creation, scoped teacher enrollment, private classroom posting and access revocation in four Edge contexts.')
} finally {
  await browser.close()
  await Promise.allSettled([manager, teacher, student, outsider].map(person => admin.auth.admin.deleteUser(person.id)))
}
