import assert from 'node:assert/strict'
import { test } from 'node:test'
import { meetingCalendar, meetingFromQuery, meetingLink } from '../apps/web/lib/meeting-calendar.ts'

test('serializes separate occurrence links and folds calendar text without breaking UTF-8',()=>{
  const origin='https://meet.example.invalid'
  const id='66000000-0000-4000-8000-000000000001'
  const second='66000000-0000-4000-8000-000000000002'
  const title='Meeting, weekly; '+ '日本語'.repeat(18)+'\nEND:VEVENT'
  const event={id,title,starts_at:'2026-12-01T10:00:00+05:30',ends_at:'2026-12-01T11:00:00+05:30'}
  const file=meetingCalendar([event,{...event,id:second}],origin,new Date('2026-11-20T12:00:00Z'))
  assert.ok(file.split('\r\n').every(line=>Buffer.byteLength(line)<=75))
  const unfolded=file.replace(/\r\n /g,'')
  assert.equal((unfolded.match(/^BEGIN:VEVENT$/gm)||[]).length,2)
  assert.equal((unfolded.match(/^END:VEVENT$/gm)||[]).length,2)
  assert.ok(unfolded.includes('DTSTART:20261201T043000Z'))
  assert.ok(unfolded.includes('SUMMARY:Meeting\\, weekly\\; '+'日本語'.repeat(18)+'\\nEND:VEVENT'))
  for(const occurrence of [id,second]){
    const link=meetingLink(origin,occurrence)
    assert.ok(unfolded.includes('URL:'+link))
    assert.equal(meetingFromQuery(new URL(link).search),occurrence)
  }
  assert.equal(meetingFromQuery('?meeting=not-a-meeting'),null)
})
