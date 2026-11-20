import assert from 'node:assert/strict'
import { test } from 'node:test'
import { fileTicketSeconds, issueFileTicket, readFileTicket } from '../apps/web/lib/file-download-ticket.ts'

test('file links enforce the recipient, exact signature and a thirty-second lifetime',()=>{
  const now=1000
  const file='68000000-0000-4000-8000-000000000001'
  const actor='68000000-0000-4000-8000-000000000002'
  const key='test-only-signing-key-32-bytes-long'
  const signed=issueFileTicket(file,actor,key,now)
  const expiry=now+fileTicketSeconds*1000
  assert.equal(readFileTicket(signed,actor,key,expiry-1).file,file)
  assert.equal(readFileTicket(signed,actor,key,expiry),null)
  assert.equal(readFileTicket(signed,'different-user',key,now),null)
  assert.equal(readFileTicket(signed,actor,key+'x',now),null)
  const [payload,signature]=signed.split('.')
  assert.equal(readFileTicket((payload[0]==='a'?'b':'a')+payload.slice(1)+'.'+signature,actor,key,now),null)
})
