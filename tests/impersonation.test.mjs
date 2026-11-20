import assert from 'node:assert/strict'
import test from 'node:test'
import { findImpersonationSignals } from '../apps/web/lib/impersonation.mjs'

const target = { id:'protected', name:'Avery Eagle', handle:'avery_eagle' }
const roster = [
  target,
  { id:'duplicate', name:'AVERY\u200B EAGLE', handle:'another_profile' },
  { id:'confusable', name:'\u0391very Eagle', handle:'avery_eag1e' },
  { id:'near', name:'Different person', handle:'avery_eaglet' },
  { id:'unrelated', name:'Avery Ng', handle:'avery_ng' },
]

test('protected accounts flag exact, visually similar and near usernames', () => {
  const signals = findImpersonationSignals(roster, [target.id])
  assert.deepEqual(signals.map(({candidate,reasons}) => [candidate.id,reasons]), [
    ['duplicate', ['same_name']],
    ['confusable', ['lookalike_name','lookalike_handle']],
    ['near', ['lookalike_handle']],
  ])
  assert.ok(signals.every(signal => signal.protectedAccount.id === target.id))
})

test('missing or identical account IDs and weak short-name variants do not create matches', () => {
  assert.deepEqual(findImpersonationSignals(roster, ['outside-workspace']), [])
  assert.deepEqual(findImpersonationSignals([
    { id:'one', name:'Dan Jones', handle:'dan' },
    { id:'two', name:'Ben Jones', handle:'den' },
  ], ['one']), [])
})
