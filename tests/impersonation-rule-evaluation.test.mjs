import assert from 'node:assert/strict'
import test from 'node:test'
import { evaluateImpersonationRules, impersonationFixtureVersion } from '../apps/web/lib/impersonation-rule-evaluation.mjs'
import { findImpersonationSignals } from '../apps/web/lib/impersonation.mjs'

test('synthetic benchmark is reproducible in both directions', () => {
  assert.equal(impersonationFixtureVersion, 'synthetic-profile-pairs-v1')
  const result = evaluateImpersonationRules('profile-rules-v1', 'profile-rules-v2')
  assert.deepEqual(result, {
    active: { tp: 4, fp: 2, tn: 2, fn: 0 },
    shadow: { tp: 3, fp: 1, tn: 3, fn: 1 },
    disagreements: 2,
    cases: 8,
  })
  assert.deepEqual(evaluateImpersonationRules('profile-rules-v2', 'profile-rules-v1'),
    { ...result, active: result.shadow, shadow: result.active })
  assert.throws(() => evaluateImpersonationRules('profile-rules-v1', 'profile-rules-v1'), /distinct/)
  assert.throws(() => evaluateImpersonationRules('unregistered', 'profile-rules-v1'), /registered/)
})

test('the runtime versions differ at the broad setting and honor the configured threshold', () => {
  const roster = [
    { id: 'protected', name: 'Casey Reed', handle: 'caseyreed' },
    { id: 'possible', name: 'Independent name', handle: 'caseyreedx' },
  ]
  assert.deepEqual(findImpersonationSignals(roster, ['protected'], 1, 'profile-rules-v1')[0].reasons, ['lookalike_handle'])
  assert.deepEqual(findImpersonationSignals(roster, ['protected'], 1, 'profile-rules-v2'), [])
  assert.deepEqual(findImpersonationSignals(roster, ['protected'], 2, 'profile-rules-v1'), [])
})
