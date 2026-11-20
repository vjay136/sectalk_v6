import { findImpersonationSignals, impersonationRuleVersions } from './impersonation.mjs'

export const impersonationFixtureVersion = 'synthetic-profile-pairs-v1'
const fixtures = [
  ['Avery Birch', 'averybirch', 'Avery Birch', 'unrelated_handle', true],
  ['Avery Birch', 'averybirch', 'Αvery Birch', 'unrelated_handle', true],
  ['Avery Birch', 'averybirch', 'April Oak', 'averybirchx', false],
  ['Robin Cedar', 'robincedar', 'Independent Display Name', 'robincedarx', true],
  ['Robin Cedar', 'robincedar', 'Independent Display Name', 'unrelated_handle', false],
  ['Sam Ellis', 'samelliss', 'Sam Ellis', 'another_sam', false],
  ['Juniper Ash', 'juniperash', 'Juniper Ash', 'juniperashx', true],
  ['Kai', 'kai', 'Mal', 'mai', false],
]

function detected(version, [name, handle, candidateName, candidateHandle]) {
  return findImpersonationSignals([
    { id: 'protected', name, handle },
    { id: 'candidate', name: candidateName, handle: candidateHandle },
  ], ['protected'], 1, version).length > 0
}

export function evaluateImpersonationRules(active, shadow) {
  if (!impersonationRuleVersions.includes(active) || !impersonationRuleVersions.includes(shadow) || active === shadow) {
    throw new Error('Choose two distinct registered impersonation rule versions')
  }
  const stats = {
    active: { tp: 0, fp: 0, tn: 0, fn: 0 },
    shadow: { tp: 0, fp: 0, tn: 0, fn: 0 },
    disagreements: 0,
    cases: fixtures.length,
  }
  for (const fixture of fixtures) {
    const expected = fixture[4]
    const incumbent = detected(active, fixture)
    const challenger = detected(shadow, fixture)
    stats.active[incumbent ? (expected ? 'tp' : 'fp') : (expected ? 'fn' : 'tn')]++
    stats.shadow[challenger ? (expected ? 'tp' : 'fp') : (expected ? 'fn' : 'tn')]++
    if (incumbent !== challenger) stats.disagreements++
  }
  return stats
}
