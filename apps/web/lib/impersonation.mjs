import mappings from './unicode-confusables.mjs'

/** @typedef {{id: string, name: string, handle: string}} Account */
/** @typedef {'same_name'|'lookalike_name'|'lookalike_handle'} MatchReason */

export const impersonationRuleVersions = ['profile-rules-v1', 'profile-rules-v2']

const ignored = /\p{Default_Ignorable_Code_Point}/gu
const separators = /[\p{Z}\p{P}]/gu

/** @param {string} value */
function fold(value) {
  return value.normalize('NFKC').toLowerCase().replace(ignored, '').trim().replace(/\s+/gu, ' ')
}

/** @param {string} folded */
function nameSkeleton(folded) {
  return [...folded.normalize('NFD')].map(character => mappings[character] ?? character)
    .join('').normalize('NFD').toLowerCase().replace(separators, '')
}

/** @param {string} left @param {string} right */
function oneHandleEdit(left, right) {
  if (left === right || Math.min(left.length, right.length) < 6 || Math.abs(left.length - right.length) > 1) return false
  if (left.length > right.length) [right, left] = [left, right]
  let i = 0
  let j = 0
  let differences = 0
  while (i < left.length && j < right.length) {
    if (left[i] !== right[j]) {
      if (++differences > 1) return false
      if (left.length < right.length) { j++; continue }
    }
    i++
    j++
  }
  return differences + (right.length - j) === 1
}

/** @param {Account} account */
function comparison(account) {
  const name = fold(account.name)
  const handle = fold(account.handle)
  return { account, name, handle, nameKey: nameSkeleton(name), handleKey: nameSkeleton(handle) }
}

/** @param {Account[]} accounts @param {string[]} watchedIds @param {number} [minimum] @param {string} [version] */
export function findImpersonationSignals(accounts, watchedIds, minimum = 1, version = impersonationRuleVersions[0]) {
  if (!impersonationRuleVersions.includes(version)) throw new Error('Unknown impersonation rule version')
  const watched = new Set(watchedIds)
  const indexed = accounts.map(comparison)
  return indexed.filter(person => watched.has(person.account.id)).flatMap(person => indexed.flatMap(candidate => {
    if (person.account.id === candidate.account.id) return []
    /** @type {MatchReason[]} */
    const reasons = []
    if (person.name && person.name === candidate.name) reasons.push('same_name')
    else if (minimum <= 2 && person.nameKey && person.nameKey === candidate.nameKey) reasons.push('lookalike_name')
    if (minimum <= 2 && person.handle && candidate.handle && person.handle !== candidate.handle &&
      (person.handleKey === candidate.handleKey || (minimum <= 1 &&
        (version === impersonationRuleVersions[0] || reasons.length > 0) && oneHandleEdit(person.handle, candidate.handle)))) {
      reasons.push('lookalike_handle')
    }
    return reasons.length ? [{ protectedAccount: person.account, candidate: candidate.account, reasons }] : []
  }))
}
