import mappings from './unicode-confusables.mjs'

/** @typedef {{id: string, name: string, handle: string}} Account */
/** @typedef {'same_name'|'lookalike_name'|'lookalike_handle'} MatchReason */

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

/** @param {Account[]} accounts @param {string[]} watchedIds */
export function findImpersonationSignals(accounts, watchedIds) {
  const watched = new Set(watchedIds)
  const indexed = accounts.map(comparison)
  return indexed.filter(person => watched.has(person.account.id)).flatMap(person => indexed.flatMap(candidate => {
    if (person.account.id === candidate.account.id) return []
    /** @type {MatchReason[]} */
    const reasons = []
    if (person.name && person.name === candidate.name) reasons.push('same_name')
    else if (person.nameKey && person.nameKey === candidate.nameKey) reasons.push('lookalike_name')
    if (person.handle && candidate.handle && person.handle !== candidate.handle &&
      (person.handleKey === candidate.handleKey || oneHandleEdit(person.handle, candidate.handle))) {
      reasons.push('lookalike_handle')
    }
    return reasons.length ? [{ protectedAccount: person.account, candidate: candidate.account, reasons }] : []
  }))
}
