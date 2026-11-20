import type { EmojiMartData } from '@emoji-mart/data'
import imported from '@emoji-mart/data/sets/15/native.json' with { type: 'json' }

const data:EmojiMartData = imported
const entries = data.emojis

export const nativeEmoji = [...new Map(Object.values(entries).flatMap(entry =>
  entry.skins.map((skin, index) => [skin.native, {
    value:skin.native,
    label:entry.name + (index ? ' · skin tone ' + index : ''),
    terms:entry.keywords.join(' ').toLowerCase(),
  }] as const))).values()]

function group(id: string, count: number) {
  return data.categories.find(category => category.id === id)!.emojis.slice(0, count).map(key => entries[key])
}

// Every custom entry displays a large base with a separate badge in the corner.
const bases = [...group('people',32), ...group('nature',30), ...group('foods',22), ...group('activity',20)]
const badges = [...group('objects',62), ...group('symbols',42)]
export const baseEmoji=bases.map(entry=>entry.skins[0].native)
export const badgeEmoji=badges.map(entry=>entry.skins[0].native)
export const customEmoji = [...new Map(bases.flatMap(base => badges.map(badge => {
  const first = base.skins[0].native
  const second = badge.skins[0].native
  const value = '[[st:' + first + '|' + second + ']]'
  const label = base.name + ' with ' + badge.name
  return [value, { value, label, terms:[...base.keywords,...badge.keywords].join(' ').toLowerCase() }] as const
}))).values()]
