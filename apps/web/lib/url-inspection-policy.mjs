import { isIP } from 'node:net'
import { domainToUnicode } from 'node:url'
import confusables from './unicode-confusables.mjs'

const brands = [
  { name: 'Microsoft', official: ['microsoft.com', 'microsoftonline.com'] },
  { name: 'Google', official: ['google.com', 'googleusercontent.com'] },
  { name: 'PayPal', official: ['paypal.com'] },
  { name: 'Apple', official: ['apple.com', 'icloud.com'] },
]

function skeleton(text) {
  return [...text.normalize('NFKC').toLowerCase()].map(character => confusables[character] ?? character)
    .join('').normalize('NFKD').toLowerCase().replace(/[^a-z0-9]/g, '')
}

export function inspectionHostname(text) {
  return typeof text === 'string' && text.length <= 253 && text.includes('.') &&
    text.split('.').every(label => /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(label)) &&
    !isIP(text) && !['.local','.localhost','.internal','.onion'].some(suffix => text.endsWith(suffix))
}

export function normalizeInspectionUrl(raw) {
  if (typeof raw !== 'string' || raw.length > 1500 || /[\u0000-\u001f\u007f\\]/u.test(raw)) return null
  try {
    const url = new URL(raw.trim())
    if (!['http:', 'https:'].includes(url.protocol) || url.username || url.password ||
        !inspectionHostname(url.hostname) || url.port) return null
    const stripped = Boolean(url.search || url.hash)
    url.search = ''
    url.hash = ''
    return { url, stripped }
  } catch { return null }
}

export function inspectionDomainSignals(url) {
  const unicode = domainToUnicode(url.hostname)
  const labels = unicode.split('.')
  const possibleBrands = brands.filter(brand => !brand.official.some(domain => url.hostname === domain || url.hostname.endsWith('.' + domain))
    && labels.some(label => {
      const name = skeleton(brand.name)
      return skeleton(label) === name || label.split('-').some(word => skeleton(word) === name)
    })).map(brand => brand.name)
  return { hostname: url.hostname, internationalized: url.hostname.split('.').some(label => label.startsWith('xn--')),
    possibleBrands, unencrypted: url.protocol === 'http:' }
}
