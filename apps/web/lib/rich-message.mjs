const token = /(\[\[st:[^\n]{1,70}?\]\])|(!?\[([^\[\]\n]{1,120})\]\(([^()\s]{1,1500})\))|(`([^`\n]{1,400})`)|(\*\*([^*\n]{1,400})\*\*)|(\*([^*\n]{1,400})\*)|(https:\/\/[^\s<>"'`()[\]{}]{1,1492})/gi

export function safeRichLink(raw) {
  if (typeof raw !== 'string' || raw.length > 1500 || /[\p{Cc}\p{Cf}\\]/u.test(raw)) return null
  try {
    const url = new URL(raw)
    const name = url.hostname
    if (url.protocol !== 'https:' || url.username || url.password || url.port || !name.includes('.') ||
        !/^(?:[a-z0-9-]+\.)+[a-z][a-z0-9-]*$/i.test(name) || /\.(?:localhost|local|internal|onion)$/i.test(name)) return null
    const inspect = new URL(url)
    inspect.search = ''
    inspect.hash = ''
    return { href: url.href, host: name, inspect: inspect.href }
  } catch { return null }
}

export function parseRichText(value) {
  const parts = []
  let start = 0
  for (const match of value.matchAll(token)) {
    const [raw, emoji, markdown, label, target, , code, , strong, , emphasis, bare] = match
    if (match.index > start) parts.push({ kind: 'text', text: value.slice(start, match.index) })
    start = match.index + raw.length
    if (emoji) parts.push({ kind: 'text', text: emoji })
    else if (code) parts.push({ kind: 'code', text: code })
    else if (strong) parts.push({ kind: 'strong', text: strong })
    else if (emphasis) parts.push({ kind: 'em', text: emphasis })
    else if (markdown?.startsWith('!')) parts.push({ kind: 'text', text: raw })
    else {
      const candidate = target || bare?.replace(/[.,;:!?]+$/, '')
      const link = safeRichLink(candidate)
      if (!link) parts.push({ kind: 'text', text: raw })
      else {
        parts.push({ kind: 'link', text: target ? label : candidate, url: link })
        if (bare && candidate.length < bare.length) parts.push({ kind: 'text', text: bare.slice(candidate.length) })
      }
    }
  }
  if (start < value.length) parts.push({ kind: 'text', text: value.slice(start) })
  return parts
}
