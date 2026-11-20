type DisclosureConfig = {
  origin: string | undefined
  contact: string | undefined
  expires: string | undefined
}

function webUrl(value: string) {
  if (!value.startsWith('https://') || /[\s\\]/u.test(value)) return null
  let url: URL
  try {
    url = new URL(value)
  } catch {
    return null
  }
  return url.username || url.password || url.hash ? null : url
}

export function parseSecurityDisclosure({ origin, contact, expires }: DisclosureConfig, now = Date.now()) {
  if (!origin || !contact || !expires || /\s/u.test(contact)) return null
  const site = webUrl(origin)
  if (!site || site.pathname !== '/' || site.search) return null

  const email = /^mailto:[A-Z0-9._-]+(?:\+[A-Z0-9._-]+)?@[A-Z0-9-]+(?:\.[A-Z0-9-]+)+$/i.test(contact)
  const form = webUrl(contact)
  if (form?.search) return null
  if (!email && !form) return null

  const expiresAt = Date.parse(expires)
  if (!Number.isFinite(expiresAt) || expiresAt <= now || expiresAt - now >= 365 * 24 * 60 * 60 * 1000) return null
  if (new Date(expiresAt).toISOString().replace('.000Z', 'Z') !== expires) return null

  return {
    contact: form?.href ?? contact,
    expires,
    canonical: new URL('/.well-known/security.txt', site).href,
    policy: new URL('/security', site).href,
  }
}

export function getSecurityDisclosure() {
  return parseSecurityDisclosure({
    origin: process.env.SECTALK_APP_URL,
    contact: process.env.SECTALK_SECURITY_CONTACT,
    expires: process.env.SECTALK_SECURITY_CONTACT_EXPIRES,
  })
}
