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
  const origin=process.env.SECTALK_APP_URL
  const override=process.env.SECTALK_SECURITY_CONTACT
  const intake=vulnerabilityIntakeContact()
  const site=origin?webUrl(origin):null
  if (site&&override&&webUrl(override)?.href===new URL('/security/report',site).href&&!intake) return null
  return parseSecurityDisclosure({
    origin,
    contact: override ?? intake ?? undefined,
    expires: process.env.SECTALK_SECURITY_CONTACT_EXPIRES,
  })
}

export function vulnerabilityIntakeContact() {
  const origin=process.env.SECTALK_APP_URL
  const key=process.env.SECTALK_DISCLOSURE_ENCRYPTION_KEY
  if (!origin||!process.env.NEXT_PUBLIC_SUPABASE_URL||!process.env.NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY||
    !process.env.SECTALK_DISCLOSURE_SERVICE_KEY||!key||!/^[-_A-Za-z0-9]{43}$/.test(key)||
    Buffer.from(key,'base64url').toString('base64url')!==key) return null
  const site=webUrl(origin)
  if (!site) return null
  return parseSecurityDisclosure({origin,contact:new URL('/security/report',site).href,
    expires:process.env.SECTALK_SECURITY_CONTACT_EXPIRES})?.contact??null
}
