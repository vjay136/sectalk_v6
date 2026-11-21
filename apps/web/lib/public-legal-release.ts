export type LegalSection = { title: string; text: string }
type ApprovedDocument = { version: string; approvedOn: string; effectiveOn: string; sections: LegalSection[] }
type LegalOperator = { name: string; supportContact: string; privacyContact: string }
type PublicLegalRelease = { operator: LegalOperator; terms: ApprovedDocument; privacy: ApprovedDocument }

function record(value: unknown): Record<string, unknown> {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error('Invalid legal release record')
  return value as Record<string, unknown>
}

function plainText(value: unknown, max: number, multiline = false): string {
  const disallowed = multiline ? /[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/ : /[\u0000-\u001f\u007f]/
  if (typeof value !== 'string' || !value.trim() || value.length > max || disallowed.test(value)) {
    throw new Error('Invalid legal release text')
  }
  return value.trim()
}

function publicContact(emailValue: unknown, urlValue: unknown, appOrigin: string | undefined): string {
  if (urlValue === undefined) {
    const email = plainText(emailValue, 254)
    if (!/^[a-z0-9_+.-]+@[a-z0-9-]+(?:\.[a-z0-9-]+)+$/i.test(email)) throw new Error('Invalid public email address')
    return 'mailto:' + email
  }
  const address = plainText(urlValue, 2048)
  if (emailValue !== undefined || address !== urlValue || !/^https:\/\/[^/]/.test(address) || /[\s\\?#]/u.test(address)) {
    throw new Error('Invalid public contact URL')
  }
  const url = new URL(address)
  const vulnerabilityForm = url.origin === URL.parse(appOrigin ?? '')?.origin &&
    /^\/security\/report\/*$/i.test(decodeURIComponent(url.pathname))
  if (url.username || url.password || !/^(?:[a-z0-9-]+\.)+[a-z][a-z0-9-]*$/i.test(url.hostname) || vulnerabilityForm) {
    throw new Error('Invalid public contact host')
  }
  return url.href
}

function releaseDate(value: unknown): string {
  const date = plainText(value, 10)
  if (!/^\d{4}-\d{2}-\d{2}$/.test(date) || new Date(date).toISOString().slice(0, 10) !== date) {
    throw new Error('Invalid legal release date')
  }
  return date
}

function approvedDocument(value: unknown, today: string): ApprovedDocument {
  const entry = record(value)
  const version = plainText(entry.version, 48)
  const approvedOn = releaseDate(entry.approvedOn)
  const effectiveOn = releaseDate(entry.effectiveOn)
  if (entry.status !== 'approved' || !/^[a-z0-9][a-z0-9._-]*$/i.test(version) ||
      approvedOn > effectiveOn || effectiveOn > today ||
      !Array.isArray(entry.sections) || !entry.sections.length || entry.sections.length > 24) {
    throw new Error('Document is unavailable for release')
  }
  const sections = entry.sections.map(value => {
    const section = record(value)
    return { title: plainText(section.title, 120), text: plainText(section.text, 8000, true) }
  })
  return { version, approvedOn, effectiveOn, sections }
}

export function parsePublicLegalRelease(raw: string | undefined, now = new Date(), appOrigin?: string): PublicLegalRelease | null {
  if (!raw || Buffer.byteLength(raw, 'utf8') > 32000) return null
  try {
    const input = record(JSON.parse(raw))
    const contact = record(input.operator)
    const today = now.toISOString().slice(0, 10)
    return {
      operator: {
        name: plainText(contact.name, 160),
        supportContact: publicContact(contact.supportEmail, contact.supportUrl, appOrigin),
        privacyContact: publicContact(contact.privacyEmail, contact.privacyUrl, appOrigin),
      },
      terms: approvedDocument(input.terms, today),
      privacy: approvedDocument(input.privacy, today),
    }
  } catch {
    return null
  }
}

export function publicLegalRelease() {
  return parsePublicLegalRelease(process.env.SECTALK_PUBLIC_LEGAL_RELEASE, new Date(), process.env.SECTALK_APP_URL)
}
