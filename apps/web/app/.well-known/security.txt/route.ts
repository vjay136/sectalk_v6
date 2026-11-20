import { getSecurityDisclosure } from '../../../lib/security-disclosure'

export async function GET() {
  const disclosure = getSecurityDisclosure()
  const headers = { 'Content-Type': 'text/plain; charset=utf-8', 'Cache-Control': 'no-store' }
  if (!disclosure) return new Response('Security disclosure contact is unavailable.\n', { status: 503, headers })

  const body = [
    'Contact: ' + disclosure.contact,
    'Expires: ' + disclosure.expires,
    'Preferred-Languages: en',
    'Canonical: ' + disclosure.canonical,
    'Policy: ' + disclosure.policy,
  ].join('\n') + '\n'
  return new Response(body, { headers })
}
