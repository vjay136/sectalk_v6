import { createHmac } from 'node:crypto'
import { setTimeout } from 'node:timers/promises'

export async function totpCode(secret) {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'
  const bits = [...secret.replace(/=+$/, '').toUpperCase()].map(character =>
    alphabet.indexOf(character).toString(2).padStart(5, '0')).join('')
  const bytes = Buffer.from(bits.match(/.{8}/g).map(part => Number.parseInt(part, 2)))
  const remaining = 30000 - Date.now() % 30000
  if (remaining < 2500) await setTimeout(remaining + 50)
  const counter = Buffer.alloc(8)
  counter.writeBigUInt64BE(BigInt(Math.floor(Date.now() / 30000)))
  const mac = createHmac('sha1', bytes).update(counter).digest()
  return String((mac.readUInt32BE(mac.at(-1) & 15) & 0x7fffffff) % 1_000_000).padStart(6, '0')
}

export async function fixtureAuthenticator(client) {
  const enrollment = await client.auth.mfa.enroll({ factorType: 'totp', friendlyName: 'Local QA' })
  if (enrollment.error) throw enrollment.error
  const { id, totp } = enrollment.data
  const verification = await client.auth.mfa.challengeAndVerify({ factorId: id, code: await totpCode(totp.secret) })
  if (verification.error) throw verification.error
  return { id, secret: totp.secret, session: verification.data }
}

export async function verifyStaffPanel(panel, secret) {
  if (!secret) {
    await panel.getByRole('button', { name: 'Set up authenticator', exact: true }).click()
    secret = (await panel.locator('.mfa-setup code').textContent()).trim()
  }
  await panel.getByLabel('Authenticator code', { exact: true }).fill(await totpCode(secret))
  await panel.getByRole('button', { name: 'Verify access', exact: true }).click()
  return secret
}
