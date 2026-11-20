import { randomBytes, randomUUID } from 'node:crypto'
import { integrationFailure, integrationHeaders, integrationIdentity, uuidPattern } from '../../../../lib/integration-server'
import { sealWebhookSecret, webhookUrl } from '../../../../lib/webhook-transport'

export const runtime = 'nodejs'

export async function POST(request: Request) {
  const client = await integrationIdentity(request)
  if (!client) return integrationFailure(401, 'Sign in to manage webhooks.')
  const input = await request.json().catch(() => null)
  if (typeof input?.workspace !== 'string' || !uuidPattern.test(input.workspace)) {
    return integrationFailure(400, 'Choose a valid workspace.')
  }
  if (input.action === 'revoke' && typeof input.endpoint === 'string' && uuidPattern.test(input.endpoint)) {
    const { error } = await client.rpc('st_v6_revoke_webhook', { p_workspace: input.workspace, p_endpoint: input.endpoint })
    if (error?.code === '42501') return integrationFailure(403, 'Verified integration access required.')
    return error ? integrationFailure(503, 'Could not revoke the webhook.') : new Response(null, { status: 204, headers: integrationHeaders })
  }
  const destination = webhookUrl(input.destination)
  if (input.action !== 'create' || !destination || typeof input.label !== 'string' || input.label.length > 48
    || !Array.isArray(input.topics) || input.topics.length < 1 || input.topics.length > 2
    || !input.topics.every((topic: unknown) => topic === 'room.created' || topic === 'membership.changed')) {
    return integrationFailure(400, 'Choose a label, a public HTTPS destination and topics.')
  }
  const id = randomUUID()
  const secret = randomBytes(32)
  let wrapped: string
  try { wrapped = sealWebhookSecret(secret, input.workspace, id) }
  catch { return integrationFailure(503, 'Webhook signing is unavailable.') }
  const { error } = await client.rpc('st_v6_register_webhook', {
    p_workspace: input.workspace, p_endpoint: id, p_label: input.label, p_destination: destination.href,
    p_wrapped: wrapped, p_topics: input.topics,
  })
  if (error?.code === '42501') return integrationFailure(403, 'Verified integration access required.')
  if (error?.code === '22023') return integrationFailure(400, error.message)
  if (error?.code === 'PT429') return integrationFailure(429, 'Try again in a minute.')
  if (error) return integrationFailure(503, 'Could not register the webhook.')
  return Response.json({ id, secret: 'whsec_' + secret.toString('base64') }, { status: 201, headers: integrationHeaders })
}
