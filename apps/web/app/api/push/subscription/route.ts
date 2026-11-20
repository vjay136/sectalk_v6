import { authenticatePush, pushConfiguration, pushEndpoint, pushHeaders, pushInput, pushSubscription } from '../../../../lib/web-push-server'

export const runtime = 'nodejs'

function failure(status: number, error: string) {
  return Response.json({ error }, { status, headers: pushHeaders })
}

async function handle(request: Request, action: 'status' | 'save' | 'delete') {
  const configuration = pushConfiguration()
  if (!configuration) return failure(503, 'Browser push is unavailable.')
  const identity = await authenticatePush(request, configuration, action === 'delete')
  if (!identity) return failure(401, 'Sign in to manage browser push.')
  const input = action === 'status' ? null : await pushInput(request)
  const subscription = action === 'save' ? pushSubscription(input) : null
  const endpoint = subscription?.endpoint ?? (action === 'delete' ? pushEndpoint(input?.endpoint) : null)
  if ((action === 'save' && !subscription) || (action === 'delete' && !endpoint)) {
    return failure(400, 'Invalid or unsupported browser push subscription.')
  }
  const { data, error } = await configuration.service.rpc('st_v6_push_subscription', {
    ...identity, p_action: action, p_endpoint: endpoint,
    p_p256dh: subscription?.keys.p256dh ?? null, p_auth: subscription?.keys.auth ?? null,
  })
  if (error) return failure(503, 'Browser push could not be updated.')
  if (action !== 'status' && data !== true) return failure(409, 'Browser push subscription could not be updated.')
  return Response.json({ publicKey: configuration.vapid.publicKey, enabled: action !== 'delete' && data === true }, { headers: pushHeaders })
}

export const GET = (request: Request) => handle(request, 'status')
export const POST = (request: Request) => handle(request, 'save')
export const DELETE = (request: Request) => handle(request, 'delete')
