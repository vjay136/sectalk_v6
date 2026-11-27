import {billingIdentity, billingWriter, stripe} from '../../../../lib/stripe-server'
import {stripeBillingUuid} from '../../../../lib/stripe-reconciliation'
import {workspaceSeatAction} from '../../../../lib/stripe-workspace-seats'
import {invoiceAdjustmentAction} from '../../../../lib/stripe-invoice-adjustments'
import { billingMode, billingPausedResponse } from '../../../../lib/billing-mode'

export const runtime = 'nodejs'
export const maxDuration = 30
const headers = {'Cache-Control': 'private, no-store', Vary: 'Authorization'}
const reply = (status: number, message: string) => Response.json({error: message}, {status, headers})
type Binding = {customer: string; subscription: string; status: string}
type StripeReference = string | {id: string} | null | undefined

function providerId(value: StripeReference) {
  return typeof value === 'string' ? value : value?.id
}

export async function POST(request: Request) {
  if (billingMode() === 'free') return billingPausedResponse()
  const identity = await billingIdentity(request)
  if (!identity) return reply(401, 'Sign in to manage workspace billing.')
  if (new URL(request.url).searchParams.get('section')==='adjustments') return invoiceAdjustmentAction(request,identity)
  return workspaceSeatAction(request,identity)
}

export async function GET(request: Request) {
  const identity = await billingIdentity(request)
  if (!identity) return reply(401, 'Sign in to view workspace billing.')
  const workspace = new URL(request.url).searchParams.get('workspace')
  if (!workspace || !stripeBillingUuid.test(workspace)) return reply(400, 'Select a workspace.')
  const args = {p_workspace: workspace}
  const summary = await identity.client.rpc('st_v7_billing_admin_view', args)
  if (summary.error) return reply(summary.error.code === '42501' ? 403 : 503, 'Workspace billing is unavailable.')
  if (!billingWriter || !stripe) return Response.json({provider: 'unavailable'}, {headers})
  const scope = {...args, p_actor: identity.user.id}
  const binding = await billingWriter.rpc('st_v7_billing_admin_provider_scope', scope)
  if (binding.error) return reply(503, 'The payment provider scope is unavailable.')
  const linked = binding.data as Binding | null
  if (!linked) return Response.json({provider: 'unlinked'}, {headers})
  try {
    const [invoicePage, subscription] = await Promise.all([
      stripe.invoices.list({customer: linked.customer, subscription: linked.subscription, limit: 20}),
      stripe.subscriptions.retrieve(linked.subscription),
    ])
    if (subscription.id !== linked.subscription || providerId(subscription.customer) !== linked.customer) {
      return reply(502, 'The payment provider returned a different billing scope.')
    }
    const [authorized, current] = await Promise.all([
      identity.client.rpc('st_v7_billing_admin_view', args),
      billingWriter.rpc('st_v7_billing_admin_provider_scope', scope),
    ])
    if (authorized.error || current.error || current.data?.customer !== linked.customer
      || current.data?.subscription !== linked.subscription) return reply(403, 'Workspace billing access changed.')

    const invoices = invoicePage.data.filter(invoice => providerId(invoice.customer) === linked.customer
      && providerId(invoice.parent?.subscription_details?.subscription) === linked.subscription)
      .slice(0, 20).map(invoice => ({number: invoice.number, status: invoice.status, currency: invoice.currency,
        total: invoice.total, amount_due: invoice.amount_due, created: invoice.created}))
    return Response.json({provider: 'linked', invoices, more: invoicePage.has_more,
      payment: {status: subscription.status, collection: subscription.collection_method,
        subscription_method_set: Boolean(subscription.default_payment_method || subscription.default_source)}}, {headers})
  } catch { return reply(502, 'Could not load payment status from Stripe.') }
}
