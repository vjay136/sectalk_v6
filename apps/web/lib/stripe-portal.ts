import type Stripe from 'stripe'
import {billingWriter,configuredCatalog,legacyOfferForPrice,origin,stripe,stripeLiveMode,type billingIdentity} from './stripe-server'

const purposes = ['overview','payment_method','plan','invoices','tax_ids','cancel','reactivate'] as const
export type PortalPurpose = typeof purposes[number]
type Identity = NonNullable<Awaited<ReturnType<typeof billingIdentity>>>
const headers = {'Cache-Control':'private, no-store', Vary:'Authorization'}
function fail(status:number,error:string) {return Response.json({error},{status,headers})}
function reference(value:string|{id:string}|null|undefined) {return typeof value==='string'?value:value?.id}

export function billingPortalConfigured() {
  return Boolean(stripe && /^bpc_[A-Za-z0-9_]{1,100}$/.test(process.env.SECTALK_STRIPE_PORTAL_CONFIGURATION ?? ''))
}

async function configuredPortal(configuration: Stripe.BillingPortal.Configuration, id: string) {
  if (!billingWriter || configuration.id!==id || !configuration.active || configuration.livemode!==stripeLiveMode
    || configuration.application!=null || configuration.login_page?.enabled) return false
  const {customer_update,invoice_history,payment_method_update,subscription_cancel,subscription_update}=configuration.features
  const taxFields=customer_update?.allowed_updates
  const updates=subscription_update?.default_allowed_updates
  const products=subscription_update?.products
  if (!invoice_history?.enabled || !payment_method_update?.enabled || !customer_update?.enabled
    || !taxFields?.includes('tax_id') || taxFields.some(value=>!['tax_id','name','address'].includes(value))
    || !subscription_cancel?.enabled || subscription_cancel.mode!=='at_period_end'
    || !subscription_update?.enabled || updates?.length!==1 || updates[0]!=='price'
    || !Array.isArray(products) || !products.length || products.length>10) return false
  if (products.some(product=>!/^prod_[A-Za-z0-9_]{1,100}$/.test(product.product)
    || !Array.isArray(product.prices) || !product.prices.length)) return false
  const choices=[...new Set(products.flatMap(product=>product.prices))]
  if (!choices.length || choices.length>100 || choices.some(price=>!/^price_[A-Za-z0-9_]{1,100}$/.test(price))) return false
  const prices=await billingWriter.rpc('st_v7_billing_portal_prices',{p_prices:choices})
  if (prices.error) throw new Error('Portal price catalog unavailable')
  const allowed=new Set(prices.data as string[])
  const unmapped=choices.filter(price=>!allowed.has(price))
  if (!unmapped.length) return true
  const catalog=await configuredCatalog()
  return unmapped.every(id=>{
    const fallback=legacyOfferForPrice(id)
    return fallback && catalog.some(version=>version.plan===fallback.plan && version.version===1
      && version.prices.some(price=>price.cadence===fallback.cadence && price.currency==='USD' && price.amount===null))
  })
}

export async function launchBillingPortal(identity: Identity,value: unknown) {
  if (!stripe || !billingWriter || !origin) return fail(503,'Payment checkout is unavailable on this deployment.')
  if (value!==undefined && (typeof value!=='string' || !purposes.includes(value as PortalPurpose))) {
    return fail(400,'Choose an available billing option.')
  }
  const purpose=(value ?? 'overview') as PortalPurpose
  const scoped=await identity.client.rpc('st_v7_billing_portal_scope',{p_purpose:purpose})
  if (scoped.error) return fail(scoped.error.code==='42501'?403:scoped.error.code==='P0001'?429:503,'Billing portal access is unavailable.')
  if (!scoped.data) return fail(404,'No billing account is linked yet.')
  const {customer,subscription}=scoped.data as {customer:string;subscription:string}
  const id=process.env.SECTALK_STRIPE_PORTAL_CONFIGURATION ?? ''
  if (!/^bpc_[A-Za-z0-9_]{1,100}$/.test(id)) return fail(503,'The billing portal is awaiting provider configuration.')

  try {
    const config=await stripe.billingPortal.configurations.retrieve(id)
    if (!await configuredPortal(config,id)) return fail(503,'The billing portal configuration is unavailable.')
    let flow:Stripe.BillingPortal.SessionCreateParams.FlowData|undefined
    if (purpose==='payment_method') flow={type:'payment_method_update'}
    if (purpose==='tax_ids') flow={type:'customer_update'}
    if (purpose==='plan' || purpose==='cancel' || purpose==='reactivate') {
      const current=await stripe.subscriptions.retrieve(subscription)
      if (current.id!==subscription || reference(current.customer)!==customer
        || current.livemode!==stripeLiveMode || current.metadata?.sectalk_user!==identity.user.id) {
        return fail(403,'Current subscription ownership could not be verified.')
      }
      const canManage=['active','trialing','past_due'].includes(current.status)
      const periodEnd=current.items?.data?.[0]?.current_period_end ?? 0
      const scheduled=current.cancel_at_period_end || (typeof current.cancel_at==='number' && current.cancel_at> Date.now()/1000)
      if (!canManage || (purpose==='cancel' && scheduled)
        || (purpose==='reactivate' && (!scheduled || periodEnd<=Date.now()/1000))) {
        return fail(409,'This subscription change is no longer available.')
      }
      if (purpose==='plan') flow={type:'subscription_update',subscription_update:{subscription}}
      if (purpose==='cancel') flow={type:'subscription_cancel',subscription_cancel:{subscription}}
    }
    const returnUrl=new URL('/?billing=portal-return',origin).href
    const session=await stripe.billingPortal.sessions.create({
      configuration:id,customer,return_url:returnUrl,...(flow?{flow_data:{...flow,after_completion:{type:'redirect',redirect:{return_url:returnUrl}}}}:{}),
    })
    const actualFlow=session.flow
    const matchingFlow=flow ? actualFlow?.type===flow.type
      && (flow.type!=='subscription_update' || actualFlow.subscription_update?.subscription===subscription)
      && (flow.type!=='subscription_cancel' || actualFlow.subscription_cancel?.subscription===subscription) : actualFlow==null
    const url=URL.parse(session.url)
    if (!matchingFlow || session.customer!==customer || session.customer_account!=null || session.on_behalf_of!=null || reference(session.configuration)!==id || session.livemode!==stripeLiveMode
      || session.return_url!==returnUrl || !url || url.origin!=='https://billing.stripe.com'
      || url.username || url.password || !/^\/p\/session\/[A-Za-z0-9_-]+$/.test(url.pathname)) {
      return fail(502,'The payment provider returned an invalid portal session.')
    }
    const proof=await identity.client.rpc('st_v7_sensitive_action_status',{p_kind:'billing'})
    if (proof.error || proof.data!=='verified') return fail(403,'Verify your current sign-in to continue to billing.')
    const audited=await billingWriter.rpc('st_v7_billing_portal_record',{
      p_actor:identity.user.id,p_customer:customer,p_subscription:subscription,p_purpose:purpose,
    })
    if (audited.error || audited.data!==true) return fail(503,'The billing portal session could not be authorized.')
    return Response.json({url:url.href},{headers})
  } catch {return fail(502,'The payment provider could not open the billing portal.')}
}
