import {billingIdentity,billingWriter,stripe,stripeLiveMode} from '../../../../lib/stripe-server'
import {stripeBillingUuid} from '../../../../lib/stripe-reconciliation'
import {finalizedInvoice, invoiceId, invoicePdf, issueInvoiceTicket, readInvoiceTicket,
  type InvoiceBinding, type InvoiceDocument} from '../../../../lib/stripe-invoice-documents'

export const runtime = 'nodejs'
export const maxDuration = 30
const headers = {'Cache-Control':'private, no-store', Vary:'Authorization', 'X-Content-Type-Options':'nosniff'}
const fail = (status:number) => new Response(null,{status,headers})

export async function GET(request: Request) {
  const actor = await billingIdentity(request)
  if (!actor) return fail(401)
  const secret = process.env.SECTALK_STRIPE_DOCUMENT_SECRET
  if (!stripe || !billingWriter || !secret || Buffer.byteLength(secret)<32) return fail(503)
  const provider = stripe
  const db = billingWriter
  const params = new URL(request.url).searchParams
  const scope = params.get('workspace')
  if (scope !== null && !stripeBillingUuid.test(scope)) return fail(400)

  async function binding(): Promise<InvoiceBinding | null> {
    if ((await actor!.client.rpc('st_v7_current_session_valid')).data !== true) throw new Error('Session inactive')
    if (scope !== null) {
      const authz = await actor!.client.rpc('st_v7_billing_admin_view', {p_workspace:scope})
      if (authz.error) throw new Error('Delegation unavailable')
      const result = await db.rpc('st_v7_billing_admin_provider_scope',{p_workspace:scope,p_actor:actor!.user.id})
      if (result.error) throw new Error('Provider binding unavailable')
      return result.data
    }
    const result = await actor!.client.from('st_v2_subscriptions').select('customer_id,subscription_id')
      .eq('user_id',actor!.user.id).maybeSingle()
    if (result.error) throw new Error('Provider binding unavailable')
    return result.data?.customer_id && result.data?.subscription_id
      ? {customer:result.data.customer_id,subscription:result.data.subscription_id} : null
  }
  let linked: InvoiceBinding | null
  try { linked = await binding() } catch { return fail(403) }
  const ticket = params.get('ticket')
  const cursor = params.get('cursor')
  if (!linked) return ticket || cursor ? fail(404) : Response.json({invoices:[],next:null},{headers})
  const fixed = linked
  const scopeKey = scope ?? 'account'
  const labels=new Map<string,Promise<string|undefined>>()
  async function taxLabels(invoice:InvoiceDocument) {
    for (const tax of invoice.taxes??[]) {
      const rate=tax.rate
      if (!rate || !/^txr_[A-Za-z0-9_]{3,96}$/.test(rate)) continue
      if (!labels.has(rate) && labels.size<12) labels.set(rate,provider.taxRates.retrieve(rate).then(result=>{
        return result.id===rate&&result.livemode===stripeLiveMode&&/^[A-Za-z][A-Za-z0-9 -]{1,30}$/.test(result.display_name)
          ?result.display_name:undefined
      }).catch(()=>undefined))
    }
    await Promise.all((invoice.taxes??[]).map(async tax=>{
      if (tax.rate) tax.label=await labels.get(tax.rate)
      delete tax.rate
    }))
  }
  function refreshed(current: InvoiceBinding | null) {
    return current?.customer === fixed.customer && current.subscription === fixed.subscription
  }
  async function pin(invoice: InvoiceDocument) {
    const result = await db.rpc('st_v7_pin_stripe_invoice',{p_live:stripeLiveMode,p_invoice:invoice.id,
      p_number:invoice.number,p_customer:fixed.customer,p_subscription:fixed.subscription,p_issued_at:invoice.issued_at})
    if (result.error) throw new Error('Invoice number verification failed')
    return result.data === true
  }
  try {
    if (ticket !== null) {
      const grant = readInvoiceTicket(ticket,actor.user.id,scopeKey,fixed,secret)
      if (cursor || !grant || grant.kind === 'page') return fail(404)
      const returned = await provider.invoices.retrieve(grant.id)
      if (returned.id !== grant.id) return fail(404)
      const invoice = finalizedInvoice(returned,fixed,scope===null)
      if (!invoice || (grant.kind === 'receipt' && !invoice.paid_at) || !await pin(invoice)) return fail(404)
      await taxLabels(invoice)
      const pdf = await invoicePdf(invoice,grant.kind === 'receipt')
      if (!refreshed(await binding().catch(()=>null))) return fail(403)
      if (request.headers.get('Accept') === 'application/octet-stream') {
        return new Response(Buffer.from(pdf),{headers:{...headers,'Content-Type':'application/octet-stream'}})
      }
      return new Response(Buffer.from(pdf),{headers:{...headers,'Content-Type':'application/pdf',
        'Content-Disposition':'attachment; filename="sectalk-'+grant.kind+'-'+invoice.number+'.pdf"'}})
    }

    const page = cursor ? readInvoiceTicket(cursor,actor.user.id,scopeKey,fixed,secret) : null
    if (cursor !== null && page?.kind !== 'page') return fail(404)
    const result = await provider.invoices.list({customer:fixed.customer,subscription:fixed.subscription,limit:20,
      ...(page ? {starting_after:page.id} : {})})
    const pageInvoices = result.data.slice(0,20)
    const candidates = pageInvoices.map(invoice=>finalizedInvoice(invoice,fixed,scope===null)).filter(invoice=>invoice!==null)
    const accepted = await Promise.all(candidates.map(async invoice => {
      if (!await pin(invoice)) return null
      await taxLabels(invoice)
      return invoice
    }))
    if (!refreshed(await binding().catch(()=>null))) return fail(403)
    const invoices = accepted.filter(invoice=>invoice!==null).map(({id,...fields})=>({...fields,
      invoice_ticket:issueInvoiceTicket(id,'invoice',actor.user.id,scopeKey,fixed,secret),
      receipt_ticket:fields.paid_at ? issueInvoiceTicket(id,'receipt',actor.user.id,scopeKey,fixed,secret) : null}))
    const last = pageInvoices.at(-1)?.id
    return Response.json({invoices,next:result.has_more && last && invoiceId.test(last)
      ? issueInvoiceTicket(last,'page',actor.user.id,scopeKey,fixed,secret) : null},{headers})
  } catch (error) {
    if (ticket && typeof error==='object' && error!==null && 'statusCode' in error && error.statusCode===404) return fail(404)
    return fail(502)
  }
}
