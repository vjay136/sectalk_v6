import type Stripe from 'stripe'
import {isBillingCurrency} from './billing'
import {readBoundedText} from './request-body'
import {billingIdentity,billingWriter,stripe,stripeLiveMode} from './stripe-server'
import {stripeBillingUuid} from './stripe-reconciliation'
import {finalizedInvoice,invoiceId,stripeReference} from './stripe-invoice-documents'

type Identity=NonNullable<Awaited<ReturnType<typeof billingIdentity>>>
type Kind='refund'|'credit'|'adjustment'
type Reason='duplicate'|'order_change'|'product_unsatisfactory'|'fraudulent'
type Terms={invoice:string;kind:Kind;reason:Reason;amount:number;currency:string}
type Binding={customer:string;subscription:string}
const noteId=/^cn_[A-Za-z0-9_]{3,96}$/
const refundId=/^re_[A-Za-z0-9_]{3,96}$/
const headers={'Cache-Control':'private, no-store',Vary:'Authorization'}
const reply=(data:object,status=200)=>Response.json(data,{status,headers})
const fail=(error:string,status:number)=>reply({error},status)

function eligibleInvoice(invoice:Stripe.Invoice,binding:Binding) {
  const document=finalizedInvoice(invoice,binding)
  if (!document || !isBillingCurrency(document.currency) || !['open','paid'].includes(document.status) ||
    ![invoice.amount_remaining,invoice.pre_payment_credit_notes_amount,invoice.post_payment_credit_notes_amount].every(Number.isSafeInteger))
    return null
  const remaining=Math.max(0,Math.min(invoice.amount_remaining,document.total-invoice.pre_payment_credit_notes_amount))
  const paid=Math.max(0,Math.min(document.amount_paid,document.total-invoice.pre_payment_credit_notes_amount)-
    invoice.post_payment_credit_notes_amount)
  return {id:document.id,number:document.number,status:document.status,currency:document.currency,
    limit:document.status==='paid'?paid:remaining}
}
function creditParams(terms:Terms) {
  return {invoice:terms.invoice,amount:terms.amount,reason:terms.reason,
    ...(terms.kind==='refund'?{refund_amount:terms.amount}:terms.kind==='credit'?{credit_amount:terms.amount}:{})}
}
async function providerQuote(terms:Terms,binding:Binding) {
  const invoice=await stripe!.invoices.retrieve(terms.invoice)
  const document=eligibleInvoice(invoice,binding)
  if (!document || document.id!==terms.invoice || document.currency!==terms.currency ||
    terms.amount>document.limit || (terms.kind==='adjustment' ? document.status!=='open' : document.status!=='paid')) return null
  if (terms.kind==='refund') {
    const payments=await stripe!.invoicePayments.list({invoice:invoice.id,limit:2,status:'paid'})
    if (payments.has_more || payments.data.length!==1 || payments.data[0].payment.type!=='payment_intent') return null
  }
  const estimate=await stripe!.creditNotes.preview(creditParams(terms))
  if (estimate.amount!==terms.amount || estimate.currency.toUpperCase()!==terms.currency ||
    stripeReference(estimate.customer)!==binding.customer || stripeReference(estimate.invoice)!==terms.invoice ||
    (terms.kind==='adjustment' ? estimate.pre_payment_amount!==terms.amount||estimate.post_payment_amount!==0 :
      estimate.pre_payment_amount!==0||estimate.post_payment_amount!==terms.amount)) return null
  return document
}

async function synchronize(note:Stripe.CreditNote) {
  const id=note.metadata?.sectalk_invoice_adjustment
  if (!id) return null
  if (!stripe || !billingWriter || !stripeBillingUuid.test(id) || !noteId.test(note.id) || note.livemode!==stripeLiveMode)
    throw new Error('Invalid credit note binding')
  let state:string=note.status
  if (state!=='issued' && state!=='void') throw new Error('Unsupported credit note status')
  const reference=note.refunds?.[0]
  let refund:string|undefined
  if (reference) {
    refund=stripeReference(reference.refund)
    if (note.refunds.length!==1 || !refund || !refundId.test(refund) || reference.amount_refunded!==note.amount)
      throw new Error('Unexpected credit note refund')
    const current=await stripe.refunds.retrieve(refund)
    if (current.id!==refund || current.amount!==note.amount || current.currency!==note.currency)
      throw new Error('Unexpected refund amount')
    if (state==='issued') state=current.status==='succeeded'?'refunded':
      current.status==='failed'||current.status==='canceled'?'refund_failed':'refund_pending'
  }
  const {data,error}=await billingWriter.rpc('st_v8_invoice_adjustment_sync',{p_action:'note',p_data:{id,state,note:note.id,
    refund:refund??null,customer:stripeReference(note.customer),invoice:stripeReference(note.invoice),currency:note.currency.toUpperCase(),
    amount:note.amount,reason:note.reason,pre:note.pre_payment_amount,post:note.post_payment_amount,
    balance:stripeReference(note.customer_balance_transaction)??null}})
  if (error || data!==true) throw new Error('Credit note could not be recorded')
  return state
}

export async function reconcileInvoiceAdjustmentEvent(type:string,resource:unknown) {
  if (!['credit_note.created','credit_note.updated','credit_note.voided','refund.created','refund.updated','refund.failed'].includes(type)) return null
  if (typeof resource!=='string'||!stripe||!billingWriter) return 400
  let note=resource
  try {
    if (type.startsWith('refund.')) {
      if (!refundId.test(resource)) return 400
      const result=await billingWriter.rpc('st_v8_invoice_adjustment_sync',{p_action:'refund_note',p_data:{refund:resource}})
      if(result.error) return 503
      if (!result.data) return 204
      note=result.data
    }
    if (!noteId.test(note)) return 400
    const current=await stripe.creditNotes.retrieve(note)
    if (current.id!==note) return 503
    await synchronize(current)
    return 204
  } catch {return 503}
}

export async function invoiceAdjustmentAction(request:Request,identity:Identity) {
  const provider=stripe,store=billingWriter
  if (!provider||!store) return fail('Invoice adjustments are unavailable.',503)
  let input
  try {
    const text=await readBoundedText(request,4096)
    if (text===undefined) return fail('Invoice request is too large.',413)
    input=text?JSON.parse(text):null
  } catch {return fail('Invalid invoice request.',400)}
  const workspace=input?.workspace,stage=input?.stage
  if (typeof workspace!=='string' || !stripeBillingUuid.test(workspace) || !['status','preview','confirm'].includes(stage))
    return fail('Choose a workspace invoice action.',400)
  if ((await identity.client.rpc('st_v8_invoice_adjustment_scope',{p_workspace:workspace})).error)
    return fail('Verify your sign-in as a delegated billing administrator.',403)
  const ledger=async(action:string,id:string|null=null,data:object|null=null)=>{
    const result=await store.rpc('st_v8_invoice_adjustment_command',{p_workspace:workspace,p_actor:identity.user.id,
      p_action:action,p_id:id,p_data:data})
    if (result.error) throw new Error('Adjustment ledger unavailable')
    return result.data
  }
  try {
    const binding=await ledger('scope')
    if (!binding) return fail('Workspace billing access changed.',403)
    if (stage==='status') {
      if (!binding.subscription) return reply({invoices:[],history:binding.history.map(publicHistory)})
      const invoices=await provider.invoices.list({customer:binding.customer,subscription:binding.subscription,limit:20})
      const current=await ledger('scope')
      if (!current || current.customer!==binding.customer || current.subscription!==binding.subscription)
        return fail('Workspace billing access changed.',403)
      return reply({invoices:invoices.data.map(invoice=>eligibleInvoice(invoice,binding)).filter(invoice=>invoice&&invoice.limit>0),
        history:current.history.map(publicHistory)})
    }
    if (stage==='preview') {
      const {invoice,kind,reason,amount,currency}=input
      if (typeof invoice!=='string'||!invoiceId.test(invoice)||!['refund','credit','adjustment'].includes(kind) ||
        !['duplicate','order_change','product_unsatisfactory','fraudulent'].includes(reason) ||
        !Number.isInteger(amount)||amount<1||amount>100000000||!isBillingCurrency(currency))
        return fail('Choose a supported action, reason and positive amount.',400)
      const terms:Terms={invoice,kind,reason,amount,currency}
      const document=binding.subscription?await providerQuote(terms,binding):null
      if (!document) return fail('The invoice is unavailable or the amount exceeds its remaining balance.',409)
      const quote=await ledger('quote',null,{...terms,subscription:binding.subscription})
      return quote?reply({id:quote.id,number:document.number,kind,reason,amount,currency}):fail('The invoice scope changed.',409)
    }
    const id=input.id
    if (typeof id!=='string'||!stripeBillingUuid.test(id)) return fail('Review the adjustment first.',400)
    const job=await ledger('inspect',id)
    if (!job) return fail('The adjustment preview is unavailable.',409)
    const claim=await ledger('claim',id)
    if (!claim) return fail('The preview expired or an adjustment is processing.',409)
    if (claim.state) return reply({state:claim.state})
    const reject=()=>ledger('reject',id,{lease:claim.lease})
    try {
      if (!claim.retry && !await providerQuote(job,{customer:job.customer,subscription:job.subscription})) {
        await reject()
        return fail('The invoice balance changed. Review a new adjustment.',409)
      }
      const note=await provider.creditNotes.create({...creditParams(job),email_type:'none',
        metadata:{sectalk_invoice_adjustment:id}}, {idempotencyKey:'sectalk-adjustment-'+id})
      return reply({state:await synchronize(note)})
    } catch(error) {
      if (typeof error==='object'&&error!==null&&'statusCode' in error&&(error.statusCode===400||error.statusCode===402)) {
        await reject()
        return fail('Stripe rejected the credit note. Review the invoice balance or payment method.',409)
      }
      throw error
    }
  } catch {
    return fail('The payment provider could not confirm the adjustment. Refresh its audit status before retrying.',503)
  }
}

function publicHistory(row:{id:string;kind:Kind;reason:Reason;amount:number;currency:string;state:string;created_at:string;owned:boolean}) {
  return {id:row.id,kind:row.kind,reason:row.reason,amount:row.amount,currency:row.currency,state:row.state,created_at:row.created_at,owned:row.owned}
}
