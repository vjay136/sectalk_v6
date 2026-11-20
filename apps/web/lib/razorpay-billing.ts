import {createHash,createHmac,timingSafeEqual} from 'node:crypto'
import {billingWriter,configuredCatalog,origin} from './stripe-server'
import {isPaidPlan,type Cadence,type PaidPlan} from './billing'
import {readBoundedBody} from './request-body'

const key=process.env.RAZORPAY_KEY_ID
const apiSecret=process.env.RAZORPAY_KEY_SECRET
const webhookSecret=process.env.RAZORPAY_WEBHOOK_SECRET
const hosted=/^https:\/\/rzp\.io\/rzp\/[A-Za-z0-9]{3,80}$/
const subId=/^sub_[A-Za-z0-9]{3,50}$/
const paymentId=/^pay_[A-Za-z0-9]{3,50}$/
const eventId=/^[A-Za-z0-9_-]{8,120}$/
const headers={'Cache-Control':'private, no-store'}
const reply=(status:number,data?:object)=>data?Response.json(data,{status,headers}):new Response(null,{status,headers})
type Catalog=Awaited<ReturnType<typeof configuredCatalog>>
type Subscription={id:string;entity:string;plan_id:string;quantity:number;status:string;short_url?:string;
  current_start?:number;current_end?:number;paid_count?:number;notes?:Record<string,string>}
type Charge={id:string;entity:string;status:string;captured:boolean;currency:string;amount:number;amount_refunded:number}
type Scope={id:string;provider_plan:string;amount:number;state:string;cadence:Cadence}

function razorpayOrigin() {
  const qa=URL.parse(process.env.SECTALK_TEST_RAZORPAY_ORIGIN??'')
  if (qa?.origin===process.env.SECTALK_TEST_RAZORPAY_ORIGIN&&qa?.protocol==='http:'&&qa.hostname==='127.0.0.1'
    && qa.port && key?.startsWith('rzp_test_') && URL.parse(origin??'')?.hostname==='127.0.0.1') return qa.origin
  return 'https://api.razorpay.com'
}
function enabled() {
  return Boolean(key&&/^rzp_(test|live)_[A-Za-z0-9]{3,60}$/.test(key)&&apiSecret&&webhookSecret&&billingWriter)
}
function providerPlan(plan:PaidPlan,cadence:Cadence) {
  const value=process.env['RAZORPAY_PLAN_'+plan.toUpperCase()+'_'+cadence.toUpperCase()]
  return value&&/^plan_[A-Za-z0-9]{3,50}$/.test(value)?value:null
}
export function razorpayOffers(catalog:Catalog) {
  if (!enabled()) return []
  return catalog.flatMap(offer=>isPaidPlan(offer.plan)?offer.prices.filter(p=>p.currency==='INR'&&p.amount!==null)
    .filter(p=>providerPlan(offer.plan as PaidPlan,p.cadence)).map(p=>({plan:offer.plan,version:offer.version,cadence:p.cadence})):[])
}
async function fetchProvider<T>(path:string,input?:object):Promise<T> {
  const response=await fetch(razorpayOrigin()+'/v1'+path,{
    method:input?'POST':'GET',redirect:'error',cache:'no-store',
    headers:{Authorization:'Basic '+Buffer.from(key+':'+apiSecret).toString('base64'),'Content-Type':'application/json'},
    body:input?JSON.stringify(input):undefined,signal:AbortSignal.timeout(8000),
  })
  if (!response.ok) throw new Error('Razorpay request failed')
  const body=await readBoundedBody(response,131072)
  if (!body?.length) throw new Error('Invalid Razorpay response')
  return JSON.parse(body.toString('utf8')) as T
}

export async function razorpayCheckout(account:string,input:Record<string,unknown>) {
  if (!enabled()) return reply(503,{error:'Razorpay checkout is unavailable.'})
  const ledger=async(action:string,data:object|null=null)=>{
    const result=await billingWriter!.rpc('st_v8_razorpay_checkout',{p_actor:account,p_action:action,p_data:data})
    if (result.error) throw new Error('Checkout unavailable')
    return result.data
  }
  try {
    if (input.action==='razorpay_status') {
      const result=await ledger('status')
      return result?reply(200,result):reply(403,{error:'Checkout access is unavailable.'})
    }
    const {plan,cadence,version,currency}=input
    if (!isPaidPlan(plan) || (cadence!=='monthly'&&cadence!=='annual') || typeof version!=='number' ||
      !Number.isInteger(version) || version<1 || version>2147483647 || currency!=='INR' || input.coupon)
      return reply(400,{error:'Choose an eligible INR plan. Razorpay checkout does not accept Stripe coupons.'})
    const provider_plan=providerPlan(plan,cadence)
    const catalog=await configuredCatalog()
    const amount=catalog.find(row=>row.plan===plan&&row.version===version)?.prices
      .find(row=>row.cadence===cadence&&row.currency==='INR')?.amount
    if (!provider_plan || !amount) return reply(422,{error:'This Razorpay offer has changed or is unavailable.'})
    const published=await fetchProvider<{id:string;entity:string;period:string;interval:number;item:{amount:number;currency:string}}>('/plans/'+provider_plan)
    if (published.id!==provider_plan || published.entity!=='plan' || published.interval!==1 ||
      published.period!==(cadence==='annual'?'yearly':'monthly') || published.item?.amount!==amount || published.item.currency!=='INR')
      return reply(422,{error:'Razorpay returned different terms for this plan.'})
    const terms={plan,cadence,version,amount,provider_plan}
    let checkout=await ledger('reserve',terms)
    if (checkout?.probe && subId.test(checkout.probe)) {
      const prior=await fetchProvider<Subscription>('/subscriptions/'+checkout.probe)
      if (prior.id!==checkout.probe || prior.plan_id!==checkout.provider_plan || prior.notes?.sectalk_checkout!==checkout.id ||
        !['expired','cancelled','completed'].includes(prior.status) || prior.paid_count!==0)
        return reply(409,{error:'Razorpay still has an open or pending checkout.'})
      await ledger('expire',{id:checkout.id,subscription:prior.id})
      checkout=await ledger('reserve',terms)
    }
    if (checkout?.url && hosted.test(checkout.url)) return reply(200,{url:checkout.url})
    if (!checkout?.id) return reply(409,{error:'An existing subscription or checkout blocks a new Razorpay checkout.'})
    const subscription=await fetchProvider<Subscription>('/subscriptions',{
      plan_id:provider_plan,quantity:1,total_count:cadence==='annual'?5:24,expire_by:checkout.deadline,
      customer_notify:0,notes:{sectalk_checkout:checkout.id},
    })
    if (!subId.test(subscription.id) || subscription.entity!=='subscription' || subscription.plan_id!==provider_plan ||
      subscription.quantity!==1 || subscription.status!=='created' || subscription.notes?.sectalk_checkout!==checkout.id ||
      !subscription.short_url || !hosted.test(subscription.short_url) ||
      !await ledger('attach',{id:checkout.id,subscription:subscription.id,url:subscription.short_url}))
      return reply(502,{error:'Razorpay did not return a valid hosted checkout.'})
    return reply(200,{url:subscription.short_url})
  } catch {return reply(503,{error:'Razorpay could not open checkout. Try again when the pending link expires.'})}
}

function validSignature(body:Buffer,provided:string) {
  if (!webhookSecret || !/^[0-9a-fA-F]{64}$/.test(provided)) return false
  const expected=createHmac('sha256',webhookSecret).update(body).digest()
  return timingSafeEqual(expected,Buffer.from(provided,'hex'))
}
export async function razorpayWebhook(request:Request,signature:string) {
  if (!enabled()) return reply(503)
  const event=request.headers.get('X-Razorpay-Event-Id')
  if (!event || !eventId.test(event)) return reply(400)
  try {
    const body=await readBoundedBody(request,262144)
    if (body===undefined) return reply(413)
    if (!body?.length || !validSignature(body,signature)) return reply(400)
    let data
    try {data=JSON.parse(body.toString('utf8'))} catch {return reply(400)}
    const kind=data?.event
    if (!['subscription.charged','subscription.cancelled','subscription.completed','subscription.expired'].includes(kind)) return reply(204)
    const brief:Subscription|undefined=data?.payload?.subscription?.entity
    const observed=data?.created_at
    if (!brief || !subId.test(brief.id) || !Number.isSafeInteger(observed) || observed<=0 || observed>Date.now()/1000+300)
      return reply(400)
    const sync=async(action:string,values:object)=>{
      const result=await billingWriter!.rpc('st_v8_razorpay_sync',{p_action:action,p_data:{subscription:brief.id,...values}})
      if (result.error) throw new Error('Razorpay reconciliation failed')
      return result.data
    }
    const scope:Scope|null=await sync('scope',{})
    if (!scope) return reply(204)
    const current=await fetchProvider<Subscription>('/subscriptions/'+brief.id)
    if (current.id!==brief.id || current.entity!=='subscription' || current.plan_id!==scope.provider_plan ||
      current.quantity!==1 || current.notes?.sectalk_checkout!==scope.id) return reply(422)
    const envelope={event,observed,hash:createHash('sha256').update(body).digest('hex')}
    if (kind!=='subscription.charged') {
      if (!['cancelled','completed','expired'].includes(current.status)) return reply(204)
      if (!Number.isSafeInteger(current.paid_count)) return reply(422)
      return reply(await sync('event',{...envelope,kind:'closed',count:current.paid_count})===true?204:409)
    }
    const eventPayment=data?.payload?.payment?.entity?.id
    if (typeof eventPayment!=='string'||!paymentId.test(eventPayment)) return reply(400)
    const paid=await fetchProvider<Charge>('/payments/'+eventPayment)
    if (paid.id!==eventPayment || paid.entity!=='payment' || paid.status!=='captured'||paid.captured!==true ||
      paid.currency!=='INR' || paid.amount!==scope.amount || paid.amount_refunded!==0) return reply(422)
    if (!['active','completed'].includes(current.status) || !Number.isSafeInteger(current.paid_count) ||
      !Number.isSafeInteger(current.current_start)||!Number.isSafeInteger(current.current_end) ||
      brief.current_start!==current.current_start || brief.current_end!==current.current_end ||
      brief.paid_count!==current.paid_count || brief.plan_id!==current.plan_id)
      return reply(204)
    const cycle=current.current_end!-current.current_start!
    const maxDays=scope.cadence==='annual'?367:32
    if (cycle<=0 || cycle>maxDays*86400 || current.current_end!>Date.now()/1000+maxDays*86400) return reply(422)
    return reply(await sync('event',{...envelope,kind:'paid',payment:paid.id,count:current.paid_count,end:current.current_end})===true?204:409)
  } catch {return reply(503)}
}
