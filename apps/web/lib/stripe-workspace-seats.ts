import type Stripe from 'stripe'
import {readBoundedText} from './request-body'
import {billingIdentity,billingWriter,stripe,stripeLiveMode} from './stripe-server'
import {stripeBillingUuid} from './stripe-reconciliation'

type Identity=NonNullable<Awaited<ReturnType<typeof billingIdentity>>>
type Status={linked:boolean;owner:string;base:string;customer:string;currency:string;cadence:string;
  subscription:string|null;quantity:number|null;until:string|null;occupied:number;cap:number;awaiting:number;
  pending:number|null;intent:'manual'|'true_up'|null}
type Snapshot={workspace:string;customer:string;quantity:number;until:number;active:boolean;item:string;price:string}
const headers={'Cache-Control':'private, no-store',Vary:'Authorization'}
const reply=(data:object,status=200)=>Response.json(data,{status,headers})
const fail=(error:string,status:number)=>reply({error},status)
const providerId=(reference:string|{id:string}|null|undefined)=>typeof reference==='string'?reference:reference?.id

function seatPriceId(currency:string,cadence:string) {
  if (!/^(USD|EUR|GBP|INR|CAD|AUD|JPY)$/.test(currency) || (cadence!=='monthly'&&cadence!=='annual')) return null
  const price=process.env['STRIPE_WORKSPACE_SEAT_'+currency+'_'+cadence.toUpperCase()]
  return price&&/^price_[A-Za-z0-9_]{3,96}$/.test(price)?price:null
}
function seatSnapshot(sub:Stripe.Subscription):Snapshot|null {
  const workspace=sub.metadata?.sectalk_workspace_seats
  const customer=providerId(sub.customer)
  const item=sub.items.data[0]
  const quantity=item?.quantity
  if (!workspace || !stripeBillingUuid.test(workspace) || !customer || sub.livemode!==stripeLiveMode ||
    sub.items.data.length!==1 || !quantity || !Number.isSafeInteger(quantity) || quantity<1 || quantity>10000 ||
    !Number.isSafeInteger(item.current_period_end)) return null
  return {workspace,customer,item:item.id,price:item.price.id,quantity,until:item.current_period_end,
    active:sub.status==='active' && !sub.pending_update}
}
export async function renewWorkspaceSeats(subscription:Stripe.Subscription,paidInvoice:string|null=null) {
  if (!subscription.metadata?.sectalk_workspace_seats) return null
  const seat=seatSnapshot(subscription)
  if (!seat || !billingWriter) return false
  const confirmedRenewal=paidInvoice!==null && providerId(subscription.latest_invoice)===paidInvoice
  const terminal=['canceled','unpaid','incomplete_expired'].includes(subscription.status)
  const {error}=await billingWriter.rpc('st_v8_workspace_seat_renew',{p_workspace:seat.workspace,p_customer:seat.customer,
    p_subscription:subscription.id,p_quantity:seat.quantity,p_until:confirmedRenewal||terminal?seat.until:0,p_active:seat.active})
  return !error
}

export async function closeWorkspaceSeatSubscriptions() {
  if (!stripe||!billingWriter) return
  const provider=stripe,store=billingWriter
  const jobs=await store.rpc('st_v8_workspace_seat_closures')
  if (jobs.error) return
  await Promise.allSettled((jobs.data as {workspace:string;customer:string;subscription:string;lease:string}[]).map(async job=>{
    const subscription=await provider.subscriptions.retrieve(job.subscription)
    const seat=seatSnapshot(subscription)
    if (!seat || subscription.id!==job.subscription || seat.workspace!==job.workspace || seat.customer!==job.customer) return
    const closed=subscription.status==='canceled'?subscription:await provider.subscriptions.cancel(subscription.id,
      {invoice_now:false,prorate:false})
    if (closed.id===job.subscription && closed.status==='canceled')
      await store.rpc('st_v8_workspace_seat_closures',{p_subscription:job.subscription,p_lease:job.lease})
  }))
}

export async function workspaceSeatAction(request:Request,identity:Identity) {
  const provider=stripe, store=billingWriter
  if (!provider || !store) return fail('Workspace seat billing is unavailable.',503)
  let input
  try {
    const body=await readBoundedText(request,4096)
    if (body===undefined) return fail('Seat request is too large.',413)
    input=body?JSON.parse(body):null
  } catch {return fail('Invalid seat request.',400)}
  const workspace=input?.workspace
  if (typeof workspace!=='string'||!stripeBillingUuid.test(workspace)||!['status','confirm'].includes(input.stage))
    return fail('Choose a workspace seat action.',400)
  const {error}=await identity.client.rpc('st_v8_workspace_seat_scope',{p_workspace:workspace})
  if (error) return fail('Verify your sign-in as an authorized workspace billing administrator.',403)
  const ledger=async (action:string,data:object|null=null)=>{
    const result=await store.rpc('st_v8_workspace_seat_command',{p_workspace:workspace,p_actor:identity.user.id,p_action:action,p_data:data})
    if (result.error) throw new Error('Seat ledger unavailable')
    return result.data
  }
  try {
    const state:Status|null=await ledger('status')
    if (!state) return fail('Workspace billing access changed.',403)
    if (!state.linked) return reply({configured:false})
    const priceId=seatPriceId(state.currency,state.cadence)
    if (!priceId) return reply({configured:false})
    const price=await provider.prices.retrieve(priceId)
    const expectedInterval=state.cadence==='annual'?'year':'month'
    if (!price.active || price.livemode!==stripeLiveMode || price.id!==priceId || price.type!=='recurring'
      || price.billing_scheme!=='per_unit' || price.currency.toUpperCase()!==state.currency
      || price.recurring?.interval!==expectedInterval || price.recurring.interval_count!==1
      || price.recurring.usage_type!=='licensed' || price.unit_amount===null || price.unit_amount<=0)
      return fail('Stripe returned different terms for the seat offer.',409)
    const trueUp=Math.min(state.cap,state.occupied+state.awaiting)
    if (input.stage==='status') return reply({configured:true,quantity:state.quantity,occupied:state.occupied,cap:state.cap,
      awaiting:state.awaiting,trueUp,amount:price.unit_amount,currency:state.currency,cadence:state.cadence,
      until:state.until,pending:state.pending,intent:state.intent})
    const quantity=input.quantity, intent=input.intent
    if (!Number.isInteger(quantity) || quantity<Math.max(1,state.occupied) || quantity>state.cap ||
      !['manual','true_up'].includes(intent) || (!state.pending&&intent==='true_up'&&(state.awaiting<1||quantity!==trueUp)) ||
      input.amount!==price.unit_amount || input.currency!==state.currency || input.cadence!==state.cadence)
      return fail('Seat terms or invitations changed. Review the current quantities and try again.',409)
    if (!state.pending&&quantity===state.quantity) return fail('The workspace already has that seat quantity.',409)
    const base=await provider.subscriptions.retrieve(state.base)
    if (base.id!==state.base || base.status!=='active' || base.livemode!==stripeLiveMode ||
      base.metadata.sectalk_user!==state.owner || providerId(base.customer)!==state.customer)
      return fail('Could not verify the workspace billing account.',409)
    const existing=state.subscription?await provider.subscriptions.retrieve(state.subscription):null
    const current=existing?seatSnapshot(existing):null
    if (existing && (!current || current.workspace!==workspace || current.customer!==state.customer ||
      current.price!==priceId || !current.active || (!state.pending&&current.quantity!==state.quantity)))
      return fail('The linked seat subscription needs reconciliation before changing quantity.',409)
    const claim=await ledger('claim',{quantity,intent,price:priceId})
    if (!claim) return fail('A seat change is processing or capacity changed. Refresh to review.',409)
    const idempotencyKey='sectalk-workspace-seats-'+claim.id
    const complete=(result:string,extra:object={})=>ledger('finish',{...claim,result,...extra})
    let subscription:Stripe.Subscription
    try {
      if (existing && current) {
        subscription=current.quantity===quantity?existing:await provider.subscriptions.update(existing.id,{
          items:[{id:current.item,quantity}],payment_behavior:'error_if_incomplete',proration_behavior:'always_invoice',
        },{idempotencyKey})
      } else {
        const payment=providerId(base.default_payment_method)
        subscription=await provider.subscriptions.create({customer:state.customer,items:[{price:priceId,quantity}],
          metadata:{sectalk_workspace_seats:workspace},payment_behavior:'error_if_incomplete',
          ...(payment?{default_payment_method:payment}:{})},{idempotencyKey})
      }
    } catch (error) {
      if (typeof error==='object' && error!==null && 'statusCode' in error &&
        (error.statusCode===402 || error.statusCode===400)) {
        await complete('rejected')
        return fail('Stripe declined the seat change. Confirm your payment method and try again.',402)
      }
      throw error
    }
    const seat=seatSnapshot(subscription)
    if (!seat || seat.workspace!==workspace || seat.customer!==state.customer || seat.price!==priceId ||
      !seat.active || seat.quantity!==quantity || seat.until*1000<=Date.now())
      throw new Error('Seat binding changed')
    if (!await complete('settled',{subscription:subscription.id,until:seat.until})) {
      await renewWorkspaceSeats(subscription)
      throw new Error('Seat binding changed')
    }
    return reply({quantity})
  } catch {
    return fail('Stripe could not confirm workspace seat billing. Refresh before trying again.',503)
  }
}
