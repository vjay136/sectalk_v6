import type Stripe from 'stripe'
import {isBillingCurrency,isPaidPlan,paidPlans,type BillingCurrency,type Cadence,type PaidPlan} from './billing'
import {billingIdentity,billingWriter,catalogPriceId,legacyOfferForPrice,stripe,stripeLiveMode} from './stripe-server'
import {stripeBillingUuid,stripeSubscriptionSnapshot} from './stripe-reconciliation'

type Terms = {plan:PaidPlan; version:number; amount:number; currency:BillingCurrency; cadence:Cadence}
type Command = {
  kind:'upgrade'|'schedule'|'abort'; current:Terms; requested:Terms|null
  price:string; target:string|null; item:string; start:number; end:number; schedule:string|null
  quotedAt:number; due:number|null; paymentMethod:string|null; scheduleRevision:string|null
}
type Scheduled = {id:string; requested:Terms; effective:number; revision:string}
type Result = {state:'upgrade'|'payment_pending'|'scheduled'|'aborted'|'stale'; schedule?:Scheduled}
type Identity = NonNullable<Awaited<ReturnType<typeof billingIdentity>>>
const fail=(error:string,status:number)=>Response.json({error},{status})

function interval(cadence:Cadence) {return cadence==='annual'?'year':'month'}

export async function changeBillingPlan(identity:Identity,payload:Record<string,unknown>) {
  if (!stripe || !billingWriter) return fail('Plan changes are unavailable.',503)
  const provider=stripe
  const stage=payload.stage
  if (stage!=='status' && stage!=='preview' && stage!=='confirm') return fail('Choose a plan change.',400)
  if (stage==='confirm' && (typeof payload.id!=='string' || !stripeBillingUuid.test(payload.id))) return fail('Preview the plan change first.',400)
  const {data:binding,error}=await identity.client.rpc('st_v7_billing_portal_scope',{p_purpose:'plan'})
  if (error || !binding) return fail('Verify your sign-in and select an active subscription.',403)
  const {data:local}=await identity.client.from('st_v2_subscriptions')
    .select('plan,catalog_version,billing_currency,billing_cadence,billing_amount,status').eq('user_id',identity.user.id).maybeSingle()
  const ledger=async(action:string,id:string|null=null,data:object|null=null)=>{
    const result=await billingWriter!.rpc('st_v7_plan_change_command',{p_actor:identity.user.id,p_customer:binding.customer,
      p_subscription:binding.subscription,p_action:action,p_id:id,p_data:data})
    if (result.error) throw new Error('Plan changes are unavailable.')
    return result.data
  }
  try {
    const subscription=await provider.subscriptions.retrieve(binding.subscription)
    const snapshot=stripeSubscriptionSnapshot(subscription)
    if (!snapshot || snapshot.user!==identity.user.id || snapshot.customer!==binding.customer || subscription.livemode!==stripeLiveMode)
      return fail('Could not verify this subscription.',403)
    const item=subscription.items.data[0]
    const scheduleId=typeof subscription.schedule==='string'?subscription.schedule:subscription.schedule?.id??null
    const state=await ledger('status')
    const schedule:Scheduled|null=state?.schedule?.id===scheduleId && scheduleId &&
      state.schedule.effective>Math.floor(Date.now()/1000)?state.schedule:null
    const scheduleView=schedule?{requested:schedule.requested,effective:schedule.effective}:null
    if (stage==='status') return Response.json({schedule:scheduleView,awaitingPayment:Boolean(subscription.pending_update),
      pending:state?.pending?{id:state.pending,command:publicCommand(state.command)}:null})

    if (stage==='confirm') {
      const id=payload.id as string
      const claim=await ledger('claim',id)
      if (!claim) return fail('This preview expired or another plan change is processing.',409)
      if (claim.result) return response(claim.result)
      const command:Command=claim.command
      const stable=item.id===command.item && item.price.id===command.price && item.current_period_end===command.end &&
        paymentMethod(subscription)===command.paymentMethod
      const knownSchedule=scheduleId===command.schedule
      const targetAvailable=!command.requested || (await catalogPriceId(command.requested.plan,command.requested.cadence,
        command.requested.currency,command.requested.version))?.id===command.target
      const sameSchedule=!command.schedule || !knownSchedule ||
        await scheduleMatches(command.schedule,command.scheduleRevision,command.end,claim.retry?id:null)
      let result:Result
      if (claim.retry && command.kind==='upgrade' && item.id===command.item && item.price.id===command.target) {
        result={state:'upgrade'}
      } else if (claim.retry && command.kind==='upgrade' && subscription.pending_update?.subscription_items
        ?.some(pending=>pending.id===command.item && (typeof pending.price==='string'?pending.price:pending.price.id)===command.target)) {
        result={state:'payment_pending'}
      } else if (claim.retry && command.kind==='abort' && !scheduleId &&
        (await provider.subscriptionSchedules.retrieve(command.schedule!)).status==='released') {
        result={state:'aborted'}
      } else if (!stable || !sameSchedule || (!knownSchedule && !(claim.retry&&command.kind==='schedule'&&!command.schedule)) ||
        !eligible(subscription,item,command.current.cadence) || !targetAvailable) {
        result={state:'stale',...(command.schedule&&schedule?{schedule}:{})}
      } else if (command.kind==='upgrade') {
        const updated=await provider.subscriptions.update(subscription.id,{
          items:[{id:command.item,price:command.target!}],payment_behavior:'pending_if_incomplete',
          proration_behavior:'always_invoice',proration_date:command.quotedAt,
        },{idempotencyKey:'sectalk-plan-upgrade-'+id})
        if (updated.id!==subscription.id || updated.items.data[0]?.id!==command.item)
          throw new Error('Unexpected provider update')
        result={state:updated.pending_update?'payment_pending':'upgrade'}
      } else if (command.kind==='abort') {
        await provider.subscriptionSchedules.release(command.schedule!,{}, {idempotencyKey:'sectalk-plan-release-'+id})
        result={state:'aborted'}
      } else {
        const created=command.schedule?null:await provider.subscriptionSchedules.create({from_subscription:subscription.id},
          {idempotencyKey:'sectalk-plan-create-'+id})
        const schedule=command.schedule??created!.id
        const requested=command.requested!
        const start=created?created.current_phase?.start_date:command.start
        const createdSubscription=typeof created?.subscription==='string'?created.subscription:created?.subscription?.id
        if (!start || start>=command.end || (created && (createdSubscription!==subscription.id ||
          (scheduleId!==null&&scheduleId!==created.id)))) throw new Error('Invalid provider phase')
        const payment=command.paymentMethod?{default_payment_method:command.paymentMethod}:{}
        await provider.subscriptionSchedules.update(schedule,{
          end_behavior:'release',proration_behavior:'none',metadata:{sectalk_plan_change:id},
          phases:[
            {...payment,start_date:start,end_date:command.end,items:[{price:command.price,quantity:1}],proration_behavior:'none'},
            {start_date:command.end,duration:{interval:interval(requested.cadence),interval_count:1},
              ...payment,items:[{price:command.target!,quantity:1}],proration_behavior:'none'},
          ],
        },{idempotencyKey:'sectalk-plan-schedule-'+id})
        result={state:'scheduled',schedule:{id:schedule,requested,effective:command.end,revision:id}}
      }
      if (!await ledger('finish',id,{lease:claim.lease,result})) throw new Error('Could not record the provider response')
      return response(result)
    }

    if (!local || !isPaidPlan(local.plan) || !isBillingCurrency(snapshot.currency) ||
      (local.billing_cadence!=='monthly' && local.billing_cadence!=='annual') ||
      !eligible(subscription,item,local.billing_cadence) || (scheduleId && !schedule))
      return fail('This subscription requires plan changes in the Stripe billing portal.',409)
    const current:Terms={plan:local.plan,version:local.catalog_version,amount:snapshot.amount,currency:snapshot.currency,cadence:local.billing_cadence}
    const legacy=legacyOfferForPrice(item.price.id)
    const legacyMatch=current.version===1 && current.currency==='USD' && legacy?.plan===current.plan && legacy.cadence===current.cadence
    if (local.status!=='active' || local.billing_currency!==snapshot.currency || local.billing_amount!==snapshot.amount ||
      (!legacyMatch && !await ledger('current_price',null,{price:item.price.id})))
      return fail('The current plan has changed. Wait for Stripe to confirm its terms.',409)
    const command:Command={kind:'abort',current,requested:null,price:item.price.id,target:null,item:item.id,
      start:item.current_period_start,end:item.current_period_end,schedule:scheduleId,quotedAt:Math.floor(Date.now()/1000),due:null,
      paymentMethod:paymentMethod(subscription),scheduleRevision:schedule?.revision??null}
    if (payload.intent==='abort') {
      if (!schedule) return fail('There is no scheduled downgrade to cancel.',409)
    } else {
      const {plan,version}=payload
      if (!isPaidPlan(plan) || plan===current.plan || typeof version!=='number' || !Number.isInteger(version) || version<1 || version>2147483647)
        return fail('Choose another published plan.',400)
      command.kind=paidPlans.indexOf(plan)>paidPlans.indexOf(current.plan)?'upgrade':'schedule'
      if (command.kind==='upgrade' && schedule) return fail('Cancel the scheduled downgrade before upgrading.',409)
      const target=await catalogPriceId(plan,current.cadence,current.currency,version)
      if (!target) return fail('A matching offer is unavailable. Refresh the catalog.',422)
      const price=await provider.prices.retrieve(target.id)
      if (!price.active || price.livemode!==stripeLiveMode || price.type!=='recurring' || price.billing_scheme!=='per_unit'
        || price.currency.toUpperCase()!==current.currency || price.recurring?.interval!==interval(current.cadence)
        || price.recurring.interval_count!==1 || price.recurring.usage_type!=='licensed' || price.unit_amount===null ||
        (target.amount!==null && price.unit_amount!==target.amount))
        return fail('Stripe returned different terms for this plan.',422)
      command.requested={...current,plan,version,amount:price.unit_amount}
      command.target=price.id
      if (command.kind==='upgrade') {
        const estimate=await provider.invoices.createPreview({subscription:subscription.id,subscription_details:{
          items:[{id:item.id,price:price.id}],proration_date:command.quotedAt,proration_behavior:'always_invoice',
        }})
        const lines=estimate.lines?.data.filter(line=>line.parent?.subscription_item_details?.proration)??[]
        if (estimate.currency.toUpperCase()===current.currency && estimate.lines?.has_more===false &&
          lines.length>0 && lines.every(line=>line.currency.toUpperCase()===current.currency&&Number.isSafeInteger(line.amount)))
          command.due=lines.reduce((total,line)=>total+line.amount,0)
      }
    }
    if (schedule) {
      const providerSchedule=await provider.subscriptionSchedules.retrieve(schedule.id)
      if (providerSchedule.status!=='active' || providerSchedule.current_phase?.end_date!==command.end ||
        providerSchedule.metadata?.sectalk_plan_change!==schedule.revision)
        return fail('The scheduled downgrade changed in Stripe. Refresh your subscription.',409)
      command.start=providerSchedule.current_phase.start_date
    }
    const quote=await ledger('quote',null,command)
    return quote?Response.json({id:quote.id,command:publicCommand(command)}):fail('A plan change is processing.',409)
  } catch {
    return fail('The payment provider could not complete the request. Reopen plan changes to check its status.',503)
  }
}

function publicCommand({kind,current,requested,end,due,schedule}:Command) {
  return {kind,current,requested,effective:end,due,replaces:Boolean(schedule)}
}
function response(result:Result) {
  if (result.state==='stale') return fail('Subscription terms changed. Refresh and preview again.',409)
  return Response.json({state:result.state,schedule:result.schedule?{
    requested:result.schedule.requested,effective:result.schedule.effective,
  }:null})
}
function eligible(sub:Stripe.Subscription,item:Stripe.SubscriptionItem,cadence:Cadence) {
  return sub.status==='active' && !sub.pending_update && sub.collection_method==='charge_automatically' &&
    !sub.cancel_at && !sub.cancel_at_period_end && !sub.pause_collection && !sub.automatic_tax?.enabled &&
    !sub.discounts?.length && !sub.default_tax_rates?.length && !item.tax_rates?.length && !item.discounts?.length &&
    !sub.billing_thresholds && !item.billing_thresholds && !sub.application_fee_percent && !sub.transfer_data && !sub.on_behalf_of &&
    item.quantity===1 && item.price.type==='recurring' && item.price.billing_scheme==='per_unit' &&
    item.price.recurring?.interval===interval(cadence) && item.price.recurring.interval_count===1 &&
    item.price.recurring.usage_type==='licensed' && item.current_period_end>Math.floor(Date.now()/1000)+60
}
function paymentMethod(sub:Stripe.Subscription) {
  return typeof sub.default_payment_method==='string'?sub.default_payment_method:sub.default_payment_method?.id??null
}
async function scheduleMatches(id:string,revision:string|null,end:number,retry:string|null) {
  const current=await stripe!.subscriptionSchedules.retrieve(id)
  return current.status==='active' && current.current_phase?.end_date===end &&
    (current.metadata?.sectalk_plan_change===revision || current.metadata?.sectalk_plan_change===retry)
}
