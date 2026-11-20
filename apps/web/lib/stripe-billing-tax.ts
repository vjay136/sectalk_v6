import type Stripe from 'stripe'
import {indiaStates,unionWithoutLegislature,validGstin,type TaxProfile,type TaxEstimate} from './billing-tax'
import {billingWriter,catalogPriceId,stripe,stripeLiveMode} from './stripe-server'
import {isBillingCurrency,isPaidPlan} from './billing'
import {stripeBillingUuid} from './stripe-reconciliation'
import {stripeReference} from './stripe-invoice-documents'

export function billingTaxConfigured() {return process.env.SECTALK_STRIPE_TAX==='enabled' && Boolean(stripe)}

function cleaner(value:unknown,min:number,max:number) {
  if (typeof value!=='string') return null
  const result=value.trim()
  return result.length>=min&&result.length<=max&&!/[\p{Cc}\p{Cf}]/u.test(result)?result:null
}
function profileFrom(input:unknown):TaxProfile|null {
  if (!input||typeof input!=='object') return null
  const p=input as Record<string,unknown>
  const company=cleaner(p.company,0,100),country=cleaner(p.country,2,2)?.toUpperCase()
  const region=cleaner(p.region,0,40),city=cleaner(p.city,1,80),postal=cleaner(p.postal,1,16)
  const address=cleaner(p.address,1,120),taxId=cleaner(p.taxId,0,24)?.toUpperCase()
  if (company===null||!country||!/^[A-Z]{2}$/.test(country)||region===null||!city||!postal||!address||taxId===undefined) return null
  if (country==='IN') {
    if (!indiaStates[region] || !/^[1-9][0-9]{5}$/.test(postal) || (taxId&&(!company||!validGstin(taxId,region)))) return null
  } else if (taxId) {
    return null
  }
  return {company,country,region,city,postal,address,taxId}
}

export async function taxLedger(account:string,action:string,data:object|null=null) {
  if (!billingWriter) throw new Error('Tax profiles are unavailable')
  const result=await billingWriter.rpc('st_v8_tax_checkout',{p_account:account,p_action:action,p_data:data})
  if (result.error) throw new Error('Tax profiles are unavailable')
  return result.data
}

export async function billingTaxAction(account:string,input:Record<string,unknown>) {
  const provider=stripe
  if (!billingTaxConfigured()||!provider) return Response.json({error:'Tax checkout is unavailable.'},{status:503})
  try {
    if (input.action==='tax_profile') return Response.json({profile:(await taxLedger(account,'profile'))?.details??null})
    const profile=profileFrom(input.profile)
    if (!profile) return Response.json({error:'Enter a valid address and matching India GSTIN. GSTIN requires a company name.'},{status:400})
    const saved=await taxLedger(account,'save',profile)
    if (!saved) return Response.json({error:'Tax profile is unavailable.'},{status:403})
    const {plan,cadence,currency,version}=input
    if (!isPaidPlan(plan)||(cadence!=='annual'&&cadence!=='monthly')||!isBillingCurrency(currency)||
      typeof version!=='number'||!Number.isInteger(version)||version<1||version>2147483647)
      return Response.json({error:'Choose a plan to estimate taxes.'},{status:400})
    const selected=await catalogPriceId(plan,cadence,currency,version)
    if (!selected) return Response.json({error:'This plan is unavailable.'},{status:422})
    const price=await provider.prices.retrieve(selected.id)
    if (price.id!==selected.id || price.currency.toUpperCase()!==currency || !price.active || price.livemode!==stripeLiveMode ||
      (selected.amount!==null&&price.unit_amount!==selected.amount))
      return Response.json({error:'The payment provider returned different pricing terms.'},{status:422})
    const estimate=await quoteTax(profile,price)
    if (!estimate) return Response.json({error:'The provider could not quote tax for this address and plan.'},{status:422})
    const quote=await taxLedger(account,'quote',{revision:saved.revision,price:selected.id,estimate})
    if (!quote) return Response.json({error:'Your tax profile changed. Review it and try again.'},{status:409})
    const {rates:_,...publicEstimate}=estimate
    return Response.json({id:quote.id,expires_at:quote.expires_at,estimate:publicEstimate})
  } catch {
    return Response.json({error:'The payment provider could not quote tax for this request.'},{status:502})
  }
}

function stripeAddress(profile:TaxProfile) {
  return {country:profile.country,state:profile.country==='IN'?indiaStates[profile.region]:profile.region||undefined,
    city:profile.city,postal_code:profile.postal,line1:profile.address}
}

async function quoteTax(profile:TaxProfile,price:Stripe.Price):Promise<TaxEstimate|null> {
  const provider=stripe!
  const behavior=price.tax_behavior==='inclusive'?'inclusive':price.tax_behavior==='exclusive'?'exclusive':null
  const base=price.unit_amount
  if (!behavior||!base||!Number.isSafeInteger(base)) return null
  const currency=price.currency.toUpperCase()
  if (profile.country==='IN') return quoteGst(profile,currency,base,behavior)
  const product=stripeReference(price.product)
  if (!product) return null
  const quote=await provider.tax.calculations.create({currency:price.currency,customer_details:{address:stripeAddress(profile),address_source:'billing'},
    line_items:[{amount:base,reference:price.id,product,tax_behavior:behavior}]})
  if (quote.currency!==price.currency || !Number.isSafeInteger(quote.amount_total)||!Number.isSafeInteger(quote.tax_amount_inclusive)||
    !Number.isSafeInteger(quote.tax_amount_exclusive) || !quote.tax_breakdown || quote.tax_breakdown.length>20 ||
    quote.tax_breakdown.some(part=>!Number.isSafeInteger(part.amount) || part.taxability_reason==='not_supported')) return null
  if (quote.amount_total!==base+quote.tax_amount_exclusive) return null
  return {base,net:base-quote.tax_amount_inclusive,total:quote.amount_total,currency,behavior,mode:'automatic',
    lines:quote.tax_breakdown.filter(part=>part.amount>0).map(part=>({
      label:(part.tax_rate_details.tax_type||'Tax').toUpperCase().replaceAll('_',' '),amount:part.amount,
    }))}
}

async function quoteGst(profile:TaxProfile,currency:string,base:number,behavior:'inclusive'|'exclusive'):Promise<TaxEstimate|null> {
  const seller=process.env.SECTALK_GST_SELLER_STATE??''
  const approvedBps=Number(process.env.SECTALK_GST_RATE_BPS)
  if (currency!=='INR'||!indiaStates[seller]||!Number.isInteger(approvedBps)||approvedBps<1||approvedBps>10000) return null
  const labels=seller!==profile.region?['IGST']:['CGST',unionWithoutLegislature.has(seller)?'UTGST':'SGST']
  const configuration=labels.map(label=>process.env['STRIPE_GST_'+label+'_'+behavior.toUpperCase()])
  if (configuration.some(value=>!value||!/^txr_[A-Za-z0-9_]{3,96}$/.test(value))) return null
  const rates=await Promise.all(configuration.map(id=>stripe!.taxRates.retrieve(id!)))
  if (rates.some((rate,index)=>rate.id!==configuration[index]||!rate.active||rate.livemode!==stripeLiveMode||rate.country!=='IN'||
    rate.display_name!==labels[index]||rate.inclusive!==(behavior==='inclusive')||
    !Number.isInteger(rate.percentage*100)||rate.percentage<=0||rate.percentage>100)) return null
  const bps=rates.map(rate=>Math.round(rate.percentage*100))
  if (bps.reduce((sum,value)=>sum+value,0)!==approvedBps||(bps.length===2&&bps[0]!==bps[1])) return null
  const divisor=behavior==='inclusive'?10000+approvedBps:10000
  const lines=labels.map((label,index)=>({label,amount:Math.round(base*bps[index]/divisor)}))
  const tax=lines.reduce((total,line)=>total+line.amount,0)
  return {base,net:behavior==='inclusive'?base-tax:base,total:behavior==='exclusive'?base+tax:base,
    currency,behavior,mode:'gst',rates:rates.map(rate=>rate.id),lines}
}

export type TaxBinding={id:string;profile:TaxProfile;estimate:TaxEstimate}
export async function taxCheckoutBinding(account:string,quote:unknown,price:string,checkout?:string):Promise<TaxBinding|null> {
  if (typeof quote!=='string'||!stripeBillingUuid.test(quote)) return null
  return taxLedger(account,checkout?'attach':'validate',{id:quote,price,checkout})
}
export async function taxCustomer(binding:TaxBinding,email:string|undefined,existing:string|null|undefined,checkout:string) {
  const provider=stripe!
  const {profile}=binding
  const address=stripeAddress(profile)
  const name=profile.company||undefined
  if (!existing) return (await provider.customers.create({email,name,address,
    ...(profile.taxId?{tax_id_data:[{type:'in_gst',value:profile.taxId}]}:{})},{idempotencyKey:'sectalk-tax-customer-'+checkout})).id
  const taxes=await provider.customers.listTaxIds(existing,{limit:10})
  if (taxes.has_more||taxes.data.some(tax=>tax.type==='in_gst'&&tax.value!==profile.taxId))
    throw new Error('Update saved GSTIN in billing settings')
  if (profile.taxId&&!taxes.data.some(tax=>tax.type==='in_gst'&&tax.value===profile.taxId))
    await provider.customers.createTaxId(existing,{type:'in_gst',value:profile.taxId},{idempotencyKey:'sectalk-tax-id-'+checkout})
  return (await provider.customers.update(existing,{name,address},{idempotencyKey:'sectalk-tax-address-'+checkout})).id
}
