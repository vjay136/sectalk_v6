import {createHmac, timingSafeEqual} from 'node:crypto'
import type Stripe from 'stripe'
import {stripeLiveMode} from './stripe-server'
import {PDFDocument, StandardFonts, rgb} from 'pdf-lib'

export const invoiceId = /^in_[a-zA-Z0-9_]{1,100}$/
export const invoiceNumber = /^[A-Z0-9][A-Z0-9-]{0,31}-[0-9]{1,12}$/
export type InvoiceBinding = {customer: string; subscription: string}
type TaxLine = {amount: number; taxable: number | null; behavior: string; reason: string}
export type InvoiceDocument = {
  id: string; number: string; issued_at: string; paid_at: string | null; status: string; currency: string;
  subtotal: number; subtotal_excluding_tax: number | null; total: number; total_excluding_tax: number | null;
  amount_due: number; amount_paid: number; taxes: TaxLine[] | null
}
type Kind = 'invoice' | 'receipt' | 'page'
type Ticket = {id: string; kind: Kind; expires: number}

export function stripeReference(value: string | {id: string} | null | undefined) {
  return typeof value === 'string' ? value : value?.id
}

function timestamp(value: number | null | undefined) {
  return typeof value === 'number' && Number.isSafeInteger(value) && value > 0 && value < 253402300800
    ? new Date(value * 1000).toISOString() : null
}
function providerLabel(value: string) {
  return /^[a-z_]{1,45}$/.test(value) ? value.replaceAll('_', ' ') : 'Unspecified'
}

export function finalizedInvoice(invoice: Stripe.Invoice, binding: InvoiceBinding): InvoiceDocument | null {
  if (!invoiceId.test(invoice.id) || !invoice.number || !invoiceNumber.test(invoice.number)
    || !invoice.status || invoice.status === 'draft' || invoice.livemode !== stripeLiveMode
    || stripeReference(invoice.customer) !== binding.customer
    || stripeReference(invoice.parent?.subscription_details?.subscription) !== binding.subscription
    || !/^[a-z]{3}$/.test(invoice.currency)) return null
  const issued = timestamp(invoice.status_transitions?.finalized_at)
  if (!issued || ![invoice.subtotal,invoice.total,invoice.amount_due,invoice.amount_paid].every(Number.isSafeInteger)
    || ![invoice.subtotal_excluding_tax,invoice.total_excluding_tax].every(value => value === null || Number.isSafeInteger(value))) return null
  const taxes = invoice.total_taxes
  if (taxes !== null && (!Array.isArray(taxes) || taxes.length > 100
    || taxes.some(line => !Number.isSafeInteger(line.amount) || (line.taxable_amount !== null && !Number.isSafeInteger(line.taxable_amount))))) return null
  return {id: invoice.id, number: invoice.number, issued_at: issued, status: invoice.status, currency: invoice.currency.toUpperCase(),
    paid_at: invoice.status === 'paid' ? timestamp(invoice.status_transitions?.paid_at) : null,
    subtotal: invoice.subtotal, subtotal_excluding_tax: invoice.subtotal_excluding_tax, total: invoice.total,
    total_excluding_tax: invoice.total_excluding_tax, amount_due: invoice.amount_due, amount_paid: invoice.amount_paid,
    taxes: taxes?.map(line => ({amount: line.amount, taxable: line.taxable_amount,
      behavior: providerLabel(line.tax_behavior), reason: providerLabel(line.taxability_reason)})) ?? null}
}

function signature(payload: string, actor: string, scope: string, binding: InvoiceBinding, secret: string) {
  return createHmac('sha256', secret).update(JSON.stringify(['sectalk-stripe-invoice-v1',
    actor, scope, binding.customer, binding.subscription, payload])).digest()
}

export function issueInvoiceTicket(id: string, kind: Kind, actor: string, scope: string, binding: InvoiceBinding, secret: string) {
  const payload = Buffer.from(JSON.stringify({id, kind, expires: Date.now() + 180000} satisfies Ticket)).toString('base64url')
  return payload + '.' + signature(payload, actor, scope, binding, secret).toString('base64url')
}

export function readInvoiceTicket(value: string, actor: string, scope: string, binding: InvoiceBinding, secret: string): Ticket | null {
  const pair = /^([A-Za-z0-9_-]{1,320})\.([A-Za-z0-9_-]{43})$/.exec(value)
  if (!pair) return null
  const received = Buffer.from(pair[2], 'base64url')
  if (received.toString('base64url') !== pair[2]
    || !timingSafeEqual(signature(pair[1], actor, scope, binding, secret), received)) return null
  try {
    const body = JSON.parse(Buffer.from(pair[1], 'base64url').toString('utf8')) as Ticket
    return invoiceId.test(body.id) && ['invoice','receipt','page'].includes(body.kind)
      && Number.isSafeInteger(body.expires) && body.expires > Date.now() ? body : null
  } catch { return null }
}

function pdfAmount(amount: number, currency: string) {
  if (!['USD','EUR','GBP','INR','CAD','AUD','JPY'].includes(currency)) return currency + ' ' + String(amount) + ' minor units'
  const digits = currency === 'JPY' ? 0 : 2
  const absolute = BigInt(Math.abs(amount)).toString().padStart(digits + 1, '0')
  const exact = digits ? absolute.slice(0, -digits) + '.' + absolute.slice(-digits) : absolute
  return currency + ' ' + (amount < 0 ? '-' : '') + exact
}

export async function invoicePdf(invoice: InvoiceDocument, receipt: boolean) {
  const pdf = await PDFDocument.create()
  const bold = await pdf.embedFont(StandardFonts.HelveticaBold)
  const regular = await pdf.embedFont(StandardFonts.Helvetica)
  const title = receipt ? 'Payment receipt' : 'Invoice'
  pdf.setTitle(title + ' ' + invoice.number)
  pdf.setAuthor('SecTalk')
  pdf.setSubject('SecTalk copy of a finalized Stripe billing record')
  const ink = rgb(.08, .17, .25)
  const label = rgb(.1, .35, .44)
  let page = pdf.addPage([612,792])
  let y = 683
  function heading() {
    page.drawText('SECTALK', {x:48,y:747,size:12,font:bold,color:label})
    page.drawText(title + ' ' + invoice.number, {x:48,y:709,size:22,font:bold,color:ink})
    y = 683
  }
  function line(text: string, strong = false) {
    if (y < 62) {page = pdf.addPage([612,792]); heading()}
    page.drawText(text, {x:48,y,size:11,font:strong ? bold : regular,color:ink})
    y -= 21
  }
  const money = (amount: number) => pdfAmount(amount, invoice.currency)
  heading()
  line('Source: Stripe finalized subscription invoice')
  line('Issued: ' + invoice.issued_at.slice(0,10) + ' UTC')
  line('Invoice status: ' + providerLabel(invoice.status))
  if (invoice.paid_at) line('Payment recorded: ' + invoice.paid_at.slice(0,10) + ' UTC')
  line('Subtotal: ' + money(invoice.subtotal))
  if (invoice.subtotal_excluding_tax !== null) line('Subtotal excluding tax: ' + money(invoice.subtotal_excluding_tax))
  if (invoice.total_excluding_tax !== null) line('Total excluding tax: ' + money(invoice.total_excluding_tax))
  line('Total: ' + money(invoice.total), true)
  line('Amount due: ' + money(invoice.amount_due))
  line('Amount paid: ' + money(invoice.amount_paid), receipt)
  y -= 9
  line('Taxes reported by Stripe', true)
  if (invoice.taxes === null) line('No tax breakdown available from Stripe.')
  else if (!invoice.taxes.length) line('Stripe reported no tax lines.')
  else for (const [index, tax] of invoice.taxes.entries()) {
    line('Tax ' + (index + 1) + ': ' + money(tax.amount) + ' (' + tax.behavior + ')')
    line('   ' + tax.reason + (tax.taxable === null ? '' : ' - taxable amount ' + money(tax.taxable)))
  }
  y -= 9
  line('SecTalk copy. Stripe remains the source of the invoice number and status.')
  if (receipt) line('This copy confirms Stripe marked the invoice paid.')
  return pdf.save()
}
