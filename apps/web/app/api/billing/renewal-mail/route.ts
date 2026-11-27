import {billingWriter} from '../../../../lib/stripe-server'
import { billingMode, billingPausedResponse } from '../../../../lib/billing-mode'
import {emailHeaders,notificationDrainAuthorized,notificationProviderFailure,notificationSMTPConfiguration} from '../../../../lib/notification-email-server'

export const runtime = 'nodejs'
export const maxDuration = 30
type Claim = {id:string;lease:string}
const mailbox = /^[^\s@<>,;:"]+@[a-z0-9.-]+\.[a-z0-9-]+$/i

export async function POST(request: Request) {
  if (billingMode() === 'free') return billingPausedResponse()
  const secret = process.env.SECTALK_RENEWAL_MAIL_SECRET
  const mail = notificationSMTPConfiguration()
  if (!secret || Buffer.byteLength(secret)<32 || !mail || !billingWriter)
    return new Response(null,{status:503,headers:emailHeaders})
  if (!notificationDrainAuthorized(request,secret)) return new Response(null,{status:401,headers:emailHeaders})
  const store=billingWriter
  const batch=await store.rpc('st_v7_renewal_mail_claim')
  if (batch.error) return new Response(null,{status:503,headers:emailHeaders})
  const result=await Promise.all((batch.data as Claim[]).map(async job=>{
    const lease={p_id:job.id,p_lease:job.lease}
    const checked=await store.rpc('st_v7_renewal_mail_confirm',lease)
    if (checked.error) return false
    const row=checked.data
    let outcome:'sent'|'retry'|'failed'|'closed'='closed'
    if (typeof row?.email==='string' && row.email.length<=254 && mailbox.test(row.email)) {
      try {
        const billing=new URL('/?billing=renewal',mail.origin)
        const body=['Stripe could not complete your SecTalk subscription renewal.',
          'Your grace period ends '+new Date(row.grace_until).toUTCString()+'.',
          row.retry_at ? 'Stripe currently schedules another attempt for '+new Date(row.retry_at).toUTCString()+'.' : '',
          'Manage payment from Billing: '+billing.href,
        ].filter(Boolean).join('\n\n')
        const sent=await mail.transport.sendMail({from:{address:mail.from,name:'SecTalk by Eagle Security'},to:{address:row.email,name:''},
          messageId:'<renewal-'+job.id+'@'+billing.hostname+'>',subject:'SecTalk subscription renewal needs attention',text:body})
        outcome=sent.accepted.length===1?'sent':'failed'
      } catch(error) {outcome=notificationProviderFailure(error)==='retry'?'retry':'failed'}
    }
    const settled=await store.rpc('st_v7_renewal_mail_finish',{...lease,p_outcome:outcome})
    return !settled.error && settled.data===true && outcome==='sent'
  }))
  return Response.json({processed:result.length,accepted:result.filter(Boolean).length},{headers:emailHeaders})
}
