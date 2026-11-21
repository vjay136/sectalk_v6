import { attachmentReadinessStatus, checkSignupServiceReadiness, readinessResponse } from '../../../lib/readiness'
import { hostedSignup, signupConfiguration } from '../../../lib/signup-configuration.mjs'
import { logProviderFailure } from '../../../lib/provider-log.mjs'

export async function GET(request: Request) {
  if (!hostedSignup()) return readinessResponse('web')
  const signup = signupConfiguration(request.url)
  if (!signup) return readinessResponse('web', false)
  const [signupReady, attachments]=await Promise.all([
    checkSignupServiceReadiness({url:signup.project,key:signup.serviceKey}),
    attachmentReadinessStatus({
      url:signup.project,publishableKey:signup.key,key:process.env.SECTALK_FILE_STORAGE_KEY,
      ticketSecret:process.env.SECTALK_FILE_TICKET_SECRET,
    }),
  ])
  if (attachments!=='ready') logProviderFailure('attachment_readiness',attachments)
  return readinessResponse('web',signupReady && attachments==='ready')
}
