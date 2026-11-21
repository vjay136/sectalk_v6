import { checkAttachmentReadiness, checkSignupServiceReadiness, readinessResponse } from '../../../lib/readiness'
import { hostedSignup, signupConfiguration } from '../../../lib/signup-configuration.mjs'

export async function GET(request: Request) {
  if (!hostedSignup()) return readinessResponse('web')
  const signup = signupConfiguration(request.url)
  if (!signup) return readinessResponse('web', false)
  const [signupReady, attachmentsReady]=await Promise.all([
    checkSignupServiceReadiness({url:signup.project,key:signup.serviceKey}),
    checkAttachmentReadiness({
      url:signup.project,publishableKey:signup.key,key:process.env.SECTALK_FILE_STORAGE_KEY,
      ticketSecret:process.env.SECTALK_FILE_TICKET_SECRET,
    }),
  ])
  return readinessResponse('web',signupReady && attachmentsReady)
}
