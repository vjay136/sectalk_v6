import { checkSignupServiceReadiness, readinessResponse } from '../../../lib/readiness'
import { hostedSignup, signupConfiguration } from '../../../lib/signup-configuration.mjs'

export async function GET(request: Request) {
  if (!hostedSignup()) return readinessResponse('web')
  const signup = signupConfiguration(request.url)
  const signupReady = signup && await checkSignupServiceReadiness({url: signup.project, key: signup.serviceKey})
  return readinessResponse('web', Boolean(signupReady))
}
