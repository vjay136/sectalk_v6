import { readinessResponse } from '../../../lib/readiness'
import { hostedSignup, signupConfiguration } from '../../../lib/signup-configuration.mjs'

export function GET(request: Request) {
  return readinessResponse('web', !hostedSignup() || Boolean(signupConfiguration(request.url)))
}
