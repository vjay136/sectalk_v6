const services = new Set(['meeting_access','meeting_signing','call_networking'])
const failureTypes = new Set(['unavailable','signing_failed'])

/** Serialize only the reviewed diagnostic fields. Never serialize an Error, request, or provider response. */
export function providerFailureEvent(service, failure){
  return JSON.stringify({
    level:'warn',
    event:'provider_failure',
    service:services.has(service)?service:'unknown',
    failure:failureTypes.has(failure)?failure:'unknown',
  })
}

export function logProviderFailure(service, failure){
  process.stderr.write(providerFailureEvent(service,failure)+'\n')
}
