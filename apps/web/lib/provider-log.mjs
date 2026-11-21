const services = new Set(['meeting_access','meeting_signing','meeting_screen_share','meeting_moderation','call_networking',
  'workspace_invitation_email','attachment_readiness'])
const failureTypes = new Set(['unavailable','signing_failed','invalid_ticket_secret','invalid_storage_configuration',
  'storage_key_rejected','storage_unavailable','private_bucket_not_verified'])

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
