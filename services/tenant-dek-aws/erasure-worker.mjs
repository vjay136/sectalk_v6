import { readAllowlist,workloadEnvironment } from './adapter.mjs'
import { awsErasureObserver,createProviderErasureAttestor } from './erasure-attestor.mjs'

const settings=process.env
const bindings=readAllowlist(settings.SECTALK_TENANT_DEK_AWS_KEYS)
const observe=awsErasureObserver(workloadEnvironment(settings))
createProviderErasureAttestor({token:settings.SECTALK_PROVIDER_ERASURE_ADAPTER_TOKEN??'',bindings,observe}).listen(8080,'0.0.0.0')
