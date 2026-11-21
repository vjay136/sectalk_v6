import {awsRunner,createAdapter,readAllowlist,workloadEnvironment} from './adapter.mjs'

const settings=process.env
const bindings=readAllowlist(settings.SECTALK_TENANT_DEK_AWS_KEYS)
const runKms=awsRunner(workloadEnvironment(settings))
const server=createAdapter({token:settings.SECTALK_TENANT_DEK_ADAPTER_TOKEN??'',bindings,runKms})
server.listen(8080,'0.0.0.0')
