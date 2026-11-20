import http from 'node:http'
import https from 'node:https'
import { syncBuiltinESMExports } from 'node:module'

const port = Number(process.env.SECTALK_TRIAL_FIXTURE_PORT)
if (!Number.isInteger(port) || port < 1024 || port > 65535) throw new Error('A loopback Stripe fixture is required')
const request = https.request
https.request = function (options, ...args) {
  if (typeof options === 'object' && (options.host || options.hostname) === 'api.stripe.com') {
    const {agent,host,hostname,headers,...rest}=options
    return http.request({...rest,headers,hostname:'127.0.0.1',port,protocol:'http:'}, ...args)
  }
  return Reflect.apply(request,this,[options,...args])
}
syncBuiltinESMExports()
