import { execFile } from 'node:child_process'
import { createHash,timingSafeEqual } from 'node:crypto'
import { createServer } from 'node:http'
import { promisify } from 'node:util'
import { keyDeletionEvidence,kmsKeyArn } from './cloudtrail-key-deletion.mjs'

const aws=promisify(execFile)
const cli='/usr/local/aws-cli/v2/current/bin/aws'
const tokenPattern=/^[A-Za-z0-9_-]{32,128}$/
const liveStates={Enabled:'active',Disabled:'disabled',PendingDeletion:'pending_deletion',PendingReplicaDeletion:'pending_replica_deletion'}

export function awsErasureObserver(env,run=aws,now=Date.now) {
  async function command(service,action,args,region) {
    const {stdout}=await run(cli,[service,action,...args,'--region',region,'--output','json','--no-cli-pager',
      '--cli-connect-timeout','1','--cli-read-timeout','1'],{cwd:'/tmp',env,timeout:1800,maxBuffer:1024*1024})
    return JSON.parse(stdout)
  }
  return async ({keyId,region,stagedAt})=>{
    const [,expectedRegion,expectedAccount,key]=kmsKeyArn.exec(keyId)??[]
    if (!key||region!==expectedRegion||!Number.isFinite(Date.parse(stagedAt))) return {state:'unavailable'}
    try {
      const result=await command('kms','describe-key',['--key-id',keyId],region)
      if (result?.KeyMetadata?.Arn!==keyId || result.KeyMetadata.AWSAccountId!==expectedAccount) return {state:'unavailable'}
      const state=Object.hasOwn(liveStates,result.KeyMetadata.KeyState) ? liveStates[result.KeyMetadata.KeyState] : 'unavailable'
      return {state}
    } catch (error) {
      if(typeof error?.stderr!=='string' || !/An error occurred \(NotFoundException\) when calling the DescribeKey operation/.test(error.stderr)) {
        return {state:'unavailable'}
      }
    }
    if(key.startsWith('mrk-'))return {state:'unavailable'}
    let next
    for(let page=0;page<2;page++) {
      const result=await command('cloudtrail','lookup-events',['--lookup-attributes','AttributeKey=EventName,AttributeValue=DeleteKey',
        '--start-time',stagedAt,'--page-size','50','--max-items','50','--query','{Events:Events[].CloudTrailEvent,NextToken:NextToken}',
        ...(next?['--starting-token',next]:[])],region)
      if(!Array.isArray(result?.Events))return {state:'unavailable'}
      for (const entry of result.Events) {
        let event
        try { event=JSON.parse(entry) } catch { continue }
        if(keyDeletionEvidence(event,keyId,stagedAt,now())) return {state:'not_found',event}
      }
      next=result.NextToken
      if(typeof next!=='string'||next.length>4096||!next)break
    }
    return {state:'not_found'}
  }
}

export function createProviderErasureAttestor({token,bindings,observe}) {
  if (!tokenPattern.test(token)) throw new Error('Erasure attestor requires its own private bearer token')
  const hash=value=>createHash('sha256').update(value).digest()
  const expected=hash('Bearer '+token)
  let active=0
  return createServer({requestTimeout:3000,headersTimeout:2500,connectionsCheckingInterval:1000,maxHeaderSize:4096},async (request,response)=>{
    const send=(status,body)=>{response.writeHead(status,{'Content-Type':'application/json','Cache-Control':'no-store'}).end(JSON.stringify(body))}
    if (request.method!=='POST'||request.url!=='/v1/provider-key-erasure') return send(404,{})
    if (!timingSafeEqual(hash(request.headers.authorization??''),expected)) return send(401,{})
    if (request.headers['content-type']!=='application/json') return send(415,{})
    const length=Number(request.headers['content-length'])
    if (!Number.isSafeInteger(length)||length<2||length>2048) return send(413,{})
    if (active>=4) return send(503,{})
    active++
    try {
      let read=0
      const parts=[]
      for await (const part of request) {
        read+=part.length
        if (read>length) return send(413,{})
        parts.push(part)
      }
      if (read!==length) return send(400,{})
      const input=JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(Buffer.concat(parts)))
      if (!input||Object.keys(input).length!==5||typeof input.workspace!=='string'||typeof input.reference!=='string'||
        !Number.isSafeInteger(input.version)||typeof input.stagedAt!=='string'||!Number.isFinite(Date.parse(input.stagedAt))||
        Date.parse(input.stagedAt)>Date.now()) return send(400,{})
      const binding=bindings.get(JSON.stringify([input.workspace,input.version,input.reference]))
      if (!binding||binding.keyId!==input.keyId) return send(403,{})
      const report=await observe({...binding,stagedAt:new Date(input.stagedAt).toISOString()})
      send(200,{keyId:binding.keyId,...report})
    } catch { send(503,{}) }
    finally {active--}
  })
}
