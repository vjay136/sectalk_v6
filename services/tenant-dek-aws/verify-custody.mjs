import {execFile} from 'node:child_process'
import {createHash,randomBytes,timingSafeEqual} from 'node:crypto'
import {pathToFileURL} from 'node:url'
import {parseArgs,promisify} from 'node:util'
import {readAllowlist,workloadEnvironment} from './adapter.mjs'

const aws=promisify(execFile)
const cli='/usr/local/aws-cli/v2/current/bin/aws'
const sha=value=>createHash('sha256').update(value).digest('hex')
const uuid=/^[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$/
const role=/^arn:aws:iam::([0-9]{12}):role\/(?:[A-Za-z0-9+=,.@_-]+\/)*([A-Za-z0-9+=,.@_-]{1,64})$/
const assumedRole=/^arn:aws:sts::([0-9]{12}):assumed-role\/([A-Za-z0-9+=,.@_-]{1,64})\/([A-Za-z0-9+=,.@_-]{2,64})$/
const origins=new Set(['AWS_KMS','EXTERNAL','AWS_CLOUDHSM','EXTERNAL_KEY_STORE'])
const keyIdParts=/^arn:aws:kms:([^:]+):([0-9]{12}):key\/(.+)$/

export function approvedBinding(settings,workspace,version,reference) {
  if(!uuid.test(workspace??'')||!Number.isSafeInteger(version)||version<1||!/^[A-Za-z0-9_-]{1,96}$/.test(reference??'')) {
    throw new Error('Select the approved workspace, version, and reference.')
  }
  let allowed
  try {allowed=readAllowlist(settings.SECTALK_TENANT_DEK_AWS_KEYS)}
  catch {throw new Error('The adapter custody mapping is invalid.')}
  const adapter=allowed.get(JSON.stringify([workspace,version,reference]))
  const mapping=settings.SECTALK_EXTERNAL_KMS_KEYS
  if(!adapter||typeof mapping!=='string'||mapping.length>262144)throw new Error('The approved app and adapter bindings are required.')
  let app
  try {app=JSON.parse(mapping)} catch {throw new Error('The app custody mapping is invalid.')}
  const configured=app?.[workspace]?.keys
  if(!configured||!Object.hasOwn(configured,reference)||configured[reference]!==adapter.keyId||
    adapter.keyId!==settings.SECTALK_CUSTODY_EXPECTED_KEY_ARN) {
    throw new Error('The independently approved key ARN, app mapping, and adapter binding must agree.')
  }
  return {workspace,version,reference,...adapter}
}

function evidencePins(binding) {
  return {
    workspaceSha256:sha(binding.workspace),version:binding.version,keyArnSha256:sha(binding.keyId),
    bindingSha256:sha(JSON.stringify([binding.workspace,binding.version,binding.reference,binding.keyId])),
  }
}

export async function inspectAwsCustody({binding,settings,expectedOrigin,run=aws}) {
  const expectedRole=role.exec(settings.SECTALK_CUSTODY_EXPECTED_ROLE_ARN??'')
  const expectedRoleId=settings.SECTALK_CUSTODY_EXPECTED_ROLE_ID??''
  const key=keyIdParts.exec(binding.keyId)
  if(!key||!expectedRole||!/^AROA[A-Z0-9]{16,28}$/.test(expectedRoleId)||!origins.has(expectedOrigin)) {
    throw new Error('Supply the approved workload role ARN and unique role ID, and the expected key material origin.')
  }
  const env=workloadEnvironment(settings)
  async function read(service,action,extra=[]) {
    try {
      const {stdout}=await run(cli,[service,action,...extra,'--region',binding.region,'--output','json',
        '--no-cli-pager','--cli-connect-timeout','3','--cli-read-timeout','5'],{
        cwd:'/tmp',env,timeout:12000,maxBuffer:65536,
      })
      return JSON.parse(stdout)
    }catch{throw new Error('The approved read-only AWS inspection could not be completed.')}
  }
  const caller=await read('sts','get-caller-identity')
  const actual=assumedRole.exec(caller?.Arn??'')
  if(!actual||caller.Account!==expectedRole[1]||actual[1]!==expectedRole[1]||actual[2]!==expectedRole[2]||
    caller.UserId!==expectedRoleId+':'+actual[3]) {
    throw new Error('AWS STS did not confirm the expected workload role.')
  }
  const metadata=(await read('kms','describe-key',['--key-id',binding.keyId]))?.KeyMetadata
  if(!metadata||metadata.Arn!==binding.keyId||metadata.KeyId!==key[3]||metadata.AWSAccountId!==key[2]||
    metadata.Enabled!==true||metadata.KeyState!=='Enabled'||metadata.KeyManager!=='CUSTOMER'||
    metadata.KeySpec!=='SYMMETRIC_DEFAULT'||metadata.KeyUsage!=='ENCRYPT_DECRYPT'||
    !Array.isArray(metadata.EncryptionAlgorithms)||!metadata.EncryptionAlgorithms.includes('SYMMETRIC_DEFAULT')||
    metadata.Origin!==expectedOrigin||metadata.MultiRegion!==key[3].startsWith('mrk-')) {
    throw new Error('AWS KMS did not confirm the exact approved enabled symmetric customer key.')
  }
  return {check:'aws_custody_metadata',checkedAt:new Date().toISOString(),...evidencePins(binding),
    roleSha256:sha(JSON.stringify([settings.SECTALK_CUSTODY_EXPECTED_ROLE_ARN,expectedRoleId])),
    keyOrigin:metadata.Origin,scope:metadata.MultiRegion?'regional_key_in_multi_region_set':'single_region_key',
    erasure:'unverified',backupErasure:'unverified'}
}

async function responseJson(response) {
  if(!response.body||!/^application\/json(?:;|$)/i.test(response.headers.get('content-type')??'')||
    !/\bno-store\b/i.test(response.headers.get('cache-control')??'')){
    await response.body?.cancel()
    throw new Error('The adapter response was not private JSON.')
  }
  const reader=response.body.getReader()
  const chunks=[]
  let size=0
  try{
    for(;;){
      const {done,value}=await reader.read()
      if(done)break
      size+=value.byteLength
      if(size>4096){value.fill(0);await reader.cancel();throw new Error('The adapter response exceeded its contract.')}
      chunks.push(value)
    }
    const joined=Buffer.concat(chunks,size)
    try{return JSON.parse(joined.toString('utf8'))}
    catch{throw new Error('The adapter response was malformed.')}
    finally{joined.fill(0)}
  }finally{
    for(const chunk of chunks)chunk.fill(0)
    reader.releaseLock()
  }
}

function capsuleValue(result,binding,context,min,max) {
  if(!result||Object.keys(result).length!==3||result.keyId!==binding.keyId||result.context!==context||
    typeof result.value!=='string'||!/^[A-Za-z0-9_-]+$/.test(result.value)) {
    throw new Error('The adapter did not return the exact approved key and context.')
  }
  const bytes=Buffer.from(result.value,'base64url')
  if(bytes.length<min||bytes.length>max||bytes.toString('base64url')!==result.value) {
    bytes.fill(0)
    throw new Error('The adapter did not return canonical custody bytes.')
  }
  return bytes
}

export async function exerciseAwsAdapter({binding,endpoint,approvedOrigin,token,approvedTestKey,fetcher=fetch}) {
  const url=URL.parse(endpoint??'')
  if(approvedTestKey!==true||!url||url.protocol!=='https:'||url.origin!==approvedOrigin||url.pathname!=='/v1/tenant-dek'||
    url.username||url.password||url.search||url.hash||!(/^[A-Za-z0-9_-]{24,128}$/).test(token??'')) {
    throw new Error('The drill requires explicit non-production key confirmation and the exact authenticated HTTPS adapter endpoint.')
  }
  const {workspace,version,reference,keyId}=binding
  const encode=scope=>Buffer.from(JSON.stringify(['sectalk/external-dek/v2',workspace,version,reference,keyId,scope])).toString('base64url')
  const context=encode(randomBytes(32).toString('base64url'))
  const wrongContext=encode(randomBytes(32).toString('base64url'))
  const dek=randomBytes(32)
  let ciphertext,tampered
  async function post(operation,actualContext,value,status,overrideKey=keyId) {
    let response
    try{
      response=await fetcher(url,{method:'POST',redirect:'error',cache:'no-store',signal:AbortSignal.timeout(6000),
        headers:{Authorization:'Bearer '+token,'Content-Type':'application/json'},
        body:JSON.stringify({operation,workspace,version,reference,keyId:overrideKey,context:actualContext,value}),
      })
    }catch{throw new Error('The approved adapter endpoint could not be reached.')}
    if(response.status!==status){await response.body?.cancel();throw new Error('The adapter returned an unexpected custody status.')}
    if(status!==200){
      const result=await responseJson(response)
      if(result?.error!=='Key operation unavailable'||Object.keys(result).length!==1) {
        throw new Error('The adapter refusal returned unexpected fields.')
      }
      return null
    }
    return responseJson(response)
  }
  async function verifyRoundTrip(value) {
    const restored=capsuleValue(await post('unwrap',context,value,200),binding,context,32,32)
    try {if(!timingSafeEqual(restored,dek))throw new Error('The exact synthetic DEK did not round trip.')}
    finally{restored.fill(0)}
  }
  try{
    ciphertext=capsuleValue(await post('wrap',context,dek.toString('base64url'),200),binding,context,60,1536)
    const wrapped=ciphertext.toString('base64url')
    await verifyRoundTrip(wrapped)
    await post('unwrap',wrongContext,wrapped,503)
    tampered=Buffer.from(ciphertext)
    tampered[tampered.length-1]^=1
    await post('unwrap',context,tampered.toString('base64url'),503)
    const incorrectKey=keyId.slice(0,-1)+(keyId.endsWith('0')?'1':'0')
    await post('unwrap',context,wrapped,403,incorrectKey)
    await verifyRoundTrip(wrapped)
  }finally{
    dek.fill(0)
    ciphertext?.fill(0)
    tampered?.fill(0)
  }
  return {check:'aws_custody_adapter',checkedAt:new Date().toISOString(),...evidencePins(binding),
    ingressSha256:sha(url.origin),exactRoundTrip:true,contextIsolation:true,ciphertextIntegrity:true,
    mismatchedKeyRefused:true,erasure:'unverified',backupErasure:'unverified'}
}

if(process.argv[1]&&pathToFileURL(process.argv[1]).href===import.meta.url){
  try {
    let values
    try {
      ({values}=parseArgs({options:{mode:{type:'string'},workspace:{type:'string'},version:{type:'string'},
        reference:{type:'string'},origin:{type:'string'},'confirm-non-production-key':{type:'boolean'}}}))
    }catch {throw new Error('Invalid custody verification options.')}
    if(!['inspect','drill'].includes(values.mode)||!/^[1-9][0-9]{0,8}$/.test(values.version??'')) {
      throw new Error('Choose inspect or drill and supply the exact version.')
    }
    const settings=process.env
    const binding=approvedBinding(settings,values.workspace,Number(values.version),values.reference)
    const result=values.mode==='inspect'
      ? await inspectAwsCustody({binding,settings,expectedOrigin:values.origin})
      : await exerciseAwsAdapter({binding,endpoint:settings.SECTALK_EXTERNAL_KMS_URL,
        approvedOrigin:settings.SECTALK_CUSTODY_EXPECTED_ADAPTER_ORIGIN,token:settings.SECTALK_EXTERNAL_KMS_TOKEN,
        approvedTestKey:values['confirm-non-production-key']})
    console.log(JSON.stringify(result))
  }catch(error){
    console.error(error.message)
    process.exitCode=1
  }
}
