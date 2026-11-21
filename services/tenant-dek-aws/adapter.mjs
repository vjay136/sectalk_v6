import {spawn} from 'node:child_process'
import {createHash,timingSafeEqual} from 'node:crypto'
import {createServer} from 'node:http'

const uuid=/^[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$/
const reference=/^[A-Za-z0-9_-]{1,96}$/
const arn=/^arn:aws:kms:([a-z]{2}-[a-z]+-[1-9][0-9]?):[0-9]{12}:key\/([0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}|mrk-[0-9a-f]{32})$/
const tokenPattern=/^[A-Za-z0-9_-]{24,128}$/
const bodyLimit=6144
const headers={'Cache-Control':'no-store','X-Content-Type-Options':'nosniff','Content-Type':'application/json'}

function keyBinding(workspace,version,ref) {return JSON.stringify([workspace,version,ref])}

export function readAllowlist(raw) {
  if(typeof raw!=='string'||raw.length>262144)throw new Error('Invalid tenant key allowlist')
  const rows=JSON.parse(raw)
  if(!Array.isArray(rows)||!rows.length||rows.length>500)throw new Error('Invalid tenant key allowlist')
  const bindings=new Map()
  const resources=new Set()
  for(const row of rows) {
    const match=typeof row?.keyId==='string'?arn.exec(row.keyId):null
    if(!match||typeof row.workspace!=='string'||!uuid.test(row.workspace)||
      !Number.isSafeInteger(row.version)||row.version<1||typeof row.reference!=='string'||!reference.test(row.reference)) {
      throw new Error('Invalid exact AWS key binding')
    }
    const binding=keyBinding(row.workspace,row.version,row.reference)
    if(bindings.has(binding)||resources.has(match[2]))throw new Error('Duplicate tenant key binding')
    resources.add(match[2])
    bindings.set(binding,{keyId:row.keyId,region:match[1]})
  }
  return bindings
}

function base64url(value,min,max) {
  if(typeof value!=='string'||value.length>Math.ceil(max*4/3)||!/^[A-Za-z0-9_-]+$/.test(value))return null
  const bytes=Buffer.from(value,'base64url')
  if(bytes.length>=min&&bytes.length<=max&&bytes.toString('base64url')===value)return bytes
  bytes.fill(0)
  return null
}

function parseRequest(input,bindings) {
  if(input?.operation!=='wrap'&&input?.operation!=='unwrap')return null
  if(Object.keys(input).length!==7)return null
  const {operation,workspace,version,reference:ref,keyId,context,value}=input
  if(typeof workspace!=='string'||!uuid.test(workspace)||!Number.isSafeInteger(version)||version<1||
    typeof ref!=='string'||!reference.test(ref))return null
  const entry=bindings.get(keyBinding(workspace,version,ref))
  if(!entry||keyId!==entry.keyId)return null
  const contextBytes=base64url(context,1,768)
  if(!contextBytes)return null
  try {
    const decoded=JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(contextBytes))
    if(!Array.isArray(decoded)||decoded.length!==6||decoded[0]!=='sectalk/external-dek/v2'||
      decoded[1]!==workspace||decoded[2]!==version||decoded[3]!==ref||decoded[4]!==keyId||
      !base64url(decoded[5],32,32)||!Buffer.from(JSON.stringify(decoded)).equals(contextBytes))return null
    const bytes=operation==='wrap'?base64url(value,32,32):base64url(value,60,1536)
    if(!bytes)return null
    return {operation,keyId,context,region:entry.region,bytes,encryptionContext:{
      purpose:'sectalk-tenant-dek-v2',binding:createHash('sha256').update(contextBytes).digest('hex'),
    }}
  } catch {return null}
  finally {contextBytes.fill(0)}
}

export function workloadEnvironment(source) {
  const tokenFile=source.AWS_WEB_IDENTITY_TOKEN_FILE, role=source.AWS_ROLE_ARN
  const task=source.AWS_CONTAINER_CREDENTIALS_RELATIVE_URI
  const webIdentity=typeof tokenFile==='string'&&tokenFile.startsWith('/')&&
    typeof role==='string'&&/^arn:aws:iam::[0-9]{12}:role\/[A-Za-z0-9+=,.@_\/-]{1,256}$/.test(role)
  const taskIdentity=typeof task==='string'&&/^\/v2\/credentials\/[A-Za-z0-9-]{1,100}$/.test(task)
  if(webIdentity===taskIdentity)throw new Error('Configure exactly one AWS workload identity')
  return {
    PATH:'/usr/local/bin:/usr/bin:/bin',HOME:'/tmp',LANG:'C.UTF-8',
    AWS_CONFIG_FILE:'/dev/null',AWS_SHARED_CREDENTIALS_FILE:'/dev/null',AWS_EC2_METADATA_DISABLED:'true',
    AWS_RETRY_MODE:'standard',AWS_MAX_ATTEMPTS:'1',AWS_CLI_AUTO_PROMPT:'off',AWS_IGNORE_CONFIGURED_ENDPOINT_URLS:'true',
    ...(webIdentity?{AWS_WEB_IDENTITY_TOKEN_FILE:tokenFile,AWS_ROLE_ARN:role,AWS_ROLE_SESSION_NAME:'sectalk-tenant-dek'}
      :{AWS_CONTAINER_CREDENTIALS_RELATIVE_URI:task}),
  }
}

export function awsArguments(input) {
  const encrypt=input.operation==='wrap'
  return ['kms',encrypt?'encrypt':'decrypt','--key-id',input.keyId,'--region',input.region,
    '--encryption-algorithm','SYMMETRIC_DEFAULT','--encryption-context',JSON.stringify(input.encryptionContext),
    encrypt?'--plaintext':'--ciphertext-blob','fileb:///dev/stdin','--output','json',
    '--no-cli-pager','--cli-connect-timeout','1','--cli-read-timeout','1']
}

export function awsRunner(env,launch=spawn) {
  return input=>new Promise((resolve,reject)=>{
    // The shell pipe gives AWS CLI a readable /dev/stdin even when Node uses a socket for child stdin.
    const child=launch('/bin/sh',['-c','/bin/cat | exec "$@"','sectalk-kms',
      '/usr/local/aws-cli/v2/current/bin/aws',...awsArguments(input)],{
      cwd:'/tmp',env,detached:true,stdio:['pipe','pipe','ignore'],
    })
    let size=0,failed=false
    const chunks=[]
    function terminate() {
      failed=true
      if(child.pid)try {process.kill(-child.pid,'SIGKILL')} catch {child.kill('SIGKILL')}
    }
    const deadline=setTimeout(terminate,1900)
    child.stdout.on('data',chunk=>{
      size+=chunk.length
      if(size>8192){chunk.fill(0);terminate();return}
      chunks.push(chunk)
    })
    child.stdin.on('error',()=>{failed=true})
    child.on('error',()=>{failed=true})
    child.on('close',code=>{
      clearTimeout(deadline)
      const output=Buffer.concat(chunks)
      for(const chunk of chunks)chunk.fill(0)
      try {
        if(failed||code!==0)throw new Error('AWS KMS unavailable')
        resolve(JSON.parse(output.toString('utf8')))
      } catch {reject(new Error('AWS KMS unavailable'))}
      finally {output.fill(0)}
    })
    child.stdin.end(input.bytes)
  })
}

function resultValue(result,input) {
  if(result?.KeyId!==input.keyId||result.EncryptionAlgorithm!=='SYMMETRIC_DEFAULT')return null
  const raw=input.operation==='wrap'?result.CiphertextBlob:result.Plaintext
  if(typeof raw!=='string'||raw.length>2048||!/^[A-Za-z0-9+/]+={0,2}$/.test(raw))return null
  const bytes=Buffer.from(raw,'base64')
  try {
    if(bytes.toString('base64')!==raw)return null
    if(input.operation==='unwrap'?bytes.length!==32:bytes.length<60||bytes.length>1536)return null
    return bytes.toString('base64url')
  } finally {bytes.fill(0)}
}

export function createAdapter({token,bindings,runKms}) {
  if(!tokenPattern.test(token))throw new Error('Adapter requires a private bearer token')
  const credential=createHash('sha256').update('Bearer '+token).digest()
  let active=0
  return createServer({requestTimeout:3000,headersTimeout:2500,connectionsCheckingInterval:1000,maxHeaderSize:4096},async(req,res)=>{
    const respond=(status,body)=>{res.writeHead(status,headers);res.end(JSON.stringify(body))}
    if(req.method!=='POST'||req.url!=='/v1/tenant-dek')return respond(404,{error:'Not found'})
    const supplied=createHash('sha256').update(req.headers.authorization??'').digest()
    if(!timingSafeEqual(supplied,credential))return respond(401,{error:'Unauthorized'})
    if(req.headers['content-type']!=='application/json')return respond(415,{error:'Unsupported media'})
    const length=Number(req.headers['content-length'])
    if(!Number.isSafeInteger(length)||length<2||length>bodyLimit)return respond(413,{error:'Invalid request size'})
    if(active>=4)return respond(503,{error:'Key operation unavailable'})
    active++
    let input
    const parts=[]
    try {
      let size=0
      for await(const chunk of req) {
        size+=chunk.length
        if(size>bodyLimit)return respond(413,{error:'Invalid request size'})
        parts.push(chunk)
      }
      if(size!==length)return respond(400,{error:'Invalid request'})
      const raw=Buffer.concat(parts)
      try {input=parseRequest(JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(raw)),bindings)}
      catch {return respond(400,{error:'Invalid request'})}
      finally {raw.fill(0)}
      if(!input)return respond(403,{error:'Key operation unavailable'})
      const value=resultValue(await runKms(input),input)
      if(!value)return respond(503,{error:'Key operation unavailable'})
      respond(200,{keyId:input.keyId,context:input.context,value})
    } catch {respond(503,{error:'Key operation unavailable'})}
    finally {
      active--
      input?.bytes.fill(0)
      for(const part of parts)part.fill(0)
    }
  })
}
