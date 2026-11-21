import {createHash,createPublicKey} from 'node:crypto'
import {pathToFileURL} from 'node:url'

const hash=value=>createHash('sha256').update(value).digest('hex')

async function readMetadata(origin,path,fetcher){
  let response
  try{
    response=await fetcher(origin+path,{method:'GET',redirect:'error',cache:'no-store',
      headers:{Accept:'application/json'},signal:AbortSignal.timeout(6000)})
  }catch{throw new Error('Could not reach the approved HTTPS issuer metadata.')}
  if(!response.ok||response.redirected||!response.body||
    !/^application\/json(?:\s*;|$)/i.test(response.headers.get('content-type')??'')){
    await response.body?.cancel().catch(()=>undefined)
    throw new Error('The approved issuer did not return direct JSON metadata.')
  }
  const reader=response.body.getReader()
  const chunks=[]
  let size=0
  try{
    for(;;){
      const {value,done}=await reader.read()
      if(done)break
      size+=value.byteLength
      if(size>32768){
        await reader.cancel()
        throw new Error('Issuer metadata exceeds the fixture limit.')
      }
      chunks.push(value)
    }
  }finally{reader.releaseLock()}
  const raw=Buffer.concat(chunks,size)
  try{return {value:JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(raw)),sha256:hash(raw)}}
  catch{throw new Error('The approved issuer returned malformed JSON metadata.')}
}

export async function preflightSyntheticOidcIssuer({issuer,fetcher=fetch}){
  const url=URL.parse(issuer??'')
  if(url?.protocol!=='https:'||url.origin!==issuer||!/^(?:[a-z0-9-]+\.)+[a-z][a-z0-9-]*$/.test(url.hostname)){
    throw new Error('Choose the approved distinct HTTPS fixture issuer origin.')
  }
  const discovery=await readMetadata(issuer,'/.well-known/openid-configuration',fetcher)
  const value=discovery.value
  if(value?.issuer!==issuer||Object.entries({
    authorization_endpoint:'/authorize',token_endpoint:'/token',jwks_uri:'/jwks',userinfo_endpoint:'/userinfo',
  }).some(([field,path])=>value[field]!==issuer+path)||
    Object.entries({
      response_types_supported:['code'],grant_types_supported:['authorization_code'],
      id_token_signing_alg_values_supported:['RS256'],code_challenge_methods_supported:['S256'],
      scopes_supported:['openid','email','profile'],token_endpoint_auth_methods_supported:['client_secret_basic','client_secret_post'],
    }).some(([field,required])=>!Array.isArray(value[field])||required.some(item=>!value[field].includes(item)))){
    throw new Error('The HTTPS discovery contract does not match the isolated native OAuth fixture.')
  }
  const jwks=await readMetadata(issuer,'/jwks',fetcher)
  const keys=jwks.value?.keys
  const ids=new Set()
  if(!Array.isArray(keys)||keys.length===0||keys.length>16)throw new Error('The fixture did not publish eligible signing keys.')
  let eligible=0
  for(const key of keys){
    if(typeof key?.kid!=='string'||!/^[A-Za-z0-9_-]{1,128}$/.test(key.kid)||ids.has(key.kid)||
      ['d','p','q','dp','dq','qi','oth','k'].some(name=>Object.hasOwn(key,name))){
      throw new Error('The fixture JWKS contains duplicate identifiers or non-public key material.')
    }
    ids.add(key.kid)
    if(key.kty!=='RSA'||key.alg!=='RS256'||key.use!=='sig')continue
    try{
      if(createPublicKey({key,format:'jwk'}).asymmetricKeyDetails?.modulusLength>=2048)eligible++
    }catch{throw new Error('The fixture published a malformed RSA signing key.')}
  }
  if(!eligible)throw new Error('The fixture lacks an eligible public RS256 signing key.')
  return {format:'sectalk-synthetic-oidc-preflight-v1',issuerSha256:hash(issuer),discoverySha256:discovery.sha256,
    jwksSha256:jwks.sha256,signingKeys:eligible,declaredPkce:'S256',nativeAuthCompletion:'unverified'}
}

if(process.argv[1]&&pathToFileURL(process.argv[1]).href===import.meta.url){
  try{console.log(JSON.stringify(await preflightSyntheticOidcIssuer({issuer:process.env.SECTALK_OIDC_ISSUER})))}
  catch(error){console.error(error.message);process.exitCode=1}
}
