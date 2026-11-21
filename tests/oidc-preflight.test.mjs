import assert from 'node:assert/strict'
import {spawnSync} from 'node:child_process'
import {randomBytes} from 'node:crypto'
import {once} from 'node:events'
import {mkdtemp,readFile,rmdir,unlink} from 'node:fs/promises'
import {createServer,request} from 'node:https'
import {tmpdir} from 'node:os'
import {join} from 'node:path'
import {test} from 'node:test'
import {createSyntheticOidcIssuer} from './fixtures/oidc-issuer.mjs'
import {preflightSyntheticOidcIssuer} from './fixtures/oidc-preflight.mjs'

const issuer='https://oidc.fixture.example.invalid'

test('read-only fixture preflight validates trusted HTTPS, native OAuth metadata and public signing keys',
  {skip:process.platform!=='linux'},async()=>{
    const sandbox=await mkdtemp(join(tmpdir(),'sectalk-oidc-tls-'))
    const cert=join(sandbox,'fixture.crt'),key=join(sandbox,'fixture.key')
    let server
    try{
      const issued=spawnSync('openssl',['req','-x509','-newkey','rsa:2048','-nodes','-days','1',
        '-subj','/CN='+new URL(issuer).hostname,'-addext','subjectAltName=DNS:'+new URL(issuer).hostname,
        '-out',cert,'-keyout',key],{stdio:'ignore',timeout:10000})
      assert.equal(issued.status,0)
      const clientId='sectalk-qa-'+randomBytes(4).toString('hex')
      const fixture=createSyntheticOidcIssuer({issuer,clientId,clientSecret:randomBytes(32).toString('base64url'),
        testerCode:randomBytes(32).toString('base64url'),email:'verified@tenant-'+clientId.slice(-8)+'.example.invalid'})
      const trusted=await readFile(cert)
      server=createServer({cert:trusted,key:await readFile(key)},fixture.listeners('request')[0])
      server.listen(0,'127.0.0.1')
      await once(server,'listening')
      const paths=[]
      const read=(url,options,ca=trusted)=>new Promise((resolve,reject)=>{
        assert.equal(options.method,'GET')
        assert.equal(options.redirect,'error')
        assert.equal(options.body,undefined)
        assert.equal(options.headers.Authorization,undefined)
        const logical=new URL(url)
        assert.equal(logical.origin,issuer)
        paths.push(logical.pathname)
        const fetch=request({hostname:'127.0.0.1',port:server.address().port,servername:logical.hostname,
          path:logical.pathname,method:'GET',headers:options.headers,signal:options.signal,ca},message=>{
          const parts=[]
          message.on('data',chunk=>parts.push(chunk))
          message.on('error',reject)
          message.on('end',()=>resolve(new Response(Buffer.concat(parts),{status:message.statusCode,
            headers:{'Content-Type':message.headers['content-type']??''}})))
        })
        fetch.on('error',reject)
        fetch.end()
      })
      const receipt=await preflightSyntheticOidcIssuer({issuer,fetcher:read})
      assert.deepEqual(paths,['/.well-known/openid-configuration','/jwks'])
      assert.equal(receipt.declaredPkce,'S256')
      assert.equal(receipt.signingKeys,1)
      assert.equal(receipt.nativeAuthCompletion,'unverified')
      assert.equal(JSON.stringify(receipt).includes(issuer),false)
      await assert.rejects(preflightSyntheticOidcIssuer({issuer,fetcher:(url,options)=>read(url,options,null)}),
        /Could not reach/)
      let redirectedReads=0
      await assert.rejects(preflightSyntheticOidcIssuer({issuer,fetcher:async(url,options)=>{
        redirectedReads++
        const original=await (await read(url,options)).json()
        return Response.json({...original,jwks_uri:'https://unknown.example.invalid/jwks'})
      }}),/discovery contract/)
      assert.equal(redirectedReads,1)
      await assert.rejects(preflightSyntheticOidcIssuer({issuer,fetcher:async(url,options)=>{
        const response=await read(url,options)
        if(!url.endsWith('/jwks'))return response
        const {keys}=await response.json()
        return Response.json({keys:[{...keys[0],d:'fixture-invalid'}]})
      }}),/non-public key material/)
      await assert.rejects(preflightSyntheticOidcIssuer({issuer,fetcher:async(url,options)=>{
        const response=await read(url,options)
        if(!url.endsWith('/jwks'))return response
        const {keys}=await response.json()
        return Response.json({keys:[keys[0],keys[0]]})
      }}),/duplicate identifiers/)
    }finally{
      if(server?.listening)await new Promise(resolve=>server.close(resolve))
      for(const file of [cert,key])await unlink(file).catch(error=>{if(error.code!=='ENOENT')throw error})
      await rmdir(sandbox)
    }
  })
