import { execFileSync } from 'node:child_process'
import { readFileSync, readdirSync } from 'node:fs'
import { join, relative, resolve } from 'node:path'
import { fileURLToPath, pathToFileURL } from 'node:url'
import { parseEnv } from 'node:util'

const browserVariables = new Set(['NEXT_PUBLIC_SUPABASE_URL','NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY'])
const credentialPatterns = [
  ['Supabase secret key', /\bsb_(?:secret_[a-z0-9_-]{16,}|access_[a-z0-9_-]{20,})\b/i],
  ['Supabase access token', /\bsbp_[a-f0-9]{30,}\b/i],
  ['Stripe server credential', /\b(?:sk_(?:test|live)_[a-z0-9]{14,}|whsec_[a-z0-9]{16,})\b/i],
  ['GitHub credential', /\b(?:gh[pousr]_[a-z0-9]{30,}|github_pat_[a-z0-9_]{40,})\b/i],
  ['OpenAI server credential', /\bsk-(?:proj-|svcacct-)[a-z0-9_-]{20,}\b/i],
  ['Private key material', /-----BEGIN (?:ENCRYPTED |RSA |EC |OPENSSH )?PRIVATE KEY-----/],
  ['Database URL with password', /\bpostgres(?:ql)?:\/\/[^\s:@/]+:[^\s@/]{8,}@[^\s/]+/i],
]
const sensitiveEnvironment = /(?:SECRET|TOKEN|PASSWORD|PRIVATE_KEY|SERVICE_ROLE|DATABASE_URL|STORAGE_KEY|SERVER_KEY|API_KEY|WEBHOOK_KEY)/
const credentialsIn = text => [...text.matchAll(/\beyJ[a-zA-Z0-9_-]{7,}\.(eyJ[a-zA-Z0-9_-]{7,})\.[a-zA-Z0-9_-]{10,}\b/g)]

export function secretFindings(text,{source=false,privateValues=[]}={}){
  const matches=new Set()
  for(const [name,pattern] of credentialPatterns){
    if(pattern.test(text))matches.add(name)
  }
  for(const [,claims] of credentialsIn(text)){
    try{
      if(JSON.parse(Buffer.from(claims,'base64url').toString()).role==='service_role')matches.add('Supabase service-role JWT')
    }catch{/* Only identifiable service credentials are reported. */}
  }
  if(source){
    for(const [,name] of text.matchAll(/\b(?:process\.env\.|process\.env\[['"])(NEXT_PUBLIC_[A-Z0-9_]+)\b/g)){
      if(!browserVariables.has(name))matches.add('Unapproved browser environment variable '+name)
    }
    if(/\bconsole\s*(?:\.\s*(?:log|error|warn|info|debug)|\[\s*['"](?:log|error|warn|info|debug)['"]\s*\])\s*\(/.test(text)){
      matches.add('Direct console logging in application source')
    }
  }
  if(privateValues.some(value=>value.length>=16&&text.includes(value)))matches.add('Configured server-only value in a browser asset')
  return [...matches]
}

function browserAssets(path){
  return readdirSync(path,{withFileTypes:true}).flatMap(file=>{
    const location=join(path,file.name)
    if(file.isDirectory())return browserAssets(location)
    return /\.(?:js|mjs|html|map|json|css)$/i.test(file.name)?[location]:[]
  })
}

function textFile(file){
  const bytes=readFileSync(file)
  return bytes.subarray(0,1024).includes(0)?null:bytes.toString('utf8')
}

export function verifySecrets({root=fileURLToPath(new URL('..',import.meta.url)),build=false}={}){
  const tracked=execFileSync('git',['ls-files','-z'],{cwd:root,encoding:'utf8'}).split('\0').filter(Boolean)
  const findings=[]
  for(const file of tracked){
    const text=textFile(resolve(root,file))
    if(text===null)continue
    const source=/^apps\/web\/(?:app|components|lib)\/.+\.(?:ts|tsx|js|mjs)$/.test(file)
    for(const rule of secretFindings(text,{source}))findings.push({file,rule})
    if(/(^|\/)\.env(?:\.|$)/.test(file)&&!file.endsWith('.env.example'))findings.push({file,rule:'Tracked environment file'})
  }
  if(build){
    const vars={...process.env}
    for(const file of ['.env','.env.production','.env.local','.env.production.local']){
      try{Object.assign(vars,parseEnv(readFileSync(join(root,'apps/web',file),'utf8')))}
      catch(error){if(error.code!=='ENOENT')throw new Error('Could not read a local environment file')}
    }
    const privateValues=Object.entries(vars).filter(([key,value])=>!key.startsWith('NEXT_PUBLIC_')
      &&sensitiveEnvironment.test(key)&&typeof value==='string'&&value.length>=16).map(([,value])=>value)
    const assets=browserAssets(join(root,'apps/web/.next/static'))
    if(!assets.length)throw new Error('Build the app before scanning browser assets')
    for(const path of [...assets,...browserAssets(join(root,'apps/web/public'))]){
      const text=textFile(path)
      if(text===null)continue
      for(const rule of secretFindings(text,{privateValues}))findings.push({file:relative(root,path),rule})
    }
  }
  return findings
}

if(process.argv[1]&&import.meta.url===pathToFileURL(resolve(process.argv[1])).href){
  try{
    const build=process.argv.includes('--build')
    const findings=verifySecrets({build})
    if(findings.length){
      for(const {file,rule} of findings)console.error(file+' — '+rule)
      process.exitCode=1
    }else console.log(build?'Tracked source and browser assets passed secret checks.':'Tracked source passed secret checks.')
  }catch{
    console.error('Secret checks could not complete. Check the Git checkout and, if requested, the production build.')
    process.exitCode=1
  }
}
