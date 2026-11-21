const projectPattern=/^[a-z]{20}$/
const regionPattern=/^(us|eu|ap)-[a-z]+-[1-9][0-9]?$/
const orgPattern=/^[A-Za-z0-9_-]{1,80}$/
const uuidPattern=/^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/

export type ProviderTarget={cell:string;project:string;region:string;organization:string}
type Runtime={controlProject:string;managementToken:string;publishableKey:string;installationNonce:string}

async function boundedJson(response:Response) {
  if(!response.ok||!response.body)return null
  const reader=response.body.getReader()
  const chunks:Uint8Array[]=[]
  let size=0
  try {
    for(;;) {
      const next=await reader.read()
      if(next.done)break
      size+=next.value.length
      if(size>32768){await reader.cancel();return null}
      chunks.push(next.value)
    }
    return JSON.parse(Buffer.concat(chunks).toString('utf8'))
  } catch {return null}
  finally {reader.releaseLock()}
}

export async function verifyProviderTarget(target:ProviderTarget,runtime:Runtime,request:typeof fetch=fetch) {
  if(!projectPattern.test(target.project)||!projectPattern.test(runtime.controlProject)||target.project===runtime.controlProject||
    !regionPattern.test(target.region)||!orgPattern.test(target.organization)||!uuidPattern.test(target.cell)||
    !uuidPattern.test(runtime.installationNonce)||!/^sb_publishable_[A-Za-z0-9_-]{10,150}$/.test(runtime.publishableKey)||
    !/^[A-Za-z0-9_.-]{20,512}$/.test(runtime.managementToken))return false
  const fixed={cache:'no-store',redirect:'error'} as const
  const providerUrl='https://api.supabase.com/v1/projects/'+target.project
  try {
    const provider=await boundedJson(await request(providerUrl,{...fixed,signal:AbortSignal.timeout(4000),
      headers:{Authorization:'Bearer '+runtime.managementToken}}))
    if(provider?.ref!==target.project||provider.region!==target.region||provider.organization_slug!==target.organization||
      provider.status!=='ACTIVE_HEALTHY')return false
    const targetUrl='https://'+target.project+'.supabase.co/rest/v1/rpc/st_v8_residency_target_ready'
    return await boundedJson(await request(targetUrl,{...fixed,signal:AbortSignal.timeout(4000),method:'POST',
      headers:{apikey:runtime.publishableKey,'Content-Type':'application/json'},
      body:JSON.stringify({p_cell:target.cell,p_project:target.project,p_installation_nonce:runtime.installationNonce}),
    }))===true
  } catch { return false }
}

export function residencyRuntime(project:string) {
  const raw=process.env.SECTALK_RESIDENCY_TARGETS
  const controlProject=process.env.SECTALK_RESIDENCY_CONTROL_PROJECT_REF
  const managementToken=process.env.SECTALK_RESIDENCY_PROVIDER_READ_TOKEN
  const controlUrl=process.env.NEXT_PUBLIC_SUPABASE_URL
  if(!raw||raw.length>32768||!controlProject||!managementToken||!controlUrl||!projectPattern.test(project))return null
  try {
    const canonical=/^([a-z]{20})\.supabase\.co$/.exec(new URL(controlUrl).hostname)
    if(canonical&&canonical[1]!==controlProject)return null
    const config=JSON.parse(raw)
    const target=Object.hasOwn(config,project)?config[project]:null
    if(typeof target?.publishableKey!=='string'||typeof target.installationNonce!=='string')return null
    return {controlProject,managementToken,publishableKey:target.publishableKey,installationNonce:target.installationNonce}
  } catch {return null}
}
