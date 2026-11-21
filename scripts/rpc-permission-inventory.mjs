import {execFileSync} from 'node:child_process'
import {createHash} from 'node:crypto'
import {readFileSync,writeFileSync} from 'node:fs'
import {pathToFileURL} from 'node:url'

const inventoryPath=new URL('../docs/spec/postgrest-rpc-inventory.json',import.meta.url)
export const rpcInventory=()=>JSON.parse(readFileSync(inventoryPath,'utf8'))

const query=`
with entry as (
  select n.nspname as schema, p.proname as name, p.oid, p.prosecdef as definer,
    oidvectortypes(p.proargtypes) as args,
    array(select r.role from (values ('anon'),('authenticated'),('service_role'),('supabase_auth_admin')) r(role)
      where has_schema_privilege(r.role,n.oid,'usage') and has_function_privilege(r.role,p.oid,'execute')) as roles,
    pg_get_functiondef(p.oid) as definition
  from pg_proc p join pg_namespace n on n.oid=p.pronamespace
  where n.nspname in ('public','graphql_public','sectalk_private') and p.prokind='f'
)
select jsonb_build_object('functions',jsonb_agg(to_jsonb(entry) - 'oid'
    order by schema,name,args),
  'direct_message_rls', (select c.relrowsecurity from pg_class c where c.oid='public.st_messages'::regclass),
  'schema_override', (select o from pg_db_role_setting s join pg_roles r on r.oid=s.setrole,
    lateral unnest(s.setconfig) o where r.rolname='authenticator' and o like 'pgrst.db_schemas=%'
    order by s.setdatabase desc limit 1),
  'pre_request', (select o from pg_db_role_setting s join pg_roles r on r.oid=s.setrole,
    lateral unnest(s.setconfig) o where r.rolname='authenticator' and o like 'pgrst.db_pre_request=%'
    order by s.setdatabase desc limit 1))
from entry;
`

const publicExceptions={
  'graphql_public.graphql(text, text, jsonb, jsonb)':'GraphQL gateway. Table grants and row-level security apply to the caller.',
  'public.st_v6_plan_catalog()':'Published plan metadata.',
  'public.st_v6_ready()':'Service readiness boolean.',
  'public.st_v8_release_ready(text)':'Schema readiness boolean for Web, Admin or Workers. Calls no job or provider.',
  'public.st_v7_public_plan_entitlements()':'Entitlement metadata for published, publicly visible plans.',
  'public.st_v7_guard_account_lockdown()':'PostgREST pre-request guard. Applies account and native assurance restrictions.',
  'public.st_v8_residency_target_ready(uuid, text, uuid)':'Boolean installation proof for an exact cell, project and private installation nonce. It requires the deployment marker and a private Storage bucket.',
}
const authHook='public.st_v7_before_signup(jsonb)'
const invokerExceptions={
  'public.st_v2_search_messages(uuid, text)':{gate:'Invoker RLS',evidence:['public.st_messages row-level security']},
  'public.st_v6_direct_timer_policy()':{gate:'Authenticated metadata',evidence:['Read-only duration limits']},
}
const external=new Set(['public','graphql_public'])
const applicationRoles=new Set(['anon','authenticated','service_role'])
const callPattern=/\b(auth|public|sectalk_private)\.([a-z_][a-z_\d]*)\s*\(/gi
const authorityName=/(?:^|_)(?:authorize|authorized|permitted|active|access|may|can|allowed|visible|visibility|role|member|participant|owner|holder|guard|entitled|verified|proof|scope|eligible|session|assurance|limit_action)(?:_|$)/

function rpcName(item){return item.schema+'.'+item.name+'('+item.args+')'}
function namedCalls(item) {
  const body=item.definition.slice(item.definition.indexOf('\n')+1)
  return [...new Set([...body.matchAll(callPattern)].map(match=>match[1]+'.'+match[2]))].sort()
}
function readDb() {
  const container=process.env.SECTALK_RPC_QA_CONTAINER||'supabase_db_v4-auth-qa'
  if(!/^supabase_db_[\w-]+$/.test(container))throw new Error('Use a local Supabase QA database container.')
  const rest=container.replace(/^supabase_db_/,'supabase_rest_')
  const config=JSON.parse(execFileSync('docker',['inspect',rest,'--format','{{json .Config.Env}}'],
    {encoding:'utf8',stdio:['ignore','pipe','ignore'],windowsHide:true}))
  const prefix='PGRST_DB_SCHEMAS='
  const configured=config.find(item=>item.startsWith(prefix))?.slice(prefix.length)
  const output=execFileSync('docker',['exec','-i',container,'psql','-X','-A','-t','-v','ON_ERROR_STOP=1','-U','postgres','-d','postgres'],
    {input:query,encoding:'utf8',maxBuffer:12*1024*1024,windowsHide:true})
  const data=JSON.parse(output)
  const schemas=(data.schema_override?.split('=')[1]??configured??'').split(',').map(name=>name.trim()).sort()
  if(schemas.join(',')!==[...external].sort().join(','))
    throw new Error('Review changed PostgREST exposed schemas: '+schemas.join(','))
  return data
}
export function liveRpcInventory() {
  const data=readDb()
  if(data.pre_request!=='pgrst.db_pre_request=public.st_v7_guard_account_lockdown')
    throw new Error('Native PostgREST pre-request authorization is unbound.')
  const byName=new Map()
  for(const item of data.functions){
    const ref=item.schema+'.'+item.name
    byName.set(ref,[...(byName.get(ref)??[]),item])
  }
  function evidence(item,visited=new Set()){
    const signature=rpcName(item)
    if(visited.has(signature)) return []
    const seen=new Set([...visited,signature])
    const calls=namedCalls(item)
    const identity=calls.filter(call=>call==='auth.uid'||call==='auth.jwt'||call==='auth.role')
    const guards=calls.filter(call=>call.startsWith('sectalk_private.')&&authorityName.test(call.split('.')[1])
      ||call.startsWith('public.')&&authorityName.test(call.split('.')[1]))
    if(identity.length||guards.length)return [...identity,...guards].slice(0,6)
    for(const call of calls){
      for(const nested of byName.get(call)??[]){
        const delegated=evidence(nested,seen)
        if(delegated.length)return [call,...delegated].slice(0,6)
      }
    }
    return []
  }
  return data.functions.filter(item=>external.has(item.schema)&&(
    item.roles.some(role=>applicationRoles.has(role))||rpcName(item)===authHook))
    .map(item=>{
      const rpc=rpcName(item)
      const roles=item.roles.filter(role=>applicationRoles.has(role)||rpc===authHook)
      const review=createHash('sha256').update(item.definition.replace(/\r\n/g,'\n')).digest('hex')
      const base={rpc,roles,security:item.definer?'definer':'invoker',review}
      if(item.roles.includes('anon')){
        if(!Object.hasOwn(publicExceptions,rpc))throw new Error('Unreviewed anonymous RPC '+rpc)
        return {...base,gate:'Public exception',evidence:[publicExceptions[rpc]]}
      }
      if(rpc===authHook){
        if(roles.length!==1||roles[0]!=='supabase_auth_admin')throw new Error('Native signup hook is callable via PostgREST.')
        return {...base,gate:'Native Auth hook',evidence:['Signup admission permit']}
      }
      if(!roles.includes('authenticated')) {
        return {...base,gate:'Service credential',evidence:['Effective service_role execute grant']}
      }
      if(Object.hasOwn(invokerExceptions,rpc)){
        if(item.definer||(rpc.startsWith('public.st_v2_search_messages(')&&!data.direct_message_rls))
          throw new Error('Invoker or table authorization changed for '+rpc)
        return {...base,...invokerExceptions[rpc]}
      }
      const witnessed=evidence(item)
      return {...base,
        gate:witnessed.length?(item.definer?'Database scope':'Delegated scope'):'Unclassified',evidence:witnessed}
    })
}

if(process.argv[1]&&pathToFileURL(process.argv[1]).href===import.meta.url) {
  const result=liveRpcInventory()
  const missing=result.filter(item=>item.gate==='Unclassified')
  if(missing.length)throw new Error('Classify remaining RPCs: '+missing.map(item=>item.rpc).join(', '))
  if(process.argv.includes('--write')) {
    writeFileSync(inventoryPath,'[\n'+result.map(item=>'  '+JSON.stringify(item)).join(',\n')+'\n]\n')
  } else {
    const expected=new Map(rpcInventory().map(entry=>[entry.rpc,entry]))
    const mismatches=result.filter(entry=>JSON.stringify(expected.get(entry.rpc))!==JSON.stringify(entry))
    const live=new Set(result.map(entry=>entry.rpc))
    const removed=[...expected.keys()].filter(rpc=>!live.has(rpc))
    if(mismatches.length||removed.length) {
      throw new Error('RPC inventory differs from live database: '+[...mismatches.map(entry=>entry.rpc),...removed].join(', '))
    }
    console.log('Verified '+result.length+' live RPC signatures against the checked-in inventory.')
  }
}
