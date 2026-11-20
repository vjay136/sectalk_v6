import assert from 'node:assert/strict'
import {readFileSync,readdirSync} from 'node:fs'
import {join,relative,resolve,sep} from 'node:path'
import {fileURLToPath} from 'node:url'
import ts from 'typescript'
import {databaseEntryPoints,entrypoints,pendingPermissionRoles,permissions,renderPermissionMatrix,roles} from '../scripts/permission-matrix.mjs'
import {rpcInventory} from '../scripts/rpc-permission-inventory.mjs'

const root=fileURLToPath(new URL('../',import.meta.url))
const api=join(root,'apps/web/app/api')
const acceptedMethods=new Set(['GET','HEAD','POST','PUT','PATCH','DELETE','OPTIONS'])
function filesBelow(directory,name){
  return readdirSync(directory,{withFileTypes:true}).flatMap(entry=>{
    const file=join(directory,entry.name)
    return entry.isDirectory()?filesBelow(file,name):name(entry.name)?[file]:[]
  })
}
function guardsByMethod(file) {
  const source=ts.createSourceFile(file,readFileSync(file,'utf8'),ts.ScriptTarget.Latest,true,ts.ScriptKind.TS)
  const declarations=new Map()
  const exported=new Map()
  for (const statement of source.statements) {
    const isExport=statement.modifiers?.some(modifier=>modifier.kind===ts.SyntaxKind.ExportKeyword)
    if (ts.isFunctionDeclaration(statement)&&statement.name&&statement.body) {
      declarations.set(statement.name.text,statement.body)
      if(isExport&&acceptedMethods.has(statement.name.text))exported.set(statement.name.text,statement.body)
    }
    if(ts.isVariableStatement(statement))for(const declaration of statement.declarationList.declarations){
      if(!ts.isIdentifier(declaration.name)||!declaration.initializer)continue
      declarations.set(declaration.name.text,declaration.initializer)
      if(isExport&&acceptedMethods.has(declaration.name.text))exported.set(declaration.name.text,declaration.initializer)
    }
    if(ts.isExportDeclaration(statement)&&statement.exportClause&&ts.isNamedExports(statement.exportClause)) {
      for(const specifier of statement.exportClause.elements)if(acceptedMethods.has(specifier.name.text))
        exported.set(specifier.name.text,specifier.propertyName??specifier.name)
    }
  }
  return new Map([...exported].map(([method,tree])=>{
    const calls=new Set()
    const visited=new Set()
    function walk(node){
      if(visited.has(node))return
      visited.add(node)
      if(ts.isIdentifier(node)&&declarations.has(node.text))walk(declarations.get(node.text))
      if(ts.isCallExpression(node)){
        if(ts.isIdentifier(node.expression))calls.add(node.expression.text)
        if(ts.isPropertyAccessExpression(node.expression)){
          const name=node.expression.name.text
          calls.add(name)
          if(name==='rpc'&&node.arguments[0]&&ts.isStringLiteral(node.arguments[0]))calls.add('rpc:'+node.arguments[0].text)
        }
      }
      ts.forEachChild(node,walk)
    }
    walk(tree)
    return [method,calls]
  }))
}

const routes=new Map()
for(const file of filesBelow(api,name=>name==='route.ts')){
  const path=relative(api,file).split(sep).slice(0,-1).join('/')
  const methods=guardsByMethod(file)
  assert.ok(methods.size,'No HTTP methods found for '+path)
  for(const [method,guards] of methods)routes.set(method+' '+path,guards)
}
const documented=new Set()
const mapped=new Set()
const lacking=[]
for(const entry of entrypoints) {
  const id=entry.method+' '+entry.path
  assert.ok(!documented.has(id),'Duplicate route entry '+id)
  documented.add(id)
  const guards=routes.get(id)
  assert.ok(guards,'Documented endpoint does not exist '+id)
  assert.ok(entry.mode==='Public'?entry.details:entry.guards.length,'Missing explicit authorization or public purpose for '+id)
  for(const guard of entry.guards)if(!guards.has(guard))lacking.push(id+' → '+guard)
  for(const permission of entry.permissions) {
    assert.ok(permissions[permission],'Uncatalogued endpoint permission '+permission+' in '+id)
    mapped.add(permission)
  }
}
assert.deepEqual([...routes.keys()].filter(route=>!documented.has(route)),[],'New endpoint needs authorization inventory')
assert.deepEqual(lacking,[],'Endpoint no longer calls the listed authorization guard')
const source=filesBelow(join(root,'supabase/migrations'),name=>name.endsWith('.sql'))
  .map(file=>readFileSync(file,'utf8')).join('\n')
for(const [permission,fn] of Object.entries(databaseEntryPoints)){
  assert.ok(permissions[permission],'Uncatalogued database permission '+permission)
  assert.match(source,new RegExp('create (?:or replace )?function public\\.'+fn+'\\s*\\(','i'),
    'Direct runtime authorization entry point is missing '+fn)
  mapped.add(permission)
}
for(const id of ['messaging.message.send','messaging.message.delete_any','room.member.remove','call.record.start',
  'file.download','file.share_external','admin.user.suspend','soc.action.quarantine','billing.invoice.refund','audit.log.read','policy.write']){
  assert.ok(permissions[id],'Missing Section 7.2 permission '+id)
}
for(const [id,description] of Object.entries(permissions)){
  const pending=pendingPermissionRoles[id]
  assert.ok(mapped.has(id)||pending&&description.startsWith('Pending.'),'Permission is neither mapped nor explicitly pending '+id)
  if(pending) {
    assert.ok(!mapped.has(id)&&pending.surface&&pending.roles.length,'Pending permission incorrectly appears granted '+id)
    for(const role of pending.roles)assert.ok(Object.hasOwn(roles,role),'Unknown intended role '+role)
  }
}
const liveCatalog=readFileSync(join(root,'supabase/migrations/20261120153922_sectalk_v7_permission_catalog.sql'),'utf8')
  .match(/create function public\.st_v7_permission_catalog\([\s\S]*?end \$\$;/)?.[0]
assert.ok(liveCatalog,'The live catalog function is missing')
for(const [,id] of liveCatalog.matchAll(/'([a-z_]+(?:\.[a-z_]+)+)'/g)){
  assert.ok(Object.hasOwn(permissions,id),'Live permission catalog returned an unmapped permission '+id)
}
for(const role of ['owner','admin','security_admin','billing_admin','compliance_officer','soc_lead','soc_analyst','moderator',
  'member','guest','managed_member','guardian/teacher','platform_operator','platform_security']){
  assert.ok(roles[role],'Missing Section 7.1 role '+role)
}
const inventory=rpcInventory()
assert.equal(new Set(inventory.map(entry=>entry.rpc)).size,inventory.length,'Duplicate native RPC signatures')
for(const entry of inventory) {
  assert.ok(entry.roles.length&&entry.evidence.length&&entry.gate!=='Unclassified','Native RPC lacks an authorization mapping: '+entry.rpc)
  assert.match(entry.review,/^[a-f0-9]{64}$/)
}
for(const fn of Object.values(databaseEntryPoints)) {
  assert.ok(inventory.some(entry=>entry.rpc.startsWith('public.'+fn+'(')),'Catalog references an unavailable direct RPC: '+fn)
}
assert.equal(readFileSync(resolve(root,'docs/spec/permission-matrix.md'),'utf8'),renderPermissionMatrix(),
  'Regenerate the checked-in permission matrix')
console.log('Permission coverage passed for '+mapped.size+' live permissions, '+routes.size+' HTTP methods, and '+inventory.length+' native signatures.')
