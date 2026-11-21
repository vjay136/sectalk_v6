import assert from 'node:assert/strict'
import childProcess from 'node:child_process'
import {syncBuiltinESMExports} from 'node:module'
import {randomUUID} from 'node:crypto'
import {readFile,writeFile} from 'node:fs/promises'

const endpoint=new URL(process.env.SECTALK_AUDIT_TEST_ENDPOINT)
assert.equal(endpoint.hostname,'127.0.0.1')
assert.equal(endpoint.protocol,'http:')
const nativeExec=childProcess.execFile
const database=process.env.SECTALK_AUDIT_TEST_DB_CONTAINER??'supabase_db_sectalk-dr-source'
assert.match(database,/^supabase_db_sectalk-dr-[a-z0-9-]{1,32}$/)
const result=(callback,promise)=>void promise.then(stdout=>callback(null,{stdout}),callback)
const option=(args,name)=>args[args.indexOf(name)+1]

childProcess.execFile=function(file,args,options,callback) {
  if (file==='aws') {
    return result(callback,(async()=>{
      assert.equal(args[0],'s3api')
      assert.equal(option(args,'--bucket'),'sectalk-audit-loopback')
      assert.equal(option(args,'--expected-bucket-owner'),'123456789012')
      assert.equal(option(args,'--output'),'json')
      assert.ok(args.includes('--no-cli-pager'))
      const operation=args[1]
      const body=operation==='put-object'?
        (await readFile(option(args,'--body'))).toString('base64'):null
      const response=await fetch(new URL('/'+operation,endpoint),{method:'POST',
        headers:{'Content-Type':'application/json'},body:JSON.stringify({args,body})})
      assert.ok(response.ok,'The independent fixture rejected '+operation)
      const data=await response.json()
      if (operation==='get-object') {
        await writeFile(args.at(-1),Buffer.from(data.body,'base64'))
        delete data.body
      }
      return JSON.stringify(data)
    })())
  }
  assert.equal(file,'psql')
  assert.ok(args.includes('--dbname=service=sectalk_test_readonly'))
  const query=option(args,'--command')
  assert.match(query,/^select sectalk_private\.st_v8_audit_checkpoint\((?:'\d{1,19}','[a-f0-9]{64}')?\)$/)
  const identity=randomUUID()
  const workspace=randomUUID()
  const number=9000000000000000n+BigInt('0x'+identity.slice(0,8))
  const advance=process.env.SECTALK_AUDIT_TEST_ADVANCE==='yes'?`
    insert into auth.users(id,email,created_at,updated_at)
      values('${identity}','${identity}@example.invalid',now(),now());
    insert into public.st_profiles(id,handle,name)
      values('${identity}','audit_${identity.slice(0,8)}','Audit fixture');
    insert into public.st_v2_workspaces(id,name,owner)
      values('${workspace}','Audit verification fixture','${identity}');
    insert into public.st_v2_workspace_audit(id,workspace_id,actor,event) overriding system value
      values(${number},'${workspace}','${identity}','workspace.created');`:''
  const sql=`begin;
    grant sectalk_audit_anchor_reader to current_user with set true;
    ${advance}
    set local role sectalk_audit_anchor_reader;
    ${query};
    rollback;`
  return result(callback,new Promise((resolve,reject)=>{
    nativeExec('docker',['exec',database,'psql','-X','-qAt','-U','postgres','-d','postgres',
      '-v','ON_ERROR_STOP=1','-c',sql],options,(error,stdout,stderr)=>{
      if (error) {
        const reason=/SecTalk audit anchor mismatch at entry \d+/.test(stderr)?'anchor-mismatch':'unrelated-error'
        fetch(new URL('/native-error',endpoint),{method:'POST',body:JSON.stringify({reason})})
          .then(()=>reject(error),reject)
      }
      else resolve(stdout)
    })
  }))
}
syncBuiltinESMExports()
