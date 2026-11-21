import assert from 'node:assert/strict'
import {execFile} from 'node:child_process'
import {createHash} from 'node:crypto'
import {createServer} from 'node:http'
import {fileURLToPath,pathToFileURL} from 'node:url'
import {promisify} from 'node:util'

// Start a migrated, clean local Supabase database-only project named sectalk-dr-* first.
// The AWS command fixture exercises the retention contract without contacting a real provider.
const worker=fileURLToPath(new URL('../scripts/audit-anchor.mjs',import.meta.url))
const fixture=pathToFileURL(fileURLToPath(new URL('./audit-anchor-command-fixture.mjs',import.meta.url))).href
const execute=promisify(execFile)
const receipts=new Map()
const prefix='local-release/audit-v1/'
const checksum=body=>createHash('sha256').update(body).digest('base64')
const option=(args,name)=>args[args.indexOf(name)+1]
let posture='normal',puts=0,problem
const nativeErrors=[]

const store=createServer(async(request,response)=>{
  response.setHeader('Content-Type','application/json')
  const reply=(status,body)=>response.writeHead(status).end(JSON.stringify(body))
  try {
    assert.equal(request.method,'POST')
    let text=''
    for await(const chunk of request)text+=chunk
    const input=JSON.parse(text)
    const operation=request.url.slice(1)
    if (operation==='native-error') {
      nativeErrors.push(input.reason)
      return reply(200,{})
    }
    const {args,body}=input
    if (operation==='list-objects-v2') {
      assert.equal(option(args,'--prefix'),prefix)
      assert.equal(option(args,'--max-items'),'50000')
      return reply(200,{Contents:[...receipts.keys()].reverse().map(Key=>({Key})),
        IsTruncated:posture==='truncated'})
    }
    const key=option(args,'--key')
    assert.match(key,/^local-release\/audit-v1\/[0-9]{19}\.json$/)
    const saved=receipts.get(key)
    if (operation==='head-object')
      return reply(200,{ContentLength:saved.bytes.length,VersionId:posture==='unversioned'?'null':saved.version})
    if (operation==='get-object') {
      assert.equal(option(args,'--version-id'),saved.version)
      assert.equal(option(args,'--checksum-mode'),'ENABLED')
      const bytes=Buffer.from(saved.bytes)
      if (posture==='corrupt') bytes[0]^=1
      return reply(200,{body:bytes.toString('base64'),ObjectLockMode:posture==='governance'?'GOVERNANCE':'COMPLIANCE',
        ObjectLockRetainUntilDate:posture==='expired'?'2000-01-01T00:00:00Z':saved.retainUntil,
        ChecksumSHA256:checksum(saved.bytes)})
    }
    assert.equal(operation,'put-object')
    puts++
    assert.equal(option(args,'--if-none-match'),'*')
    assert.equal(option(args,'--object-lock-mode'),'COMPLIANCE')
    assert.equal(option(args,'--content-type'),'application/json')
    assert.equal(option(args,'--checksum-algorithm'),'SHA256')
    const bytes=Buffer.from(body,'base64')
    assert.equal(option(args,'--checksum-sha256'),checksum(bytes))
    const receipt=JSON.parse(bytes)
    assert.deepEqual(Object.keys(receipt),['entry','sha256'])
    assert.match(receipt.sha256,/^[a-f0-9]{64}$/)
    assert.equal(key,prefix+receipt.entry.padStart(19,'0')+'.json')
    const retainUntil=option(args,'--object-lock-retain-until-date')
    assert.ok(Math.abs(Date.parse(retainUntil)-Date.now()-31*86400000)<10000)
    if (saved) return reply(412,{error:'PreconditionFailed'})
    receipts.set(key,{bytes,retainUntil,version:'protected-version-'+puts})
    return posture==='lost-ack'?reply(503,{error:'AcknowledgmentLost'}):reply(200,{VersionId:'protected-version-'+puts})
  } catch(error) {
    problem??=error
    return reply(500,{error:'Fixture contract violation'})
  }
})

await new Promise((resolve,reject)=>store.once('error',reject).listen(0,'127.0.0.1',resolve))
const base={
  ...process.env,
  SECTALK_AUDIT_PG_SERVICE:'sectalk_test_readonly',
  SECTALK_AUDIT_RECEIPT_BUCKET:'sectalk-audit-loopback',
  SECTALK_AUDIT_RECEIPT_OWNER:'123456789012',
  SECTALK_AUDIT_RECEIPT_NAMESPACE:'local-release',
  SECTALK_AUDIT_RECEIPT_DAYS:'31',
  SECTALK_AUDIT_TEST_ENDPOINT:'http://127.0.0.1:'+store.address().port,
}
const run=async(action,advance=false)=>JSON.parse((await execute(process.execPath,['--import',fixture,worker,action],{
  env:{...base,SECTALK_AUDIT_TEST_ADVANCE:advance?'yes':'no'},timeout:40000,windowsHide:true,
})).stdout)
const rejects=(action,message)=>assert.rejects(()=>run(action),error=>error.code===1&&message.test(error.stderr))

try {
  await rejects('verify-and-anchor',/No independent audit receipt/)
  const original=await run('bootstrap')
  assert.equal(original.status,'anchored')
  assert.equal(puts,1)
  await rejects('bootstrap',/already initialized/)
  assert.deepEqual(await run('verify-and-anchor'),{...original,status:'verified'})
  for (const [mode,message] of [
    ['truncated',/inventory exceeded/],['unversioned',/metadata is invalid/],
    ['expired',/not protected by active Object Lock/],['governance',/not protected by active Object Lock/],
    ['corrupt',/Unexpected token|checksum or identity mismatch/],
  ]) {
    posture=mode
    await rejects('verify-and-anchor',message)
    assert.equal(puts,1)
  }
  posture='lost-ack'
  const ahead=await run('verify-and-anchor',true)
  assert.equal(ahead.status,'anchored')
  assert.ok(BigInt(ahead.entry)>BigInt(original.entry))
  assert.equal(puts,2)
  posture='normal'
  await rejects('verify-and-anchor',/native audit verifier rejected/)
  assert.deepEqual(nativeErrors,['anchor-mismatch'])
  assert.equal(puts,2)
  assert.equal(receipts.size,2)
  assert.ifError(problem)
  console.log('Verified production audit-worker command contract, retention and version checks, lost acknowledgment recovery, and native PostgreSQL rewind rejection.')
} finally {
  store.closeAllConnections()
  await new Promise(resolve=>store.close(resolve))
}
