import {execFile} from 'node:child_process'
import {createHash} from 'node:crypto'
import {mkdtemp,readFile,unlink,rmdir,writeFile} from 'node:fs/promises'
import {tmpdir} from 'node:os'
import {join} from 'node:path'
import {promisify} from 'node:util'
import {pathToFileURL} from 'node:url'

const execute=promisify(execFile)
const entryPattern=/^(0|[1-9][0-9]{0,18})$/
const digestPattern=/^[a-f0-9]{64}$/
const entryKey=/^([0-9]{19})\.json$/
const day=86400000

function validateReceipt(value) {
  if (!value || typeof value.entry!=='string' || typeof value.sha256!=='string' ||
    !entryPattern.test(value.entry) || !digestPattern.test(value.sha256)) throw new Error('Invalid audit receipt.')
  return {entry:value.entry,sha256:value.sha256}
}

export async function runAuditAnchor({database,store,initialize=false}) {
  const previous=await store.latest()
  if (!previous && !initialize) throw new Error('No independent audit receipt. Run an approved bootstrap first.')
  if (previous && initialize) throw new Error('The receipt namespace was already initialized.')
  const head=validateReceipt(await database.verify(previous))
  if (previous && (BigInt(head.entry)<BigInt(previous.entry) ||
    (head.entry===previous.entry&&head.sha256!==previous.sha256))) throw new Error('Audit checkpoint mismatch.')
  if (previous?.entry===head.entry) return {status:'verified',...head}
  await store.append(head)
  return {status:'anchored',...head}
}

function environment() {
  const {SECTALK_AUDIT_PG_SERVICE:service,SECTALK_AUDIT_RECEIPT_BUCKET:bucket,
    SECTALK_AUDIT_RECEIPT_OWNER:owner,SECTALK_AUDIT_RECEIPT_NAMESPACE:namespace,
    SECTALK_AUDIT_RECEIPT_DAYS:duration='365'}=process.env
  const days=Number(duration)
  if (!/^[a-zA-Z][a-zA-Z0-9_-]{0,63}$/.test(service??'') || !/^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$/.test(bucket??'') ||
    !/^\d{12}$/.test(owner??'') || !/^[a-z0-9][a-z0-9-]{3,59}$/.test(namespace??'') ||
    !Number.isInteger(days) || days<30 || days>3650) throw new Error('Invalid independent audit receipt configuration.')
  return {service,bucket,owner,prefix:`${namespace}/audit-v1/`,days}
}

async function command(file,args) {
  return (await execute(file,args,{timeout:25000,maxBuffer:16*1024*1024,windowsHide:true})).stdout
}

function postgres(service) {
  return {async verify(previous) {
    const receipt=previous ? validateReceipt(previous) : null
    const args=receipt ? `'${receipt.entry}','${receipt.sha256}'` : ''
    try {
      return JSON.parse(await command('psql',['--no-psqlrc','--no-align','--tuples-only','--set=ON_ERROR_STOP=1',
        '--dbname=service='+service,'--command',`select sectalk_private.st_v8_audit_checkpoint(${args})`]))
    } catch {
      throw new Error('The native audit verifier rejected the chain or could not be reached.')
    }
  }}
}

function s3({bucket,owner,prefix,days},directory) {
  async function aws(operation,parameters) {
    return JSON.parse(await command('aws',['s3api',operation,'--bucket',bucket,'--expected-bucket-owner',owner,
      '--no-cli-pager','--output','json','--cli-connect-timeout','7','--cli-read-timeout','10',...parameters]))
  }
  const keyFor=entry=>prefix+entry.padStart(19,'0')+'.json'
  const out=join(directory,'read.json')
  const body=join(directory,'write.json')

  async function read(key) {
    const head=await aws('head-object',['--key',key])
    if (!Number.isSafeInteger(head.ContentLength) || head.ContentLength<1 || head.ContentLength>256 ||
      typeof head.VersionId!=='string' || head.VersionId==='null') throw new Error('Receipt object metadata is invalid.')
    const metadata=await aws('get-object',['--key',key,'--version-id',head.VersionId,'--checksum-mode','ENABLED',out])
    const bytes=await readFile(out)
    if (metadata.ObjectLockMode!=='COMPLIANCE' || !Number.isFinite(Date.parse(metadata.ObjectLockRetainUntilDate)) ||
      Date.parse(metadata.ObjectLockRetainUntilDate)<=Date.now()) throw new Error('The independent receipt is not protected by active Object Lock.')
    const checksum=createHash('sha256').update(bytes).digest('base64')
    const receipt=validateReceipt(JSON.parse(bytes.toString('utf8')))
    if (bytes.length!==head.ContentLength || metadata.ChecksumSHA256!==checksum || key!==keyFor(receipt.entry)) {
      throw new Error('Independent receipt checksum or identity mismatch.')
    }
    return receipt
  }

  return {
    async latest() {
      const keys=await aws('list-objects-v2',['--prefix',prefix,'--max-items','50000'])
      if (keys.NextToken || keys.IsTruncated) throw new Error('The independent audit receipt inventory exceeded its configured bound.')
      const found=(keys.Contents??[]).map(item=>item.Key)
      if (found.some(key=>typeof key!=='string' || !key.startsWith(prefix) || !entryKey.test(key.slice(prefix.length)))) {
        throw new Error('Unexpected object in the independent receipt namespace.')
      }
      const latest=found.reduce((maximum,key)=>!maximum||key>maximum?key:maximum,null)
      return latest ? read(latest) : null
    },
    async append(receipt) {
      const key=keyFor(receipt.entry)
      const bytes=Buffer.from(JSON.stringify(receipt)+'\n')
      await writeFile(body,bytes,{flag:'wx',mode:0o600})
      try {
        await aws('put-object',['--key',key,'--if-none-match','*','--body',body,'--content-type','application/json',
          '--checksum-algorithm','SHA256','--checksum-sha256',createHash('sha256').update(bytes).digest('base64'),
          '--object-lock-mode','COMPLIANCE','--object-lock-retain-until-date',new Date(Date.now()+days*day).toISOString()])
      } catch {
        // A concurrent writer or an interrupted acknowledgment can leave an exact protected receipt.
      }
      const confirmed=await read(key)
      if (confirmed.sha256!==receipt.sha256) throw new Error('Conflicting immutable audit receipt.')
    },
  }
}

async function main() {
  const [action]=process.argv.slice(2)
  if (process.argv.length!==3 || !['bootstrap','verify-and-anchor'].includes(action)) {
    throw new Error('Choose bootstrap or verify-and-anchor.')
  }
  const config=environment()
  const temporary=await mkdtemp(join(tmpdir(),'sectalk-receipts-'))
  try {
    const result=await runAuditAnchor({database:postgres(config.service),store:s3(config,temporary),initialize:action==='bootstrap'})
    console.log(JSON.stringify({status:result.status,entry:result.entry,sha256:result.sha256}))
  } finally {
    for (const name of ['read.json','write.json']) await unlink(join(temporary,name)).catch(()=>{})
    await rmdir(temporary)
  }
}

if (process.argv[1] && import.meta.url===pathToFileURL(process.argv[1]).href) {
  main().catch(error=>{
    console.error(error?.code?'Independent audit receipt storage is unavailable.':error.message)
    process.exitCode=1
  })
}
