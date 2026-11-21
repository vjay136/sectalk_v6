import {createCipheriv,createDecipheriv,createHash,createHmac,randomBytes,randomUUID} from 'node:crypto'
import {isIP} from 'node:net'
import {createClient} from '@supabase/supabase-js'
import {vulnerabilityIntakeContact} from './security-disclosure'
import {readBoundedText} from './request-body'

const auth={persistSession:false,autoRefreshToken:false}
const states=['received','reviewing','resolved','dismissed']
const uuid=/^[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}$/i
const headers={'Cache-Control':'private, no-store','X-Content-Type-Options':'nosniff'}
const reply=(body:object,status=200,extra:Record<string,string>={})=>Response.json(body,{status,headers:{...headers,...extra}})
const reject=(error:string,status:number)=>reply({error},status)

function httpsOnly(request:Request) {
  const url=new URL(request.url)
  return url.protocol==='https:'||(process.env.SECTALK_DISCLOSURE_TEST_LOOPBACK==='yes'&&
    ['127.0.0.1','localhost'].includes(url.hostname)&&url.protocol==='http:')
}
function key() {
  const raw=process.env.SECTALK_DISCLOSURE_ENCRYPTION_KEY
  if (!raw||!/^[-_A-Za-z0-9]{43}$/.test(raw)) return null
  const bytes=Buffer.from(raw,'base64url')
  return bytes.length===32&&bytes.toString('base64url')===raw?bytes:null
}
function inputText(value:unknown,min:number,max:number) {
  if (typeof value!=='string') return null
  const text=value.trim()
  if (text.length<min||text.length>max||/[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F]/.test(text)) return null
  return text
}
function reportInput(value:unknown) {
  if (!value||typeof value!=='object'||Array.isArray(value)) return null
  const input=value as Record<string,unknown>
  if (Object.keys(input).some(name=>!['title','feature','details','contact'].includes(name))) return null
  const title=inputText(input.title,4,160),feature=inputText(input.feature,1,160),details=inputText(input.details,20,8000)
  const contact=inputText(input.contact??'',0,254)
  if (!title||!feature||!details||contact===null||(contact&&!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(contact))) return null
  return {title,feature,details,contact}
}
function aad(id:string) {return Buffer.from('sectalk-disclosure-v1:'+id,'utf8')}
function seal(secret:Buffer,id:string,data:object) {
  const nonce=randomBytes(12)
  const cipher=createCipheriv('aes-256-gcm',secret,nonce)
  cipher.setAAD(aad(id))
  const envelope=Buffer.concat([cipher.update(JSON.stringify(data),'utf8'),cipher.final()])
  return ['v1',nonce.toString('base64url'),cipher.getAuthTag().toString('base64url'),envelope.toString('base64url')].join('.')
}
function open(secret:Buffer,id:string,envelope:string) {
  const [version,vector,tag,body,...extra]=envelope.split('.')
  if (version!=='v1'||!/^[A-Za-z0-9_-]{16}$/.test(vector)||!/^[A-Za-z0-9_-]{22}$/.test(tag)||
    !/^[A-Za-z0-9_-]+$/.test(body)||extra.length) throw new Error('Invalid disclosure envelope')
  const cipher=createDecipheriv('aes-256-gcm',secret,Buffer.from(vector,'base64url'))
  cipher.setAAD(aad(id))
  cipher.setAuthTag(Buffer.from(tag,'base64url'))
  const decoded=Buffer.concat([cipher.update(Buffer.from(body,'base64url')),cipher.final()])
  const report=JSON.parse(decoded.toString('utf8'))
  const {receipt,...fields}=report
  const contents=reportInput(fields)
  if (!contents||typeof receipt!=='string'||!/^[-_A-Za-z0-9]{32}$/.test(receipt)) throw new Error('Invalid disclosure record')
  return {...contents,receipt}
}

export async function submitDisclosure(request:Request) {
  const project=process.env.NEXT_PUBLIC_SUPABASE_URL
  const service=process.env.SECTALK_DISCLOSURE_SERVICE_KEY
  const secret=key()
  if (!project||!service||!secret||!vulnerabilityIntakeContact()) return reject('Private vulnerability intake is unavailable.',503)
  if (!httpsOnly(request)) return reject('Use the HTTPS report form.',403)
  if (request.headers.get('content-type')?.split(';')[0].trim().toLowerCase()!=='application/json')
    return reject('Submit the report as plain text using the form.',415)
  try {
    const raw=await readBoundedText(request,12000)
    if (raw===undefined) return reject('The report is too large.',413)
    const contents=reportInput(JSON.parse(raw??'null'))
    if (!contents) return reject('Provide a valid title, affected feature and report. Check the optional email.',400)
    const id=randomUUID()
    const receipt=randomBytes(24).toString('base64url')
    const ip=process.env.VERCEL==='1'?request.headers.get('x-vercel-forwarded-for'):null
    const scope=ip&&isIP(ip)?createHmac('sha256',secret).update('sectalk-disclosure-rate:'+ip).digest('hex'):null
    const store=createClient(project,service,{auth})
    const result=await store.rpc('st_v8_disclosure_submit',{p_id:id,p_envelope:seal(secret,id,{...contents,receipt}),
      p_receipt:createHash('sha256').update(receipt).digest('hex'),p_scope:scope}).abortSignal(AbortSignal.timeout(5000))
    if (result.error) return reject('The report could not be saved. Try again later.',503)
    if (result.data==='limited') return reply({error:'Too many reports. Try again later.'},429,{'Retry-After':'900'})
    if (result.data!=='received') return reject('The report could not be saved.',503)
    return reply({receipt},201)
  } catch(error) {
    return error instanceof SyntaxError||error instanceof TypeError?reject('The report format is invalid.',400):
      reject('The report could not be saved. Try again later.',503)
  }
}

export async function disclosureQueue(request:Request) {
  const token=request.headers.get('authorization')?.match(/^Bearer ([^\s]+)$/)?.[1]
  const project=process.env.NEXT_PUBLIC_SUPABASE_URL
  const publishable=process.env.NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY
  const secret=key()
  if (!token||token.length>8192) return reject('Sign in as a disclosure operator.',401)
  if (!project||!publishable||!secret) return reject('The disclosure queue is unavailable.',503)
  if (!httpsOnly(request)) return reject('Open the disclosure queue over HTTPS.',403)
  const actor=createClient(project,publishable,{auth,global:{headers:{Authorization:'Bearer '+token}}})
  try {
    const identity=await actor.auth.getUser(token)
    if (identity.error||!identity.data.user) return reject('Sign in as a disclosure operator.',401)
    const raw=await readBoundedText(request,1024)
    if (raw===undefined) return reject('Queue request is too large.',413)
    let input
    try {input=JSON.parse(raw??'null')} catch {return reject('Invalid queue request.',400)}
    const {action,id,state}=input??{}
    if (!['list','open','move'].includes(action)||
      (action==='list'&&!states.includes(state)) ||
      (action!=='list'&&(typeof id!=='string'||!uuid.test(id))) ||
      (action==='move'&&(!states.includes(state)||state==='received')))
      return reject('Invalid queue request.',400)
    const invoke=(operation:string)=>actor.rpc('st_v8_disclosure_queue',{p_action:operation,p_id:id??null,p_state:state??null})
      .abortSignal(AbortSignal.timeout(5000))
    if (action==='move') {
      const original=await invoke('open')
      if (original.error?.code==='42501') return reject('Fresh disclosure operator verification is required.',403)
      if (original.error) return reject('The report could not be read.',503)
      if (!original.data) return reject('The report is unavailable.',404)
      open(secret,original.data.id,original.data.envelope)
    }
    const {error,data}=await invoke(action)
    if (error?.code==='42501') return reject('Fresh disclosure operator verification is required.',403)
    if (error) return reject('The queue is unavailable.',503)
    if (action==='list') return reply({reports:data})
    if (!data) return reject(action==='move'?'The report state changed. Refresh the queue.':'The report is unavailable.',action==='move'?409:404)
    if (action==='move') return reply({state:data.state})
    const {envelope,...report}=data
    return reply({report:{...report,...open(secret,report.id,envelope)}})
  } catch {return reject('The report could not be read. No report details were returned.',503)}
}
