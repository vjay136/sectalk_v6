import { createCipheriv,createDecipheriv,randomBytes } from 'node:crypto'
import { createClient } from '@supabase/supabase-js'
import { maxVoiceBytes,voiceSampleRate,voiceWave,voiceWaveform } from '../../../lib/voice-note-format'

export const runtime='nodejs'
const headers={'Cache-Control':'private, no-store',Vary:'Authorization'}
const uuid=/^[\da-f]{8}(?:-[\da-f]{4}){3}-[\da-f]{12}$/i
const fail=(status:number)=>Response.json({error:'Voice note unavailable.'},{status,headers})
const auth={persistSession:false,autoRefreshToken:false}
type Note={audio:string;speech:string|null;canTranscribe:boolean;expiresAt:string|null;done?:boolean}

function config() {
  const {NEXT_PUBLIC_SUPABASE_URL:url,NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY:key,VOICE_NOTE_SERVICE_KEY:service,
    VOICE_NOTE_ENCRYPTION_KEY:encryption,MEETING_CAPTIONS_WORKER_URL:worker,MEETING_CAPTIONS_WORKER_TOKEN:secret}=process.env
  if (!url || !key || !service || !encryption || !/^[\da-f]{64}$/i.test(encryption)) return null
  const endpoint=worker ? URL.parse(worker) : null
  const speech=endpoint?.protocol==='http:' && endpoint.hostname==='127.0.0.1' && endpoint.port &&
    endpoint.pathname==='/transcribe' && !endpoint.search && !endpoint.hash && !endpoint.username &&
    !endpoint.password && secret && secret.length>=24 ? {endpoint,secret} : null
  return {url,key,service,encryption:Buffer.from(encryption,'hex'),speech}
}

function seal(key:Buffer,scope:string,bytes:Uint8Array) {
  const nonce=randomBytes(12)
  const cipher=createCipheriv('aes-256-gcm',key,nonce)
  cipher.setAAD(Buffer.from(scope))
  return Buffer.concat([nonce,cipher.update(bytes),cipher.final(),cipher.getAuthTag()]).toString('base64')
}

function unseal(key:Buffer,scope:string,encoded:string) {
  const bytes=Buffer.from(encoded,'base64')
  if (bytes.length<28) throw new Error('Encrypted note is incomplete')
  const cipher=createDecipheriv('aes-256-gcm',key,bytes.subarray(0,12))
  cipher.setAAD(Buffer.from(scope))
  cipher.setAuthTag(bytes.subarray(-16))
  return Buffer.concat([cipher.update(bytes.subarray(12,-16)),cipher.final()])
}

async function context(request:Request) {
  const settings=config()
  if (!settings) return fail(503)
  const query=new URL(request.url).searchParams
  const chat=query.get('chat')?.toLowerCase()
  const message=query.get('message')?.toLowerCase()
  const jwt=request.headers.get('Authorization')?.match(/^Bearer (\S+)$/i)?.[1]
  if (!jwt) return fail(401)
  if (!chat || !message || !uuid.test(chat) || !uuid.test(message)) return fail(400)
  const client=createClient(settings.url,settings.key,{auth})
  const {data,error}=await client.auth.getUser(jwt)
  if (error || !data.user) return fail(401)
  const db=createClient(settings.url,settings.service,{auth})
  const scope='sectalk-voice-note/v1/'+chat+'/'+message
  async function command(action:string,values:Record<string,unknown>={}) {
    const result=await db.rpc('st_v6_voice_note_command',{p_action:action,p_actor:data.user!.id,p_chat:chat,p_message:message,...values})
    if (result.error) throw new Error('Voice note operation failed')
    return result.data
  }
  return {settings,query,scope,command}
}

export async function GET(request:Request) {
  if (!new URL(request.url).searchParams.size) {
    const settings=config()
    return Response.json({configured:Boolean(settings),speech:Boolean(settings?.speech)},{headers})
  }
  try {
    const scope=await context(request)
    if (scope instanceof Response) return scope
    const note=await scope.command('read') as Note|null
    if (!note) return fail(404)
    const bytes=unseal(scope.settings.encryption,scope.scope+'/pcm',note.audio)
    if (scope.query.get('mode')==='audio') {
      return new Response(voiceWave(bytes),{headers:{...headers,'Content-Type':'audio/wav','X-Content-Type-Options':'nosniff'}})
    }
    return Response.json({duration:bytes.length/(voiceSampleRate*2),waveform:voiceWaveform(bytes),
      transcript:note.speech?unseal(scope.settings.encryption,scope.scope+'/speech',note.speech).toString('utf8'):null,
      canTranscribe:Boolean(note.canTranscribe && scope.settings.speech),expiresAt:note.expiresAt},{headers})
  } catch { return fail(503) }
}

export async function POST(request:Request) {
  try {
    const scope=await context(request)
    if (scope instanceof Response) return scope
    if (scope.query.get('mode')==='transcribe') {
      const speech=scope.settings.speech
      if (!speech) return fail(503)
      const note=await scope.command('begin_speech') as Note|null
      if (!note) return fail(403)
      if (note.done) return new Response(null,{status:204,headers})
      const pcm=unseal(scope.settings.encryption,scope.scope+'/pcm',note.audio)
      const parts:string[]=[]
      const deadline=AbortSignal.any([request.signal,AbortSignal.timeout(30000)])
      for(let offset=0;offset<pcm.length;offset+=voiceSampleRate*2*5) {
        const chunk=Uint8Array.from(pcm.subarray(offset,offset+voiceSampleRate*2*5))
        if (chunk.length<1000) break
        const response=await fetch(speech.endpoint,{method:'POST',redirect:'error',signal:deadline,
          headers:{Authorization:'Bearer '+speech.secret,'X-Source-Language':'en'},body:chunk})
        if (!response.ok) return fail(503)
        const result=await response.json()
        if (typeof result?.text!=='string' || result.text.length>500) return fail(503)
        if (result.text.trim()) parts.push(result.text.trim())
      }
      const transcript=Buffer.from(parts.join(' ') || 'No speech was recognized.','utf8')
      if (transcript.length>4096) return fail(503)
      const saved=await scope.command('save_speech',{p_cipher:seal(scope.settings.encryption,scope.scope+'/speech',transcript)})
      return saved ? new Response(null,{status:204,headers}) : fail(403)
    }
    const size=Number(request.headers.get('Content-Length'))
    const seconds=Number(scope.query.get('timer') ?? 0)
    const speech=scope.query.get('speech')==='1'
    if (!Number.isInteger(size)||size<2000||size>maxVoiceBytes||size%2||
      ![0,60,3600,86400,604800].includes(seconds)||request.headers.get('Content-Type')!=='application/octet-stream'||
      (speech&&!scope.settings.speech)) return fail(400)
    const content=new Uint8Array(await request.arrayBuffer())
    if (content.length!==size) return fail(400)
    const result=await scope.command('create',{p_cipher:seal(scope.settings.encryption,scope.scope+'/pcm',content),p_speech:speech,p_seconds:seconds})
    return result ? new Response(null,{status:201,headers}) : fail(403)
  } catch { return fail(503) }
}
