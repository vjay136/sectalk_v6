import { createClient } from '@supabase/supabase-js'
import { supabaseApiFetch } from './supabase-api-fetch.mjs'

export const fileHeaders={'Cache-Control':'private, no-store','X-Content-Type-Options':'nosniff','Referrer-Policy':'no-referrer'}
export const fileAuthOptions={auth:{persistSession:false,autoRefreshToken:false}}

export function fileFailure(status:number,message:string){
  return Response.json({error:message},{status,headers:fileHeaders})
}

export async function authenticateFileRequest(request:Request,scope?:{type:'workspace'|'room';id:string}){
  const url=process.env.NEXT_PUBLIC_SUPABASE_URL
  const publicKey=process.env.NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY
  const storageKey=process.env.SECTALK_FILE_STORAGE_KEY
  if(!url||!publicKey||!storageKey)return fileFailure(503,'Attachments are unavailable.')
  const jwt=request.headers.get('Authorization')?.match(/^Bearer (\S+)$/i)?.[1]
  if(!jwt)return fileFailure(401,'Sign in to access attachments.')
  const client=createClient(url,publicKey,{...fileAuthOptions,global:{headers:{Authorization:'Bearer '+jwt}}})
  const {data,error}=await client.auth.getUser(jwt)
  if(error||!data.user)return fileFailure(401,'Sign in to access attachments.')
  const target=new URL(request.url)
  const read=request.method==='GET'||request.method==='HEAD'||target.pathname==='/api/files/download'
    ||(scope?.type==='workspace'&&['view','share'].includes(target.searchParams.get('action')??''))
  const action=read?'file_read':target.pathname==='/api/files/resumable'?'file_chunk':'file_write'
  const admission=await client.rpc('st_v7_admit_file_request',{
    p_action:action,p_scope_type:scope?.type??null,p_scope:scope?.id??null,
  }).abortSignal(AbortSignal.timeout(2000))
  if(admission.error||typeof admission.data!=='number')return fileFailure(503,'Attachment access is temporarily unavailable.')
  if(admission.data>0)return Response.json({error:'Too many attachment requests. Try again shortly.'},{
    status:429,headers:{...fileHeaders,'Retry-After':String(admission.data)},
  })
  return {actor:data.user.id,client,storage:createClient(url,storageKey,{
    ...fileAuthOptions,global:{fetch:supabaseApiFetch(storageKey)},
  })}
}
