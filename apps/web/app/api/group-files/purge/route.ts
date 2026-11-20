import { timingSafeEqual } from 'node:crypto'
import { createClient } from '@supabase/supabase-js'
import { fileAuthOptions,fileHeaders } from '../../../../lib/authenticated-file-request'

export const runtime='nodejs'
export const maxDuration=60

export async function POST(request:Request) {
  const url=process.env.NEXT_PUBLIC_SUPABASE_URL
  const key=process.env.SECTALK_FILE_STORAGE_KEY
  const secret=process.env.SECTALK_FILE_PURGE_SECRET
  if(!url||!key||!secret||Buffer.byteLength(secret)<32)return new Response(null,{status:503,headers:fileHeaders})
  const expected=Buffer.from('Bearer '+secret)
  const supplied=Buffer.from(request.headers.get('authorization')||'')
  if(supplied.length!==expected.length||!timingSafeEqual(supplied,expected))return new Response(null,{status:401,headers:fileHeaders})
  const service=createClient(url,key,{...fileAuthOptions,global:{
    fetch:(input,options)=>fetch(input,{...options,signal:AbortSignal.timeout(5000)}),
  }})
  const claim=await service.rpc('st_v7_claim_group_file_cleanup')
  if(claim.error)return new Response(null,{status:503,headers:fileHeaders})
  const files=claim.data as {id:string;lease:string}[]
  const storage=service.storage.from('sectalk-encrypted-group-files')
  const removed=files.length?await storage.remove(files.map(file=>file.id)):null
  if(removed?.error)return new Response(null,{status:503,headers:fileHeaders})
  const outcomes=await Promise.allSettled(files.map(file=>service.rpc('st_v7_finish_group_file_cleanup',{p_file:file.id,p_lease:file.lease})))
  const purged=outcomes.filter(outcome=>outcome.status==='fulfilled'&&outcome.value.data===true).length
  return Response.json({claimed:files.length,purged},{status:purged===files.length?200:503,headers:fileHeaders})
}
