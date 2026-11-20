import { createClient } from '@supabase/supabase-js'

export const fileHeaders={'Cache-Control':'private, no-store','X-Content-Type-Options':'nosniff','Referrer-Policy':'no-referrer'}
export const fileAuthOptions={auth:{persistSession:false,autoRefreshToken:false}}

export function fileFailure(status:number,message:string){
  return Response.json({error:message},{status,headers:fileHeaders})
}

export async function authenticateFileRequest(request:Request){
  const url=process.env.NEXT_PUBLIC_SUPABASE_URL
  const publicKey=process.env.NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY
  const storageKey=process.env.SECTALK_FILE_STORAGE_KEY
  if(!url||!publicKey||!storageKey)return fileFailure(503,'Attachments are unavailable.')
  const jwt=request.headers.get('Authorization')?.match(/^Bearer (\S+)$/i)?.[1]
  if(!jwt)return fileFailure(401,'Sign in to access attachments.')
  const client=createClient(url,publicKey,{...fileAuthOptions,global:{headers:{Authorization:'Bearer '+jwt}}})
  const {data,error}=await client.auth.getUser(jwt)
  if(error||!data.user)return fileFailure(401,'Sign in to access attachments.')
  return {actor:data.user.id,client,storage:createClient(url,storageKey,fileAuthOptions)}
}
