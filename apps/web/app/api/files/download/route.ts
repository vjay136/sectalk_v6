import { type SupabaseClient } from '@supabase/supabase-js'
import { fileTicketSeconds, issueFileTicket, readFileTicket, validFileId } from '../../../../lib/file-download-ticket'
import { authenticateFileRequest, fileFailure as failure, fileHeaders as headers } from '../../../../lib/authenticated-file-request'

export const runtime='nodejs'

async function checkAccess(client:SupabaseClient,file:string){
  const {data,error}=await client.rpc('st_v6_file_can_read',{p_file:file})
  if(error?.code==='PT429')return failure(429,'Too many attachment requests. Try again in a minute.')
  if(error)return failure(503,'Attachment permissions could not be verified.')
  if(data!==true)return failure(404,'Attachment unavailable.')
  return null
}

export async function POST(request:Request){
  const secret=process.env.SECTALK_FILE_TICKET_SECRET
  if(!secret||Buffer.byteLength(secret)<32)return failure(503,'Attachment downloads are unavailable.')
  const auth=await authenticateFileRequest(request)
  if(auth instanceof Response)return auth
  const input=await request.json().catch(()=>null)
  if(!validFileId(input?.file))return failure(400,'Choose a valid attachment.')
  const denied=await checkAccess(auth.client,input.file)
  if(denied)return denied
  const ticket=issueFileTicket(input.file,auth.actor,secret)
  return Response.json({url:'/api/files/download?ticket='+ticket,expiresIn:fileTicketSeconds},{headers})
}

export async function GET(request:Request){
  const secret=process.env.SECTALK_FILE_TICKET_SECRET
  if(!secret||Buffer.byteLength(secret)<32)return failure(503,'Attachment downloads are unavailable.')
  const auth=await authenticateFileRequest(request)
  if(auth instanceof Response)return auth
  const ticket=readFileTicket(new URL(request.url).searchParams.get('ticket')||'',auth.actor,secret)
  if(!ticket)return failure(404,'Attachment unavailable. Request a new download link.')
  const denied=await checkAccess(auth.client,ticket.file)
  if(denied)return denied
  const {data,error}=await auth.storage.storage.from('sectalk-chat-files').download(ticket.file)
  if(error||!data)return failure(404,'Attachment unavailable.')
  const {error:logError}=await auth.storage.rpc('st_v6_log_file_download',{p_file:ticket.file,p_actor:auth.actor,p_ticket:ticket.nonce})
  if(logError)return failure(503,'Attachment download could not be recorded.')
  return new Response(data,{headers:{...headers,'Content-Type':'application/octet-stream','Content-Disposition':'attachment'}})
}
