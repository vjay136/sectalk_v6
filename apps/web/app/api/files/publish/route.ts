import { authenticateFileRequest, fileFailure, fileHeaders } from '../../../../lib/authenticated-file-request'
import { validFileId } from '../../../../lib/file-download-ticket'
import { allowedFileType } from '../../../../lib/file-type-policy'

export const runtime='nodejs'

export async function POST(request:Request){
  const auth=await authenticateFileRequest(request)
  if(auth instanceof Response)return auth
  const input=await request.json().catch(()=>null)
  if(!validFileId(input?.file)||typeof input.caption!=='string'||[...input.caption].length>4000||
    typeof input.mime!=='string'||input.mime.length>100)return fileFailure(400,'Invalid attachment request.')
  const pending=await auth.client.rpc('st_v6_pending_file',{p_file:input.file})
  if(pending.error?.code==='PT429')return fileFailure(429,'Too many attachments. Try again in a minute.')
  if(pending.error)return fileFailure(503,'Attachment permissions could not be verified.')
  if(!pending.data)return fileFailure(404,'Attachment unavailable.')
  if(pending.data.published)return Response.json({id:pending.data.published},{headers:fileHeaders})
  const {data,error}=await auth.storage.storage.from('sectalk-chat-files').download(input.file)
  if(error||!data||data.size!==pending.data.size)return fileFailure(409,'Attachment upload is incomplete.')
  if(!allowedFileType(pending.data.filename,input.mime,Buffer.from(await data.arrayBuffer())))
    return fileFailure(415,'The file contents do not match an allowed attachment type.')
  const publication=await auth.storage.rpc('st_v6_publish_validated_file',{p_file:input.file,p_actor:auth.actor,p_caption:input.caption})
  if(publication.error)return fileFailure(409,'The attachment could not be published.')
  return Response.json({id:publication.data},{headers:fileHeaders})
}
