import { readAttachmentUpload } from '../../../lib/attachment-upload-body'
import { authenticateFileRequest,fileFailure,fileHeaders } from '../../../lib/authenticated-file-request'
import { validFileId } from '../../../lib/file-download-ticket'

export const runtime='nodejs'
export const maxDuration=30
const bucket='sectalk-encrypted-group-files'
const maxCipherBytes=4194332

export async function POST(request:Request) {
  const file=new URL(request.url).searchParams.get('file')
  if(!validFileId(file)||request.headers.get('content-type')!=='application/octet-stream'){
    return fileFailure(400,'Choose an encrypted attachment.')
  }
  const auth=await authenticateFileRequest(request)
  if(auth instanceof Response)return auth
  const permission=await auth.client.rpc('st_v7_group_file_access',{p_file:file,p_action:'upload'})
  if(permission.error)return fileFailure(503,'Could not verify access to this encrypted attachment.')
  const expected=permission.data
  if(!Number.isInteger(expected)||expected<29||expected>maxCipherBytes)return fileFailure(404,'Encrypted attachment unavailable.')
  const bytes=await readAttachmentUpload(request,expected).catch(()=>null)
  if(bytes===undefined)return fileFailure(413,'The upload exceeds its reserved size.')
  if(!bytes||bytes.length!==expected)return fileFailure(400,'The encrypted attachment is incomplete.')
  const lease=await auth.client.rpc('st_v7_lease_group_file_upload',{p_file:file,p_cipher_bytes:bytes.length})
  if(lease.error)return fileFailure(503,'Could not prepare the encrypted upload.')
  if(lease.data!==true)return fileFailure(404,'Encrypted attachment unavailable.')
  const storage=auth.storage.storage.from(bucket)
  const saved=await storage.upload(file,bytes,{contentType:'application/octet-stream',cacheControl:'0',upsert:false})
  if(saved.error){
    const existing=await storage.download(file)
    if(!existing.data||existing.data.size!==expected||!Buffer.from(await existing.data.arrayBuffer()).equals(bytes)){
      return fileFailure(409,'These attachment bytes could not be stored. Choose the file again.')
    }
  }
  return Response.json({id:file},{headers:fileHeaders})
}

export async function GET(request:Request) {
  const url=new URL(request.url)
  const file=url.searchParams.get('file')
  const message=url.searchParams.get('message')
  if(!validFileId(file)||!validFileId(message))return fileFailure(400,'Choose an encrypted attachment.')
  const auth=await authenticateFileRequest(request)
  if(auth instanceof Response)return auth
  const authorize=()=>auth.client.rpc('st_v7_group_file_access',{p_file:file,p_action:'read',p_message:message})
  const allowed=await authorize()
  if(allowed.error)return fileFailure(503,'Could not verify access to this encrypted attachment.')
  if(!Number.isInteger(allowed.data)||allowed.data<29||allowed.data>maxCipherBytes)return fileFailure(404,'Encrypted attachment unavailable.')
  const {data,error}=await auth.storage.storage.from(bucket).download(file)
  if(error||!data||data.size!==allowed.data)return fileFailure(404,'Encrypted attachment unavailable.')
  const final=await authorize()
  if(final.error||final.data!==allowed.data)return fileFailure(404,'Encrypted attachment unavailable.')
  return new Response(data,{headers:{...fileHeaders,'Content-Type':'application/octet-stream','Content-Disposition':'attachment'}})
}
