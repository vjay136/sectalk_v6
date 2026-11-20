import { withOperationalMetrics } from '../../../../lib/operational-metrics-server'
import { createHash } from 'node:crypto'
import { authenticateFileRequest, fileFailure, fileHeaders } from '../../../../lib/authenticated-file-request'
import { validFileId } from '../../../../lib/file-download-ticket'
import { allowedFileType, attachmentDocumentFormat, officeFormatPattern } from '../../../../lib/file-type-policy'
import { attachmentInspectionLabel, inspectAttachment } from '../../../../lib/attachment-inspection'
import { attachmentScannerConfigured, scanAttachment } from '../../../../lib/attachment-scan-server'

export const runtime='nodejs'
export const maxDuration=30

async function handlePost(request:Request){
  const auth=await authenticateFileRequest(request)
  if(auth instanceof Response)return auth
  const input=await request.json().catch(()=>null)
  if(!validFileId(input?.file)||typeof input.caption!=='string'||[...input.caption].length>4000||
    typeof input.mime!=='string'||input.mime.length>100)return fileFailure(400,'Invalid attachment request.')
  const pending=await auth.client.rpc('st_v6_pending_file',{p_file:input.file})
  if(pending.error?.code==='PT429')return fileFailure(429,'Too many attachments. Try again in a minute.')
  if(pending.error)return fileFailure(503,'Attachment permissions could not be verified.')
  if(!pending.data)return fileFailure(404,'Attachment unavailable.')
  if(pending.data.published)
    return Response.json({id:pending.data.published,duplicate:pending.data.duplicate===true},{headers:fileHeaders})
  const {data,error}=await auth.storage.storage.from('sectalk-chat-files').download(input.file)
  if(error||!data||data.size!==pending.data.size)return fileFailure(409,'Attachment upload is incomplete.')
  const bytes=Buffer.from(await data.arrayBuffer())
  if(!allowedFileType(pending.data.filename,input.mime,bytes))
    return fileFailure(415,'The file contents do not match an allowed attachment type.')
  const hash=createHash('sha256').update(bytes).digest('hex')
  const blocked=await auth.storage.rpc('st_v7_upload_digest_blocked',{p_hash:hash})
  if(blocked.error)return fileFailure(503,'The platform file policy could not be checked.')
  if(blocked.data===true)return fileFailure(422,'The attachment was blocked by platform policy.')
  const scanState=pending.data.scan_state
  if(scanState==='malware')return fileFailure(422,'The attachment was blocked by security scanning.')
  const localReason=inspectAttachment(pending.data.filename,bytes)
  if(scanState!=='released'&&(attachmentScannerConfigured()||scanState||localReason||officeFormatPattern.test(pending.data.filename))){
    const result=await scanAttachment(bytes,hash,attachmentDocumentFormat(pending.data.filename))
    if(result.unsupported)return fileFailure(415,'This document type or structure is outside the supported inspection limits.')
    const inspectionReason=result.reason??localReason
    const scan=await auth.storage.rpc('st_v6_record_attachment_scan',{
      p_file:input.file,p_actor:auth.actor,p_hash:hash,p_verdict:result.verdict,
      p_inspection_reason:inspectionReason,
      p_validated_document_format:result.validatedFormat??null,
    })
    if(scan.error||!scan.data)return fileFailure(503,'The attachment scan could not be recorded.')
    if(scan.data==='malware')return fileFailure(422,'The attachment was blocked by security scanning.')
    const reason=attachmentInspectionLabel(inspectionReason)
    if(scan.data==='quarantined')return fileFailure(423,reason
      ? `The attachment is quarantined. Static inspection flagged: ${reason}. Security scanning must also be available.`
      : 'The attachment is quarantined. Retry after scanning is available.')
    if(scan.data==='awaiting_release')return fileFailure(423,reason
      ? `The attachment awaits security review. Static inspection flagged: ${reason}.`
      : 'The attachment passed re-scanning and awaits security review.')
  }
  const publication=await auth.storage.rpc('st_v7_publish_hashed_file',{
    p_file:input.file,p_actor:auth.actor,p_caption:input.caption,p_hash:hash,
  })
  if(publication.error?.code==='PT413')return fileFailure(413,publication.error.message)
  if(publication.error?.code==='PT409')return fileFailure(409,publication.error.message)
  if(publication.error?.code==='PT423')return fileFailure(423,'The attachment remains quarantined.')
  if(publication.error?.code==='PT422')return fileFailure(422,'The attachment was blocked by platform policy.')
  if(publication.error)return fileFailure(409,'The attachment could not be published.')
  return Response.json(publication.data,{headers:fileHeaders})
}

export async function POST(request: Request) {
  return withOperationalMetrics('file_publish', () => handlePost(request))
}
