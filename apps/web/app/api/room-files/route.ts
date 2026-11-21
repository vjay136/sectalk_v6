import { authenticateFileRequest, fileFailure, fileHeaders } from '../../../lib/authenticated-file-request'
import { validFileId } from '../../../lib/file-download-ticket'
import { readAttachmentUpload, readUploadFilename } from '../../../lib/attachment-upload-body'
import { allowedFileType, attachmentDocumentFormat, officeFormatPattern } from '../../../lib/file-type-policy'
import { inspectAttachment } from '../../../lib/attachment-inspection'
import { scanAttachment } from '../../../lib/attachment-scan-server'
import { checkFileEgress, scopedFileSession } from '../../../lib/file-egress'
import { digestWorkspaceBytes, roomFilePath, workspaceFileBucket, workspaceFileMaximum, workspaceFileReadOnlyMessage } from '../../../lib/workspace-file-storage'

export const runtime = 'nodejs'
export const maxDuration = 40
const unavailable = () => fileFailure(404, 'Room file access is unavailable.')

async function handle(request: Request) {
  const query = new URL(request.url).searchParams
  const room = query.get('room')?.toLowerCase()
  const file = query.get('file')?.toLowerCase()
  const exportId = query.get('offboarding')?.toLowerCase()
  const storagePlan = query.get('offboarding-storage-plan')?.toLowerCase()
  const importId = query.get('residency-import')?.toLowerCase()
  const verificationId = query.get('residency-verify')?.toLowerCase()
  if (!validFileId(room) || (file !== undefined && !validFileId(file))) return fileFailure(400, 'Choose a valid room file.')
  if (exportId !== undefined && (!validFileId(exportId) || !file || request.method !== 'GET')) return unavailable()
  if (storagePlan !== undefined && (!validFileId(storagePlan) || !exportId || request.method !== 'GET')) return unavailable()
  if (importId !== undefined && (!validFileId(importId) || !file || request.method !== 'POST')) return unavailable()
  if (verificationId !== undefined && (!validFileId(verificationId) || !file || exportId || request.method !== 'GET')) return unavailable()
  const auth = await authenticateFileRequest(request,{type:'room',id:room})
  if (auth instanceof Response) return auth
  // The three specialized flows must each prove their own exact approval below.
  const separateWorkflow = Boolean(exportId || importId || verificationId)
  const session = await scopedFileSession(auth.client, 'room', room, separateWorkflow)
  if (session instanceof Response) return session
  const filename = readUploadFilename(request)
  const command = (action: string, size: number | null = null, hash: string | null = null) => {
    const params = {
      p_scope_type:'room', p_scope:room, p_actor:auth.actor, p_session:session,
      p_action:action, p_id:file ?? null, p_name:filename, p_bytes:size, p_hash:hash,
    }
    return separateWorkflow ? auth.storage.rpc('st_v8_scoped_file_command', params) : auth.storage.rpc('st_v8_app_file_command', params)
  }
  if (request.method === 'GET' && !file) {
    const list = await command('list')
    if (list.error) return fileFailure(503, 'Room files are unavailable.')
    return list.data ? Response.json(list.data, { headers: fileHeaders }) : unavailable()
  }
  if (!file) return fileFailure(400, 'Choose a valid room file.')
  if (request.method === 'DELETE') {
    const result = await command('remove')
    if (result.error) return fileFailure(503, 'The room file could not be removed.')
    return result.data ? new Response(null, { status: 204, headers: fileHeaders }) : unavailable()
  }
  const bucket = auth.storage.storage.from(workspaceFileBucket)
  if (request.method === 'GET') {
    const exportAccess = (hash?:string) => auth.client.rpc('st_v8_offboarding_room_file_access',{
      p_room:room,p_export:exportId,p_file:file,...(hash?{p_hash:hash}:{}),
    })
    const pinned=exportId?await exportAccess():null
    if(exportId&&(!pinned?.data||pinned.error))return unavailable()
    const denied = await checkFileEgress(auth.client, 'room', room, file, 'download')
    if (denied) return denied
    const access = await command('get')
    if (access.error || !access.data) return unavailable()
    const proof=storagePlan?await auth.client.rpc('st_v8_begin_offboarding_room_storage_copy',{
      p_room:room,p_plan:storagePlan,p_export:exportId,p_file:file,
    }):null
    if (storagePlan&&(proof?.error||!validFileId(proof?.data))) return unavailable()
    const verification = {p_kind:'room',p_scope:room,p_approval:verificationId,p_file:file}
    const snapshot = verificationId ? await auth.client.rpc('st_v8_residency_file_verification_snapshot',verification) : null
    if (verificationId && (snapshot?.error || !snapshot?.data)) return unavailable()
    const stored = await bucket.download(roomFilePath(access.data.workspace, room, file))
    if (stored.error || !stored.data || stored.data.size !== access.data.size_bytes || stored.data.size > workspaceFileMaximum) return unavailable()
    const bytes = Buffer.from(await stored.data.arrayBuffer())
    const hash=digestWorkspaceBytes(bytes)
    const current = await command('get')
    if (current.error || !current.data || current.data.workspace !== access.data.workspace ||
      current.data.size_bytes !== bytes.length || current.data.sha256 !== hash ||
      (pinned&&(pinned.data.bytes!==bytes.length||pinned.data.sha256!==hash))) return unavailable()
    const changed = await checkFileEgress(auth.client, 'room', room, file, 'download')
    if (changed) return changed
    if(exportId) {
      const allowed=await exportAccess(hash)
      if(allowed.error||!allowed.data||allowed.data.sha256!==pinned?.data.sha256||
        allowed.data.publishedAt!==pinned?.data.publishedAt)return unavailable()
    }
    if(snapshot?.data){
      const result=await auth.storage.rpc('st_v8_record_residency_file_verification',{
        ...verification,p_actor:auth.actor,p_session:session,p_snapshot:snapshot.data,p_sha256:hash,p_bytes:bytes.length,
      })
      return result.error||!result.data?unavailable():Response.json({verified:true},{headers:fileHeaders})
    }
    const receipt=proof?.data?await auth.storage.rpc('st_v8_finish_offboarding_room_storage_copy',{
      p_ticket:proof.data,p_sha256:hash,p_bytes:bytes.length,
    }):null
    if (storagePlan&&(receipt?.error||!validFileId(receipt?.data))) return unavailable()
    return new Response(Uint8Array.from(bytes), { headers: { ...fileHeaders, 'Content-Type': 'application/octet-stream',
      'Content-Disposition': 'attachment', ...(exportId?{'X-SecTalk-File-SHA256':hash}:{}),
      ...(receipt?.data?{'X-SecTalk-Storage-Copy-Receipt':receipt.data}:{}) } })
  }
  const mime = request.headers.get('content-type') || ''
  if (!filename || [...filename].length > 140 || /[\/\\\p{Cc}]/u.test(filename) || mime.length > 100) {
    return fileFailure(400, 'Choose a supported room file.')
  }
  if (Number(request.headers.get('content-length')) > workspaceFileMaximum) return fileFailure(413, 'Choose a file up to 4 MiB.')
  const gate = await command('access')
  if (gate.error) return fileFailure(503, 'Room file authorization is unavailable.')
  if (!gate.data) return unavailable()
  const payment = await auth.client.rpc('st_v7_workspace_payment_state', {p_room:room})
  if (payment.error) return fileFailure(payment.error.code === '42501' ? 403 : 503, 'Workspace upload status is unavailable.')
  if (payment.data?.mode === 'read_only') return fileFailure(423,workspaceFileReadOnlyMessage(payment.data.reason))
  const bytes = await readAttachmentUpload(request, workspaceFileMaximum).catch(() => null)
  if (bytes === undefined) return fileFailure(413, 'Choose a file up to 4 MiB.')
  if (!bytes?.length) return fileFailure(400, 'Choose a file that contains data.')
  if (!allowedFileType(filename, mime, bytes)) return fileFailure(415, 'The file contents do not match a supported attachment type.')
  const hash = digestWorkspaceBytes(bytes)
  const importDetails = {p_room:room, p_approval:importId, p_file:file, p_name:filename, p_bytes:bytes.length, p_hash:hash}
  const importApproved = async () => {
    if (!importId) return true
    const approval = await auth.client.rpc('st_v8_residency_room_file_import_access', importDetails)
    return approval.data === true && !approval.error
  }
  const write = (action: 'reserve' | 'publish') => importId
    ? auth.storage.rpc('st_v8_residency_room_file_import_command', {
      ...importDetails, p_actor:auth.actor, p_session:session, p_action:action,
    })
    : command(action, bytes.length, hash)
  if (!await importApproved()) return unavailable()
  const document = attachmentDocumentFormat(filename)
  const scan = await scanAttachment(bytes, hash, document)
  if (scan.verdict !== 'unavailable') {
    const metered = await auth.storage.rpc('st_v7_meter_file_scan', {p_scope: 'room', p_container: room,
      p_actor: auth.actor, p_file: file, p_digest: hash, p_name: filename})
    if (metered.error) return fileFailure(503, 'File inspection usage is unavailable.')
    if (!metered.data) return unavailable()
  }
  if (scan.verdict === 'malware' || scan.reason || inspectAttachment(filename, bytes)) {
    return fileFailure(422, 'The room file was blocked by security inspection.')
  }
  if (scan.unsupported) return fileFailure(415, 'The document structure is outside supported inspection limits.')
  if (scan.verdict !== 'clean' || (officeFormatPattern.test(filename) && !scan.validatedFormat)) {
    return fileFailure(503, 'Room file security scanning is unavailable.')
  }
  const reservation = await write('reserve')
  if (reservation.error?.code === 'PT423') return fileFailure(423, 'This workspace is read-only until payment is restored.')
  if (reservation.error?.code === 'PT413') return fileFailure(413, 'The room file storage limit was reached.')
  if (reservation.error?.code === 'PT422') return fileFailure(422, 'The room file was blocked by security scanning.')
  if (reservation.error?.code === 'PT409') return fileFailure(409, 'The approved room file identifier is already in use.')
  if (reservation.error) return fileFailure(503, 'Room file storage is unavailable.')
  if (!reservation.data) return unavailable()
  const path = roomFilePath(reservation.data.workspace, room, file)
  if (!reservation.data.uploaded) await bucket.upload(path, bytes, { contentType: 'application/octet-stream', upsert: false, cacheControl: '0' })
  const stored = await bucket.download(path)
  if (stored.error || !stored.data || stored.data.size !== bytes.length ||
    digestWorkspaceBytes(Buffer.from(await stored.data.arrayBuffer())) !== hash) return fileFailure(409, 'The room file could not be verified.')
  if (!await importApproved()) return unavailable()
  const published = await write('publish')
  if (published.error?.code === 'PT423') return fileFailure(423, 'This workspace is read-only until payment is restored.')
  if (published.error?.code === 'PT422') return fileFailure(422, 'The room file was blocked by security scanning.')
  if (published.error) return fileFailure(503, 'The room file could not be published.')
  return published.data ? Response.json(published.data, { headers: fileHeaders }) : unavailable()
}

export const GET = handle
export const POST = handle
export const DELETE = handle
