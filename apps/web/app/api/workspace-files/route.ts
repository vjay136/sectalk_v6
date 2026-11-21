import { authenticateFileRequest, fileFailure, fileHeaders } from '../../../lib/authenticated-file-request'
import { validFileId } from '../../../lib/file-download-ticket'
import { readAttachmentUpload, readUploadFilename } from '../../../lib/attachment-upload-body'
import { allowedFileType, attachmentDocumentFormat, officeFormatPattern } from '../../../lib/file-type-policy'
import { attachmentInspectionLabel, inspectAttachment } from '../../../lib/attachment-inspection'
import { scanAttachment } from '../../../lib/attachment-scan-server'
import { checkFileEgress, scopedFileSession } from '../../../lib/file-egress'
import { digestWorkspaceBytes, workspaceFileBucket, workspaceFileFingerprint, workspaceFileMaximum, workspaceFilePath, workspaceFileReadOnlyMessage } from '../../../lib/workspace-file-storage'

export const runtime = 'nodejs'
export const maxDuration = 40

const forbidden = () => fileFailure(404, 'Workspace file access is unavailable.')

async function stageRollbackFile(request: Request, workspace: string, file: string) {
  const encoded = request.headers.get('x-sectalk-rollback-file-proof')
  if (!encoded || !/^[A-Za-z0-9_-]{1,5462}$/.test(encoded)) return forbidden()
  let proof: unknown
  try {
    proof = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(Buffer.from(encoded, 'base64url')))
  } catch { return forbidden() }

  const auth = await authenticateFileRequest(request, { type: 'workspace', id: workspace })
  if (auth instanceof Response) return auth
  const bytes = await readAttachmentUpload(request, workspaceFileMaximum).catch(() => null)
  if (bytes === undefined) return fileFailure(413, 'Choose a file up to 4 MiB.')
  if (!bytes?.length) return fileFailure(400, 'The recovery copy contains no file data.')
  const hash = digestWorkspaceBytes(bytes)
  const args = { p_workspace: workspace, p_file: file, p_proof: proof, p_sha256: hash, p_bytes: bytes.length }
  const admitted = await auth.client.rpc('st_v8_residency_source_file_admission', args)
  if (admitted.error || admitted.data?.state !== 'proof_verified' || !validFileId(admitted.data.handoff)) return forbidden()

  const filename = admitted.data.filename
  if (typeof filename !== 'string' || !allowedFileType(filename, 'application/octet-stream', bytes)) {
    return fileFailure(415, 'The recovery copy has an unsupported attachment type.')
  }
  const blocked = await auth.storage.rpc('st_v7_upload_digest_blocked', { p_hash: hash })
  if (blocked.error) return fileFailure(503, 'The platform file policy could not be checked.')
  if (blocked.data === true) return fileFailure(422, 'The recovery copy was blocked by platform policy.')
  const scan = await scanAttachment(bytes, hash, attachmentDocumentFormat(filename))
  if (scan.verdict === 'malware' || attachmentInspectionLabel(scan.reason ?? inspectAttachment(filename, bytes))) {
    return fileFailure(422, 'The recovery copy was blocked by security scanning.')
  }
  if (scan.unsupported) return fileFailure(415, 'The document structure is outside supported inspection limits.')
  if (scan.verdict !== 'clean' || (officeFormatPattern.test(filename) && !scan.validatedFormat)) {
    return fileFailure(503, 'Workspace file security scanning is unavailable.')
  }

  const bucket = auth.storage.storage.from('sectalk-residency-recovery')
  const object = `${workspace}/${admitted.data.handoff}/${file}/${hash}`
  // A retry may find the immutable path already occupied. Verify the actual bytes before claiming it.
  await bucket.upload(object, bytes, { contentType: 'application/octet-stream', upsert: false, cacheControl: '0' })
  const stored = await bucket.download(object)
  if (stored.error || !stored.data || stored.data.size !== bytes.length ||
    digestWorkspaceBytes(Buffer.from(await stored.data.arrayBuffer())) !== hash) {
    return fileFailure(409, 'The private recovery copy in Storage could not be verified.')
  }
  const staged = await auth.client.rpc('st_v8_residency_source_file_stage', args)
  if (staged.error?.code === 'PT409') return fileFailure(409, 'The staged copy differs from its previous receipt.')
  if (staged.error && staged.error.code !== '42501') return fileFailure(503, 'The private recovery receipt could not be recorded.')
  if (staged.data?.state !== 'staged') return forbidden()
  return Response.json(staged.data, { headers: fileHeaders })
}

async function handle(request: Request) {
  const query = new URL(request.url).searchParams
  const workspace = query.get('workspace')?.toLowerCase()
  const file = query.get('file')?.toLowerCase()
  const action = query.get('action')
  const exportId = query.get('offboarding')?.toLowerCase()
  const storagePlan = query.get('offboarding-storage-plan')?.toLowerCase()
  const importId = query.get('residency-import')?.toLowerCase()
  const verificationId = query.get('residency-verify')?.toLowerCase()
  const rollbackReview = query.get('residency-rollback')?.toLowerCase()
  const rollbackStage = query.get('residency-rollback-stage')
  const filename = readUploadFilename(request)
  const mime = request.headers.get('content-type') || ''
  if (!validFileId(workspace) || (file !== undefined && !validFileId(file))) return fileFailure(400, 'Choose a valid workspace file.')
  if (rollbackStage !== null) {
    if (rollbackStage !== '1' || !file || request.method !== 'POST' || action !== null ||
      exportId || storagePlan || importId || verificationId || rollbackReview) return forbidden()
    return stageRollbackFile(request, workspace, file)
  }
  if (exportId !== undefined && (!validFileId(exportId) || !file || request.method !== 'GET')) return forbidden()
  if (storagePlan !== undefined && (!validFileId(storagePlan) || !exportId || action !== null || request.method !== 'GET')) return forbidden()
  if (importId !== undefined && (!validFileId(importId) || !file || action !== null || request.method !== 'POST')) return forbidden()
  if (verificationId !== undefined && (!validFileId(verificationId) || !file || action !== null || exportId || request.method !== 'GET')) return forbidden()
  if (rollbackReview !== undefined && (!validFileId(rollbackReview) || !file || action !== null ||
    exportId || storagePlan || importId || verificationId || request.method !== 'GET')) return forbidden()
  const auth = await authenticateFileRequest(request,{type:'workspace',id:workspace})
  if (auth instanceof Response) return auth
  // The three specialized flows must each prove their own exact approval below.
  const separateWorkflow = Boolean(exportId || importId || verificationId)
  const session = await scopedFileSession(auth.client, 'workspace', workspace, separateWorkflow)
  if (session instanceof Response) return session
  const command = (action: string, size: number | null = null, hash: string | null = null) => {
    const params = {
      p_scope_type:'workspace', p_scope:workspace, p_actor:auth.actor, p_session:session,
      p_action:action, p_id:file ?? null, p_name:filename ?? null, p_bytes:size, p_hash:hash,
    }
    return separateWorkflow ? auth.storage.rpc('st_v8_scoped_file_command', params) : auth.storage.rpc('st_v8_app_file_command', params)
  }
  const bucket = auth.storage.storage.from(workspaceFileBucket)
  if (request.method === 'GET' && !file) {
    const result = await command('list')
    if (result.error) return fileFailure(503, 'Workspace files are unavailable.')
    return result.data ? Response.json(result.data, { headers: fileHeaders }) : forbidden()
  }
  if (!file) return fileFailure(400, 'Choose a valid workspace file.')
  const object = workspaceFilePath(workspace, file)
  if (request.method === 'POST' && action !== null) {
    if (action !== 'view' && action !== 'share') return fileFailure(400, 'Choose a valid workspace file action.')
    if (action === 'share') {
      const denied = await checkFileEgress(auth.client, 'workspace', workspace, file, 'share')
      if (denied) return denied
    }
    const result = await command(action)
    if (result.error) return fileFailure(503, 'Workspace file access could not be recorded.')
    if (!result.data) return forbidden()
    return Response.json(action === 'share' ? { path: '/workspace-file/' + object } : result.data, { headers: fileHeaders })
  }
  if (request.method === 'DELETE') {
    const result = await command('remove')
    if (result.error) return fileFailure(503, 'The workspace file could not be removed.')
    return result.data ? new Response(null, { status: 204, headers: fileHeaders }) : forbidden()
  }
  if (request.method === 'GET') {
    const exportAccess = (hash?:string) => auth.client.rpc('st_v8_offboarding_file_access',{
      p_workspace:workspace,p_export:exportId,p_file:file,...(hash?{p_hash:hash}:{}),
    })
    const pinned = exportId ? await exportAccess() : null
    if (exportId && (!pinned?.data || pinned.error)) return forbidden()
    const denied = await checkFileEgress(auth.client, 'workspace', workspace, file, 'download')
    if (denied) return denied
    const rollbackArgs = {p_workspace:workspace, p_review:rollbackReview, p_file:file}
    const rollbackSnapshot = rollbackReview ? await auth.client.rpc('st_v8_residency_rollback_file_copy',rollbackArgs) : null
    if (rollbackReview && (rollbackSnapshot?.error || !rollbackSnapshot?.data)) return forbidden()
    const proof = storagePlan ? await auth.client.rpc('st_v8_begin_offboarding_storage_copy',{
      p_workspace:workspace, p_plan:storagePlan, p_export:exportId, p_file:file,
    }) : null
    if (storagePlan && (proof?.error || !validFileId(proof?.data))) return forbidden()
    const metadata = await command('get')
    if (metadata.error) return fileFailure(503, 'Workspace files are unavailable.')
    if (!metadata.data) return forbidden()
    const verification = {p_kind:'workspace',p_scope:workspace,p_approval:verificationId,p_file:file}
    const snapshot = verificationId ? await auth.client.rpc('st_v8_residency_file_verification_snapshot',verification) : null
    if (verificationId && (snapshot?.error || !snapshot?.data)) return forbidden()
    const downloaded = await bucket.download(object)
    if (downloaded.error || !downloaded.data || downloaded.data.size !== metadata.data.size_bytes ||
      downloaded.data.size > workspaceFileMaximum) return forbidden()
    const bytes = Buffer.from(await downloaded.data.arrayBuffer())
    const hash = digestWorkspaceBytes(bytes)
    const current = await command('get')
    if (current.error || !current.data || current.data.size_bytes !== bytes.length ||
      (current.data.fingerprint && current.data.fingerprint !== workspaceFileFingerprint(workspace, hash)) ||
      (pinned && (pinned.data.bytes!==bytes.length || pinned.data.fingerprint!==workspaceFileFingerprint(workspace,hash)))) {
      return forbidden()
    }
    const changed = await checkFileEgress(auth.client, 'workspace', workspace, file, 'download')
    if (changed) return changed
    if (exportId) {
      const allowed=await exportAccess(hash)
      if(allowed.error||!allowed.data||allowed.data.fingerprint!==pinned?.data.fingerprint||
        allowed.data.publishedAt!==pinned?.data.publishedAt) return forbidden()
    }
    const rollback = rollbackSnapshot?.data ? await auth.client.rpc('st_v8_residency_rollback_file_copy',{
      ...rollbackArgs, p_sha256:hash,
    }) : null
    if (rollbackSnapshot?.data && (rollback?.error || !rollback?.data?.proof ||
      rollback.data.stamp !== rollbackSnapshot.data.stamp || rollback.data.bytes !== bytes.length)) return forbidden()
    const logged = await command('download')
    if (logged.error) return fileFailure(503, 'Workspace file access could not be recorded.')
    if (!logged.data) return forbidden()
    const receipt = proof ? await auth.storage.rpc('st_v8_finish_offboarding_storage_copy',{
      p_ticket:proof.data, p_sha256:hash, p_bytes:bytes.length,
    }) : null
    if (proof && (receipt?.error || !validFileId(receipt?.data))) return forbidden()
    if(snapshot?.data){
      const result=await auth.storage.rpc('st_v8_record_residency_file_verification',{
        ...verification,p_actor:auth.actor,p_session:session,p_snapshot:snapshot.data,p_sha256:hash,p_bytes:bytes.length,
      })
      return result.error||!result.data?forbidden():Response.json({verified:true},{headers:fileHeaders})
    }
    return new Response(Uint8Array.from(bytes), { headers: { ...fileHeaders, 'Content-Type': 'application/octet-stream',
      'Content-Disposition': 'attachment', ...(exportId?{'X-SecTalk-File-SHA256':hash}:{}),
      ...(rollback?.data?.proof?{'X-SecTalk-Rollback-File-Proof':Buffer.from(JSON.stringify(rollback.data.proof)).toString('base64url')}:{}),
      ...(receipt?{'X-SecTalk-Storage-Copy-Receipt':receipt.data}:{}) } })
  }
  if (!filename || [...filename].length > 140 || /[\/\\\p{Cc}]/u.test(filename) || mime.length > 100) {
    return fileFailure(400, 'Choose a supported workspace file.')
  }
  if (Number(request.headers.get('content-length')) > workspaceFileMaximum) return fileFailure(413, 'Choose a file up to 4 MiB.')
  const access = await command('access')
  if (access.error) return fileFailure(503, 'Workspace files are unavailable.')
  if (!access.data) return forbidden()
  const payment = await auth.client.rpc('st_v7_workspace_payment_state', {p_workspace:workspace})
  if (payment.error) return fileFailure(payment.error.code === '42501' ? 403 : 503, 'Workspace upload status is unavailable.')
  if (payment.data?.mode === 'read_only') return fileFailure(423,workspaceFileReadOnlyMessage(payment.data.reason))
  const bytes = await readAttachmentUpload(request, workspaceFileMaximum).catch(() => null)
  if (bytes === undefined) return fileFailure(413, 'Choose a file up to 4 MiB.')
  if (!bytes?.length) return fileFailure(400, 'Choose a file that contains data.')
  if (!allowedFileType(filename, mime, bytes)) return fileFailure(415, 'The file contents do not match a supported attachment type.')
  const hash = digestWorkspaceBytes(bytes)
  const importApproved = async () => {
    if (!importId) return true
    const result = await auth.client.rpc('st_v8_residency_file_import_access', {
      p_workspace:workspace, p_approval:importId, p_file:file, p_filename:filename, p_bytes:bytes.length, p_hash:hash,
    })
    return result.data === true && !result.error
  }
  if (!await importApproved()) return forbidden()
  const blocked = await auth.storage.rpc('st_v7_upload_digest_blocked', { p_hash: hash })
  if (blocked.error) return fileFailure(503, 'The platform file policy could not be checked.')
  if (blocked.data === true) return fileFailure(422, 'The workspace file was blocked by platform policy.')
  const scan = await scanAttachment(bytes, hash, attachmentDocumentFormat(filename))
  if (scan.verdict === 'malware') await command('malware', null, hash)
  if (scan.verdict !== 'unavailable') {
    const metered = await auth.storage.rpc('st_v7_meter_file_scan', {p_scope: 'workspace', p_container: workspace,
      p_actor: auth.actor, p_file: file, p_digest: hash, p_name: filename})
    if (metered.error) return fileFailure(503, 'File inspection usage is unavailable.')
    if (!metered.data) return forbidden()
  }
  if (scan.verdict === 'malware') {
    return fileFailure(422, 'The workspace file was blocked by security scanning.')
  }
  if (scan.unsupported) return fileFailure(415, 'The document structure is outside supported inspection limits.')
  if (scan.verdict !== 'clean' || (officeFormatPattern.test(filename) && !scan.validatedFormat)) {
    return fileFailure(503, 'Workspace file security scanning is unavailable.')
  }
  const reason = attachmentInspectionLabel(scan.reason ?? inspectAttachment(filename, bytes))
  if (reason) return fileFailure(422, 'Workspace file inspection flagged ' + reason.toLowerCase() + '.')
  const reservation = await command('reserve', bytes.length, hash)
  if (reservation.error?.code === 'PT423') return fileFailure(423, 'This workspace is read-only until payment is restored.')
  if (reservation.error?.code === 'PT413') return fileFailure(413, 'The workspace file storage limit was reached.')
  if (reservation.error?.code === 'PT409') return fileFailure(409, 'Choose a new workspace file identifier.')
  if (reservation.error?.code === 'PT422') return fileFailure(422, 'The workspace file was blocked by security scanning.')
  if (reservation.error) return fileFailure(503, 'Workspace file storage is unavailable.')
  if (!reservation.data) return forbidden()
  if (!reservation.data.uploaded) {
    await bucket.upload(object, bytes, { contentType: 'application/octet-stream', upsert: false, cacheControl: '0' })
  }
  const stored = await bucket.download(object)
  if (stored.error || !stored.data || stored.data.size !== bytes.length ||
    digestWorkspaceBytes(Buffer.from(await stored.data.arrayBuffer())) !== hash) {
    return fileFailure(409, 'The workspace file in Storage could not be verified.')
  }
  if (!await importApproved()) return forbidden()
  const publication = await command('publish', bytes.length, hash)
  if (publication.error?.code === 'PT423') return fileFailure(423, 'This workspace is read-only until payment is restored.')
  if (publication.error?.code === 'PT422') return fileFailure(422, 'The workspace file was blocked by security scanning.')
  if (publication.error) return fileFailure(503, 'The workspace file could not be published.')
  return publication.data ? Response.json(publication.data, { headers: fileHeaders }) : forbidden()
}

export const GET = handle
export const POST = handle
export const DELETE = handle
