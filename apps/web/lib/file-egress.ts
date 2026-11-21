import type { SupabaseClient } from '@supabase/supabase-js'
import { fileFailure, fileHeaders } from './authenticated-file-request'
import { validFileId } from './file-download-ticket'

export const workspaceFileSsoMessage = 'Sign in through your workspace provider to access files.'

export async function scopedFileSession(client: SupabaseClient, scope: 'workspace' | 'room', scopeId: string, separateWorkflow = false) {
  const params = {p_scope_type: scope, p_scope: scopeId}
  const context = separateWorkflow ? client.rpc('st_v8_scoped_file_context', params) : client.rpc('st_v8_app_file_context', params)
  const result = await context.abortSignal(AbortSignal.timeout(2000))
  if (result.error) return fileFailure(503, 'Attachment access is temporarily unavailable.')
  if (result.data?.access === 'sso_required') return Response.json({
    error:workspaceFileSsoMessage, code:'workspace_sso_required',
  },{status:403,headers:fileHeaders})
  if (result.data?.access !== 'allowed' || !validFileId(result.data.session)) {
    return fileFailure(404, scope==='room'?'Room file access is unavailable.':'Workspace file access is unavailable.')
  }
  return result.data.session as string
}

export async function checkFileEgress(client: SupabaseClient, scope: 'workspace' | 'room',
  scopeId: string, file: string, operation: 'download' | 'share') {
  const result = await client.rpc('st_v7_explain_file_egress', {
    p_scope_type: scope, p_scope: scopeId, p_file: file, p_operation: operation,
  })
  if (result.error || typeof result.data?.allowed !== 'boolean') return fileFailure(503, 'File policy is unavailable.')
  if (result.data.allowed) return null
  if (result.data.reasons?.includes('access_unavailable')) return fileFailure(404, 'File access is unavailable.')
  return fileFailure(403, 'Workspace file policy blocked this action.')
}
