import type { SupabaseClient } from '@supabase/supabase-js'
import { fileFailure } from './authenticated-file-request'

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
