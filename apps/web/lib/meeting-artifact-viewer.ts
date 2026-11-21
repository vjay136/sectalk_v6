import { createClient } from '@supabase/supabase-js'
import { validFileId } from './file-download-ticket'

export async function meetingArtifactViewer(url: string, key: string, token: string) {
  const client = createClient(url,key,{
    auth: { persistSession:false, autoRefreshToken:false },
    global: { headers:{ Authorization:'Bearer '+token } },
  })
  const result = await client.rpc('st_v8_meeting_artifact_viewer').abortSignal(AbortSignal.timeout(3000))
  const {actor,session} = result.data ?? {}
  if (result.error || !validFileId(actor) || !validFileId(session)) return null
  return { actor, session }
}
