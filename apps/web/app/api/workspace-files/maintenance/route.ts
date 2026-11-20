import { timingSafeEqual } from 'node:crypto'
import { createClient } from '@supabase/supabase-js'
import { fileAuthOptions, fileHeaders } from '../../../../lib/authenticated-file-request'
import { digestWorkspaceBytes, roomFilePath, workspaceFileBucket, workspaceFileMaximum, workspaceFilePath } from '../../../../lib/workspace-file-storage'

export const runtime = 'nodejs'
export const maxDuration = 60
type Job = { workspace: string; id: string; size_bytes: number; lease: string; task: 'index' | 'purge' }
type RoomJob = { room: string; workspace: string; id: string; lease: string }
const unavailable = (status: number) => new Response(null, { status, headers: fileHeaders })

export async function POST(request: Request) {
  const url = process.env.NEXT_PUBLIC_SUPABASE_URL
  const serviceKey = process.env.SECTALK_FILE_STORAGE_KEY
  const secret = process.env.SECTALK_FILE_PURGE_SECRET
  if (!url || !serviceKey || !secret || Buffer.byteLength(secret) < 32) return unavailable(503)
  const expected = Buffer.from('Bearer ' + secret)
  const supplied = Buffer.from(request.headers.get('authorization') || '')
  if (supplied.length !== expected.length || !timingSafeEqual(supplied, expected)) return unavailable(401)
  const storage = createClient(url, serviceKey, { ...fileAuthOptions, global: {
    fetch: (input, options) => fetch(input, { ...options, signal: AbortSignal.timeout(5000) }),
  } })
  const [claim, roomClaim] = await Promise.all([
    storage.rpc('st_v6_workspace_file_maintenance_claim'),
    storage.rpc('st_v6_claim_room_file_cleanup'),
  ])
  if (claim.error || roomClaim.error) return unavailable(503)
  const bucket = storage.storage.from(workspaceFileBucket)
  const jobs = claim.data as Job[]
  let indexed = 0
  let purged = 0
  for (let index = 0; index < jobs.length; index += 4) {
    const results = await Promise.allSettled(jobs.slice(index, index + 4).map(async job => {
      let hash: string | null = null
      const path = workspaceFilePath(job.workspace, job.id)
      if (job.task === 'purge') {
        if ((await bucket.remove([path])).error) return null
      } else {
        const result = await bucket.download(path)
        if (result.error || !result.data || result.data.size !== job.size_bytes || job.size_bytes > workspaceFileMaximum) return null
        hash = digestWorkspaceBytes(Buffer.from(await result.data.arrayBuffer()))
      }
      const result = await storage.rpc('st_v6_workspace_file_maintenance_finish', {
        p_workspace: job.workspace, p_id: job.id, p_lease: job.lease, p_hash: hash,
      })
      return !result.error && result.data === true ? job.task : null
    }))
    for (const result of results) {
      if (result.status === 'fulfilled' && result.value === 'index') indexed++
      if (result.status === 'fulfilled' && result.value === 'purge') purged++
    }
  }
  const roomJobs = roomClaim.data as RoomJob[]
  let roomPurged = 0
  for (let index = 0; index < roomJobs.length; index += 4) {
    const results = await Promise.allSettled(roomJobs.slice(index, index + 4).map(async job => {
      const removal = await bucket.remove([roomFilePath(job.workspace, job.room, job.id)])
      if (removal.error) return false
      const done = await storage.rpc('st_v6_finish_room_file_cleanup', { p_room: job.room, p_id: job.id, p_lease: job.lease })
      return !done.error && done.data === true
    }))
    roomPurged += results.filter(result => result.status === 'fulfilled' && result.value === true).length
  }
  const pruned = await storage.rpc('st_v6_prune_workspace_file_history')
  if (pruned.error) return unavailable(503)
  const deferred = jobs.length - indexed - purged + roomJobs.length - roomPurged
  return Response.json({ claimed: jobs.length, indexed, purged, roomPurged, deferred }, {
    status: deferred ? 503 : 200, headers: fileHeaders,
  })
}
