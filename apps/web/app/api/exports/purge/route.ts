import { timingSafeEqual } from 'node:crypto'
import { fileHeaders } from '../../../../lib/authenticated-file-request'
import { exportBucket, exportStorage } from '../../../../lib/export-storage-server'

export const runtime = 'nodejs'
export const maxDuration = 60

type Job = { id: string; lease: string }

export async function POST(request: Request) {
  const key = process.env.SECTALK_FILE_PURGE_SECRET
  const storage = exportStorage()
  if (!storage || !key || Buffer.byteLength(key) < 32) return new Response(null, { status: 503, headers: fileHeaders })
  const expected = Buffer.from('Bearer ' + key)
  const supplied = Buffer.from(request.headers.get('authorization') || '')
  if (supplied.length !== expected.length || !timingSafeEqual(supplied, expected)) {
    return new Response(null, { status: 401, headers: fileHeaders })
  }
  const claim = await storage.rpc('st_v6_claim_export_cleanup')
  if (claim.error) return new Response(null, { status: 503, headers: fileHeaders })
  const jobs = claim.data as Job[]
  let purged = 0
  for (let index = 0; index < jobs.length; index += 4) {
    const batch = jobs.slice(index, index + 4)
    const results = await Promise.allSettled(batch.map(async job => {
      const removal = await storage.storage.from(exportBucket).remove([job.id])
      if (removal.error) return false
      const finish = await storage.rpc('st_v6_finish_export_cleanup', { p_artifact: job.id, p_lease: job.lease })
      return !finish.error && finish.data === true
    }))
    purged += results.filter(result => result.status === 'fulfilled' && result.value === true).length
  }
  const deferred = jobs.length - purged
  return Response.json({ claimed: jobs.length, purged, deferred }, {
    status: deferred ? 503 : 200, headers: fileHeaders,
  })
}
