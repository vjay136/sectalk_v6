import { timingSafeEqual } from 'node:crypto'
import { createClient } from '@supabase/supabase-js'
import { fileAuthOptions, fileHeaders } from '../../../../lib/authenticated-file-request'

export const runtime = 'nodejs'
export const maxDuration = 60

type Claim = { file_id: string; lease: string }

export async function POST(request: Request) {
  const key = process.env.SECTALK_FILE_STORAGE_KEY
  const url = process.env.NEXT_PUBLIC_SUPABASE_URL
  const secret = process.env.SECTALK_FILE_PURGE_SECRET
  if (!key || !url || !secret || Buffer.byteLength(secret) < 32) return new Response(null, { status: 503, headers: fileHeaders })
  const expected = Buffer.from('Bearer ' + secret)
  const supplied = Buffer.from(request.headers.get('authorization') || '')
  if (supplied.length !== expected.length || !timingSafeEqual(supplied, expected)) {
    return new Response(null, { status: 401, headers: fileHeaders })
  }

  const service = createClient(url, key, { ...fileAuthOptions, global: {
    fetch: (input, options) => fetch(input, { ...options, signal: AbortSignal.timeout(5000) }),
  } })
  const abandoned = await service.rpc('st_v6_expire_resumable_attachments')
  if (abandoned.error) return new Response(null, { status: 503, headers: fileHeaders })
  const claim = await service.rpc('st_v6_claim_attachment_purge', { p_limit: 20 })
  if (claim.error) return new Response(null, { status: 503, headers: fileHeaders })
  const jobs = claim.data as Claim[]
  let purged = 0
  let deferred = 0
  for (let index = 0; index < jobs.length; index += 4) {
    const batch = jobs.slice(index, index + 4)
    const results = await Promise.allSettled(batch.map(async job => {
      const lease = { p_file: job.file_id, p_lease: job.lease }
      const confirmed = await service.rpc('st_v6_confirm_attachment_purge', lease)
      const removal = confirmed.data === true && !confirmed.error
        ? await service.storage.from('sectalk-chat-files').remove([job.file_id]) : null
      const result = await service.rpc('st_v6_finish_attachment_purge', {
        ...lease, p_removed: removal !== null && !removal.error,
      })
      return !result.error && result.data === true
    }))
    for (const result of results) {
      if (result.status === 'fulfilled' && result.value) purged++
      else deferred++
    }
  }
  return Response.json({ claimed: jobs.length, purged, deferred }, {
    status: deferred ? 503 : 200, headers: fileHeaders,
  })
}
