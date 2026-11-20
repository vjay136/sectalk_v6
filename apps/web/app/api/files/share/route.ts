import { createClient } from '@supabase/supabase-js'
import { fileAuthOptions, fileFailure, fileHeaders } from '../../../../lib/authenticated-file-request'

export const runtime = 'nodejs'

async function readInput(request: Request) {
  const reader = request.body?.getReader()
  if (!reader) return null
  let size = 0
  const decoder = new TextDecoder()
  let body = ''
  try {
    for (;;) {
      const { value, done } = await reader.read()
      if (done) return JSON.parse(body + decoder.decode())
      size += value.byteLength
      if (size > 1024) {
        void reader.cancel().catch(() => undefined)
        return null
      }
      body += decoder.decode(value, { stream: true })
    }
  } finally {
    reader.releaseLock()
  }
}

export async function POST(request: Request) {
  const input = await readInput(request).catch(() => null)
  if (typeof input?.token !== 'string' || !/^[a-f0-9]{64}$/.test(input.token) ||
      typeof input.password !== 'string' || Buffer.byteLength(input.password) < 10 || Buffer.byteLength(input.password) > 64 ||
      (input.action !== 'view' && input.action !== 'download')) {
    return fileFailure(400, 'Enter a valid link and password.')
  }
  const url = process.env.NEXT_PUBLIC_SUPABASE_URL
  const key = process.env.SECTALK_FILE_STORAGE_KEY
  if (!url || !key) return fileFailure(503, 'Shared attachments are unavailable.')
  const storage = createClient(url, key, fileAuthOptions)
  const access = (action: 'view' | 'peek' | 'download') => storage.rpc('st_v6_access_file_share', {
    p_token: input.token, p_password: input.password, p_action: action,
  })
  const permission = await access(input.action === 'view' ? 'view' : 'peek')
  if (permission.error) return fileFailure(503, 'Shared attachments are unavailable.')
  if (!permission.data) return fileFailure(404, 'The link or password is unavailable.')
  const { file, filename, size_bytes } = permission.data
  if (input.action === 'view') return Response.json({ filename, size_bytes }, { headers: fileHeaders })

  const { data, error } = await storage.storage.from('sectalk-chat-files').download(file)
  if (error || !data || data.size !== size_bytes) return fileFailure(404, 'The shared attachment is unavailable.')
  const redemption = await access('download')
  if (redemption.error) return fileFailure(503, 'Shared attachments are unavailable.')
  if (!redemption.data || redemption.data.file !== file) return fileFailure(404, 'The link or password is unavailable.')
  return new Response(data, { headers: { ...fileHeaders, 'Content-Type': 'application/octet-stream',
    'Content-Disposition': 'attachment' } })
}
