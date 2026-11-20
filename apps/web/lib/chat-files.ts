import { db } from './data'

export const chatFileLimit = 4 * 1024 * 1024
const uploadChunkBytes = 256 * 1024
export const extensions = '.png,.jpg,.jpeg,.webp,.gif,.pdf,.txt,.docx,.docm,.xlsx,.xlsm,.pptx,.pptm'
export type ChatFile = { id: string; message_id?: string; filename: string; size_bytes: number }
export type ChatFileCapacity = {
  max_file_bytes: number
  max_storage_bytes: number
  stored_bytes: number
  reserved_bytes: number
}

export function supportedFile(file: File) {
  return file.size > 0 && file.size <= chatFileLimit &&
    extensions.split(',').includes(file.name.slice(file.name.lastIndexOf('.')).toLowerCase()) && [...file.name].length <= 140
}

export async function getChatFileCapacity() {
  const { data, error } = await db!.rpc('st_v6_attachment_capacity')
  return error ? null : data as ChatFileCapacity | null
}

export function formatChatFileBytes(bytes: number) {
  const units = ['B', 'KiB', 'MiB', 'GiB']
  let unit = 0
  while (bytes >= 1024 && unit < units.length - 1) {
    bytes /= 1024
    unit++
  }
  return bytes.toLocaleString(undefined, { maximumFractionDigits: 1 }) + ' ' + units[unit]
}

async function uploadHash(data: Blob) {
  const digest = await crypto.subtle.digest('SHA-256', await data.arrayBuffer())
  return Array.from(new Uint8Array(digest), byte => byte.toString(16).padStart(2, '0')).join('')
}

async function resumeAttachmentUpload(id: string, file: File, authorization: { Authorization: string }) {
  const endpoint = '/api/files/resumable?file=' + encodeURIComponent(id)
  const headers = { ...authorization, 'X-SecTalk-Upload-SHA256': await uploadHash(file), 'X-SecTalk-File-Type': file.type }
  async function state(response: Response) {
    const value = await response.json().catch(() => null)
    if (!response.ok) throw new Error(value?.error || 'The attachment could not be uploaded.')
    if (!Number.isInteger(value?.offset) || value.offset < 0 || value.offset > file.size ||
      (value.offset < file.size && value.offset % uploadChunkBytes !== 0) || typeof value.uploaded !== 'boolean' ||
      (value.uploaded && value.offset !== file.size)) throw new Error('Invalid attachment upload progress.')
    return value as { offset: number; uploaded: boolean }
  }
  const current = await state(await fetch(endpoint + '&action=status', { method: 'POST', headers, signal: AbortSignal.timeout(12000) }))
  if (current.uploaded) return
  let offset = current.offset
  while (offset < file.size) {
    const part = file.slice(offset, offset + uploadChunkBytes)
    const next = await state(await fetch(endpoint + '&offset=' + offset, {
      method: 'PUT', body: part, signal: AbortSignal.timeout(12000),
      headers: { ...headers, 'Content-Type': 'application/octet-stream', 'X-SecTalk-Chunk-SHA256': await uploadHash(part) },
    }))
    if (next.offset < offset + part.size) throw new Error('Attachment upload did not advance.')
    offset = next.offset
  }
  const completed = await state(await fetch(endpoint + '&action=assemble', {
    method: 'POST', headers, signal: AbortSignal.timeout(45000),
  }))
  if (!completed.uploaded) throw new Error('The attachment upload is incomplete.')
}

export async function sendChatFile(chat: string, id: string, file: File, caption: string) {
  const { error } = await db!.rpc('st_v5_stage_file', {
    p_chat: chat, p_id: id, p_filename: file.name, p_bytes: file.size,
  })
  if (error) throw error
  const session = await db!.auth.getSession()
  if (!session.data.session) throw new Error('Sign in to send attachments.')
  const authorization = { Authorization: 'Bearer ' + session.data.session.access_token }
  await resumeAttachmentUpload(id, file, authorization)
  const result=await fetch('/api/files/publish',{
    method:'POST',headers:{...authorization,'Content-Type':'application/json'},
    body:JSON.stringify({file:id,caption,mime:file.type}),
  })
  if(!result.ok){
    const value=await result.json().catch(()=>null)
    throw new Error(value?.error||'The attachment could not be published.')
  }
  const value=await result.json()
  return {duplicate:value.duplicate===true}
}

export async function fetchChatFile(id: string) {
  const {data}=await db!.auth.getSession()
  if(!data.session)throw new Error('Sign in to download attachments.')
  const authorization={Authorization:'Bearer '+data.session.access_token}
  const grant=await fetch('/api/files/download',{method:'POST',headers:{...authorization,'Content-Type':'application/json'},body:JSON.stringify({file:id})})
  if(!grant.ok)throw new Error('Could not authorize the attachment download.')
  const {url}=await grant.json()
  if(typeof url!=='string'||!url.startsWith('/api/files/download?ticket='))throw new Error('Download link unavailable.')
  const file=await fetch(url,{headers:authorization})
  if(!file.ok)throw new Error('The attachment is no longer available.')
  return file.blob()
}

export function downloadName(filename: string) {
  return filename.replace(/[\/\\:*?"<>|\u0000-\u001f]/g, '_').replace(/^\.+/, '_') || 'attachment'
}

export function saveDownload(data: Blob, filename: string) {
  const url = URL.createObjectURL(data)
  const link = document.createElement('a')
  link.href = url
  link.download = downloadName(filename)
  link.click()
  window.setTimeout(() => URL.revokeObjectURL(url), 5000)
}

export async function downloadChatFile(file: ChatFile) {
  const data = await fetchChatFile(file.id)
  saveDownload(new Blob([data], { type: 'application/octet-stream' }), file.filename)
}
