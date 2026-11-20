import { db } from './data'

export const chatFileLimit = 4 * 1024 * 1024
export const extensions = '.png,.jpg,.jpeg,.webp,.gif,.pdf,.txt'
export type ChatFile = { id: string; message_id?: string; filename: string; size_bytes: number }

export function supportedFile(file: File) {
  return file.size > 0 && file.size <= chatFileLimit &&
    /\.(png|jpe?g|webp|gif|pdf|txt)$/i.test(file.name) && [...file.name].length <= 140
}

export async function sendChatFile(chat: string, id: string, file: File, caption: string) {
  const { data: uploaded, error } = await db!.rpc('st_v5_stage_file', {
    p_chat: chat, p_id: id, p_filename: file.name, p_bytes: file.size,
  })
  if (error) throw error
  if (!uploaded) {
    const { error } = await db!.storage.from('sectalk-chat-files').upload(id, await file.arrayBuffer(), {
      contentType: 'application/octet-stream', upsert: false,
    })
    if (error) throw error
  }
  const result = await db!.rpc('st_v5_send_file', { p_id: id, p_caption: caption })
  if (result.error) throw result.error
}

export async function fetchChatFile(id: string) {
  const { data, error } = await db!.storage.from('sectalk-chat-files').download(id)
  if (error) throw error
  return data
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
