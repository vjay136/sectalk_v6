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
  const session=await db!.auth.getSession()
  if(!session.data.session)throw new Error('Sign in to send attachments.')
  const result=await fetch('/api/files/publish',{
    method:'POST',headers:{Authorization:'Bearer '+session.data.session.access_token,'Content-Type':'application/json'},
    body:JSON.stringify({file:id,caption,mime:file.type}),
  })
  if(!result.ok){
    const value=await result.json().catch(()=>null)
    throw new Error(value?.error||'The attachment could not be published.')
  }
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
