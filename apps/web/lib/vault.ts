const magic = new Uint8Array([83,84,86,1])
const headerLength = 32
export const vaultFileLimit = 8 * 1024 * 1024
const encoder = new TextEncoder()
const decoder = new TextDecoder('utf-8', { fatal: true })

async function derive(password: string, salt: Uint8Array<ArrayBuffer>) {
  const material = await crypto.subtle.importKey('raw', encoder.encode(password), 'PBKDF2', false, ['deriveKey'])
  return crypto.subtle.deriveKey({ name: 'PBKDF2', salt, iterations: 600000, hash: 'SHA-256' },
    material, { name: 'AES-GCM', length: 256 }, false, ['encrypt','decrypt'])
}

export async function lockFile(file: File, password: string): Promise<Blob> {
  if (file.size > vaultFileLimit || password.length < 12) throw new Error('Choose a file up to 8 MiB and a passphrase of at least 12 characters.')
  const name = encoder.encode(file.name)
  if (!name.length || name.length > 1024) throw new Error('Choose a shorter filename.')
  const header = new Uint8Array(headerLength)
  header.set(magic)
  header.set(crypto.getRandomValues(new Uint8Array(16)),4)
  header.set(crypto.getRandomValues(new Uint8Array(12)),20)
  const bytes = new Uint8Array(await file.arrayBuffer())
  const clear = new Uint8Array(2 + name.length + bytes.length)
  new DataView(clear.buffer).setUint16(0,name.length)
  clear.set(name,2)
  clear.set(bytes,2+name.length)
  try {
    const key = await derive(password,header.slice(4,20))
    const encrypted = await crypto.subtle.encrypt({ name: 'AES-GCM', iv: header.slice(20), additionalData: header },key,clear)
    return new Blob([header,encrypted],{ type: 'application/octet-stream' })
  } finally {
    clear.fill(0)
    bytes.fill(0)
  }
}

export async function unlockFile(blob: Blob,password: string): Promise<{ name: string; file: Blob }> {
  if (blob.size < headerLength + 19 || blob.size > vaultFileLimit + 1074) throw new Error('Invalid vault file.')
  const data = new Uint8Array(await blob.arrayBuffer())
  if (!magic.every((value,index) => data[index] === value)) throw new Error('Unsupported vault file format.')
  const header = data.slice(0,headerLength)
  const key = await derive(password,header.slice(4,20))
  const clear = new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-GCM', iv: header.slice(20), additionalData: header },key,data.slice(headerLength)))
  try {
    const size = new DataView(clear.buffer).getUint16(0)
    if (!size || size > 1024 || size + 2 > clear.length) throw new Error('Invalid vault filename.')
    const name = decoder.decode(clear.subarray(2,2+size)).replace(/[\\/:*?"<>|\u0000-\u001f]/g,'_')
    return { name, file: new Blob([clear.subarray(2+size)],{ type: 'application/octet-stream' }) }
  } finally { clear.fill(0) }
}
