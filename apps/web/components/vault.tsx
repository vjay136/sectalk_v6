'use client'

import { useCallback, useEffect, useState, type FormEvent } from 'react'
import { Download, LockKeyhole, Trash2, Upload } from 'lucide-react'
import { db } from '../lib/data'
import { lockFile, unlockFile, vaultFileLimit } from '../lib/vault'
import { SectionTabs } from './section-tabs'

type VaultObject = { name: string; id: string; created_at: string; metadata: { size?: number } | null }

export function Vault({ user }: { user: string }) {
  const [files,setFiles] = useState<VaultObject[] | null>(null)
  const [view,setView] = useState<'files'|'upload'>('files')
  const [selected,setSelected] = useState<VaultObject | null>(null)
  const [remove,setRemove] = useState(false)
  const [busy,setBusy] = useState(false)
  const [error,setError] = useState('')
  const [notice,setNotice] = useState('')
  const load = useCallback(async () => {
    const { data,error } = await db!.storage.from('sectalk-vault').list(user,{ limit: 100,sortBy:{column:'created_at',order:'desc'} })
    if (error) setError('Could not load your vault.')
    else setFiles(data as VaultObject[])
  },[user])
  useEffect(() => { void load() },[load])

  async function upload(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    if (busy) return
    const form = event.currentTarget
    const values = new FormData(form)
    const file = values.get('file')
    const password = String(values.get('password'))
    if (!(file instanceof File) || !file.name || file.size > vaultFileLimit) { setError('Choose a file up to 8 MiB.'); return }
    if (password !== values.get('confirm')) { setError('The passphrases do not match.'); return }
    setBusy(true); setError(''); setNotice('')
    try {
      const encrypted = await lockFile(file,password)
      const { error } = await db!.storage.from('sectalk-vault').upload(user+'/'+crypto.randomUUID()+'.stvault',encrypted,{ upsert:false,contentType:'application/octet-stream' })
      if (error) throw error
      form.reset()
      await load()
      setNotice('File encrypted and uploaded.')
      setView('files')
    } catch { setError('Could not encrypt or upload the file. Check the file size and try again.') }
    finally { setBusy(false) }
  }

  async function open(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    if (busy || !selected) return
    const form = event.currentTarget
    setBusy(true); setError(''); setNotice('')
    try {
      const path = user+'/'+selected.name
      if (remove) {
        const { error } = await db!.storage.from('sectalk-vault').remove([path])
        if (error) throw error
        await load()
        setNotice('Encrypted file removed.')
      } else {
        const { data,error } = await db!.storage.from('sectalk-vault').download(path)
        if (error) throw error
        const unlocked = await unlockFile(data,String(new FormData(form).get('password')))
        const url = URL.createObjectURL(unlocked.file)
        const anchor = document.createElement('a')
        anchor.href=url; anchor.download=unlocked.name
        anchor.click()
        window.setTimeout(() => URL.revokeObjectURL(url),1000)
        form.reset()
        setNotice('File decrypted on this device.')
      }
      setSelected(null)
    } catch {
      setError(remove ? 'Could not remove the encrypted file.' : 'Could not unlock this file. Check its passphrase.')
    } finally { setBusy(false) }
  }

  return <section className="content-page">
    <header className="content-title"><div className="card-icon"><LockKeyhole size={22}/></div><div><h1>Private vault</h1><p>Encrypt files and filenames on this device before they leave your browser.</p></div></header>
    <p className="release-info">Keep each file’s passphrase. SecTalk cannot recover it or open the file for you. File size and upload time remain visible to the service.</p>
    {error && <p role="alert" className="error">{error}</p>}
    {notice && <p role="status">{notice}</p>}
    <SectionTabs label="Vault sections" value={view} onChange={next=>{if(!busy){setView(next);setSelected(null);setError('')}}}
      options={ [['files','My files'], ['upload','Upload']] }/>
    {view==='upload' ? <div className="panel release-panel"><h2>Upload an encrypted file</h2>
      <form className="release-form" onSubmit={upload}>
        <label>File up to 8 MiB<input type="file" name="file" required disabled={busy}/></label>
        <label>File passphrase<input type="password" name="password" required minLength={12} maxLength={180} autoComplete="new-password"/></label>
        <label>Confirm passphrase<input type="password" name="confirm" required autoComplete="new-password"/></label>
        <button className="primary" disabled={busy}><Upload size={17}/> Encrypt and upload</button>
      </form>
    </div> :
    <div className="panel release-panel"><h2>Encrypted files</h2>
      {files === null && <p>Loading your vault…</p>}
      {files?.length === 0 && <p>Your vault is empty.</p>}
      {files?.map(file => <div className="release-row" key={file.name}>
        <strong>Encrypted file</strong><time dateTime={file.created_at}>{new Date(file.created_at).toLocaleString()}</time>
        {file.metadata?.size && <span className="pill">{Math.ceil(file.metadata.size/1024)} KiB</span>}
        <button className="secondary" disabled={busy} onClick={() => { setRemove(false);setSelected(file);setError('') }}><Download size={15}/> Unlock</button>
        <button className="secondary" disabled={busy} onClick={() => { setRemove(true);setSelected(file);setError('') }} aria-label="Remove encrypted file"><Trash2 size={15}/></button>
      </div>)}
      {selected && <form className="release-form" onSubmit={open}>
        {remove ? <p>Remove this encrypted file from your vault?</p> : <label>File passphrase<input key={selected.name} name="password" type="password" autoComplete="off" required/></label>}
        <div className="action-row"><button className={remove ? 'danger' : 'primary'} disabled={busy}>{remove ? 'Remove file' : 'Decrypt and download'}</button><button className="secondary" type="button" disabled={busy} onClick={() => setSelected(null)}>Cancel</button></div>
      </form>}
    </div>}
  </section>
}
