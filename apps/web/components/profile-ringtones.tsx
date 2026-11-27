'use client'

import { useEffect, useRef, useState } from 'react'
import { AudioLines, Play, Square } from 'lucide-react'
import { callSoundBuffer, type CallAudio } from '../lib/call-sounds'
import { maxRingtoneSeconds, prepareRingtone, ringtonePresets, type useProfileRingtone } from '../lib/profile-ringtones'

export function ProfileRingtones({ audio, preference }: { audio: CallAudio; preference: ReturnType<typeof useProfileRingtone> }) {
  const { settings, save } = preference
  const [busy, setBusy] = useState(false)
  const [message, setMessage] = useState('')
  const [error, setError] = useState('')
  const [playing, setPlaying] = useState(false)
  const preview = useRef<AudioBufferSourceNode | null>(null)
  const generation = useRef(0)

  function stop() {
    generation.current++
    const source = preview.current
    preview.current = null
    if (source) { source.stop(); source.disconnect() }
    setPlaying(false)
  }

  useEffect(() => () => {
    generation.current++
    const source = preview.current
    preview.current = null
    if (source) { source.stop(); source.disconnect() }
  }, [])

  async function update(next: typeof settings) {
    stop()
    setMessage('')
    setError('')
    setBusy(true)
    try {
      await save(next)
      setMessage('Ringtone saved on this device.')
    } catch { setError('Could not save your ringtone on this device.') }
    finally { setBusy(false) }
  }

  async function chooseFile(file: File) {
    stop()
    setMessage('')
    setError('')
    const context = audio.context
    if (!context) { setError('Audio is unavailable on this device.'); return }
    setBusy(true)
    try {
      const local = await prepareRingtone(context, file)
      await save({ selected: 'local', local })
      setMessage('Custom ringtone saved on this device.')
    } catch (error) { setError(error instanceof Error ? error.message : 'Could not save the custom ringtone.') }
    finally { setBusy(false) }
  }

  async function togglePreview() {
    if (playing) { stop(); return }
    setError('')
    audio.enable()
    const context = audio.context
    if (!context) { setError('Audio is unavailable on this device.'); return }
    const current = ++generation.current
    setPlaying(true)
    try {
      await context.resume()
      const buffer = settings.selected === 'local' && settings.local
        ? await context.decodeAudioData(await settings.local.file.arrayBuffer())
        : callSoundBuffer(context, 'ringtone', settings.selected === 'local' ? 'classic' : settings.selected)
      if (current !== generation.current) return
      const source = context.createBufferSource()
      source.buffer = buffer
      source.connect(context.destination)
      preview.current = source
      source.onended = () => {
        if (preview.current !== source) return
        preview.current = null
        source.disconnect()
        setPlaying(false)
      }
      source.start()
    } catch {
      if (current === generation.current) {
        stop()
        setError('Could not play this ringtone.')
      }
    }
  }

  return <section className="release-section" aria-labelledby="profile-ringtones-title">
    <h2 id="profile-ringtones-title"><AudioLines size={19} aria-hidden="true" /> Call ringtone</h2>
    <p>Choose what you hear when an audio or video call arrives while SecTalk is open. Background alerts use your device’s notification sound.</p>
    <div className="release-form">
      <label>Incoming call ringtone
        <select value={settings.selected} disabled={busy} onChange={event => {
          const selected = event.target.value as typeof settings.selected
          void update({ ...settings, selected })
        }}>
          {Object.entries(ringtonePresets).map(([id, label]) => <option value={id} key={id}>{label}</option>)}
          {settings.local && <option value="local">Custom clip</option>}
        </select>
      </label>
      <button type="button" className="secondary" disabled={busy} onClick={() => void togglePreview()}>
        {playing ? <Square size={16} /> : <Play size={16} />} {playing ? 'Stop preview' : 'Preview ringtone'}
      </button>
      <label>Use an audio file
        <input type="file" accept=".mp3,.wav,.ogg,.m4a,audio/mpeg,audio/wav,audio/ogg,audio/mp4" disabled={busy}
          aria-describedby="ringtone-file-help" onChange={event => {
            const file = event.target.files?.[0]
            event.target.value = ''
            if (file) void chooseFile(file)
          }} />
      </label>
      <p id="ringtone-file-help" className="muted">MP3, WAV, Ogg, or M4A. Choose a clip of 1–{maxRingtoneSeconds} seconds, up to 2 MiB. The audio stays on this device.</p>
      {settings.local && <div className="release-flex">
        <span style={{ overflowWrap: 'anywhere' }}>{settings.local.name} · {Math.round(settings.local.seconds)} seconds</span>
        <button type="button" className="secondary" disabled={busy} onClick={() => void update({
          selected: settings.selected === 'local' ? 'classic' : settings.selected,
        })}>Remove custom clip</button>
      </div>}
      {message && <p role="status">{message}</p>}
      {error && <p role="alert">{error}</p>}
    </div>
  </section>
}
