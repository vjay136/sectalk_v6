'use client'

import { useCallback, useEffect, useRef, useState } from 'react'
import type { RingtonePreset } from './profile-ringtones'

export type CallTone = 'ringtone' | 'ringback'

const incomingNotes = {
  classic: [[0, 0.24, 523.25, 659.25], [0.32, 0.24, 659.25, 783.99], [0.64, 0.28, 523.25, 783.99]],
  chime: [[0, 0.45, 587.33, 880], [0.55, 0.6, 659.25, 987.77]],
  pulse: [[0, 0.14, 440, 880], [0.22, 0.14, 440, 880], [0.53, 0.28, 554.37, 1108.73]],
  horizon: [[0, 0.22, 392, 587.33], [0.3, 0.22, 493.88, 739.99], [0.62, 0.4, 587.33, 880]],
} satisfies Record<RingtonePreset, number[][]>

export function callSoundBuffer(context: AudioContext, tone: CallTone, preset: RingtonePreset = 'classic') {
  const incoming = tone === 'ringtone'
  const seconds = incoming ? 3 : 5
  const sampleRate = context.sampleRate
  const buffer = context.createBuffer(1, seconds * sampleRate, sampleRate)
  const samples = buffer.getChannelData(0)
  const notes = incoming
    ? incomingNotes[preset]
    : [[0, 1.2, 440, 480]]

  for (const [start, duration, low, high] of notes) {
    const offset = Math.round(start * sampleRate)
    const length = Math.round(duration * sampleRate)
    for (let index = 0; index < length; index++) {
      const time = index / sampleRate
      const envelope = Math.min(1, time / 0.025, (duration - time) / 0.055)
      samples[offset + index] = 0.085 * envelope *
        (Math.sin(2 * Math.PI * low * time) + Math.sin(2 * Math.PI * high * time))
    }
  }
  return buffer
}

export type CallAudio = { context: AudioContext | null; enable: () => void }

// Keep the same Web Audio context across sign-in, onboarding and the inbox.
// Browsers may block incoming sounds until the first trusted interaction.
export function useCallAudioActivation(): CallAudio {
  const audio = useRef<AudioContext | null>(null)
  const [context, setContext] = useState<AudioContext | null>(null)

  const enable = useCallback(() => {
    if (typeof window.AudioContext !== 'function') return
    try {
      if (!audio.current || audio.current.state === 'closed') {
        audio.current = new window.AudioContext()
        setContext(audio.current)
      }
      if (audio.current.state !== 'running') void audio.current.resume().catch(() => undefined)
    } catch {
      // The visual and screen-reader alerts remain available without Web Audio.
    }
  }, [])

  useEffect(() => {
    const tryEnable = (event: Event) => {
      if (event.isTrusted && audio.current?.state !== 'running') enable()
    }
    window.addEventListener('click', tryEnable, true)
    window.addEventListener('keydown', tryEnable, true)
    return () => {
      window.removeEventListener('click', tryEnable, true)
      window.removeEventListener('keydown', tryEnable, true)
      const previous = audio.current
      audio.current = null
      if (previous && previous.state !== 'closed') void previous.close().catch(() => undefined)
    }
  }, [enable])

  return { context, enable }
}

export function useCallSounds({ context, enable }: CallAudio, tone: CallTone | null, callId?: string, expiresAt?: string,
  ringtone?: { selected: RingtonePreset | 'local'; local?: { file: Blob } }) {
  const [playing, setPlaying] = useState(false)
  const [decoded, setDecoded] = useState<{ context: AudioContext; file: Blob; buffer: AudioBuffer }>()
  const file = ringtone?.selected === 'local' ? ringtone.local?.file : undefined
  const custom = decoded && decoded.file === file && decoded.context === context ? decoded.buffer : null
  const preset = ringtone?.selected && ringtone.selected !== 'local' ? ringtone.selected : 'classic'

  useEffect(() => {
    if (!context || !file) return
    let current = true
    void file.arrayBuffer().then(bytes => context.decodeAudioData(bytes)).then(buffer => {
      if (current) setDecoded({ context, file, buffer })
    }).catch(() => undefined)
    return () => { current = false }
  }, [context, file])

  useEffect(() => {
    if (tone && !context) enable()
  }, [tone, context, enable])

  useEffect(() => {
    if (!tone || !callId || !context) return
    const deadline = Date.parse(expiresAt ?? '')
    if (!Number.isFinite(deadline) || deadline <= Date.now()) return
    let source: AudioBufferSourceNode | null = null
    const stop = () => {
      if (source) {
        source.stop()
        source.disconnect()
        source = null
      }
      setPlaying(false)
    }
    const update = () => {
      if (deadline <= Date.now()) {
        stop()
        return
      }
      if (context.state !== 'running') {
        setPlaying(false)
        return
      }
      if (!source) {
        source = context.createBufferSource()
        source.buffer = (tone === 'ringtone' && custom) || callSoundBuffer(context, tone, preset)
        source.loop = true
        source.connect(context.destination)
        source.start()
      }
      setPlaying(true)
    }
    context.addEventListener('statechange', update)
    update()
    const timer = window.setTimeout(stop, deadline - Date.now())
    return () => {
      window.clearTimeout(timer)
      context.removeEventListener('statechange', update)
      stop()
    }
  }, [tone, callId, expiresAt, context, custom, preset])

  return { enable, needsActivation: Boolean(tone && !playing && typeof AudioContext === 'function') }
}
