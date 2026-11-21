'use client'

import { useCallback, useEffect, useRef, useState } from 'react'

export type CallTone = 'ringtone' | 'ringback'

function callSoundBuffer(context: AudioContext, tone: CallTone) {
  const incoming = tone === 'ringtone'
  const seconds = incoming ? 3 : 5
  const sampleRate = context.sampleRate
  const buffer = context.createBuffer(1, seconds * sampleRate, sampleRate)
  const samples = buffer.getChannelData(0)
  const notes = incoming
    ? [[0, 0.24, 523.25, 659.25], [0.32, 0.24, 659.25, 783.99], [0.64, 0.28, 523.25, 783.99]]
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

export function useCallSounds(tone: CallTone | null, callId?: string, expiresAt?: string) {
  const audio = useRef<AudioContext | null>(null)
  const [context, setContext] = useState<AudioContext | null>(null)
  const [playing, setPlaying] = useState(false)

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
        source.buffer = callSoundBuffer(context, tone)
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
  }, [tone, callId, expiresAt, context])

  return { enable, needsActivation: Boolean(tone && !playing && typeof AudioContext === 'function') }
}
