'use client'

import { useCallback, useEffect, useState } from 'react'

export const ringtonePresets = {
  classic: 'SecTalk Classic',
  chime: 'Soft Chime',
  pulse: 'Neon Pulse',
  horizon: 'Horizon',
} as const

export type RingtonePreset = keyof typeof ringtonePresets
type LocalTone = { file: Blob; name: string; seconds: number }
type Settings = { selected: RingtonePreset | 'local'; local?: LocalTone }
export const maxRingtoneSeconds = 20
const maxRingtoneSize = 2 * 1024 * 1024
const defaults: Settings = { selected: 'classic' }

function openDatabase() {
  return new Promise<IDBDatabase>((resolve, reject) => {
    const request = indexedDB.open('sectalk-call-sounds', 1)
    request.onupgradeneeded = () => request.result.createObjectStore('ringtones')
    request.onsuccess = () => resolve(request.result)
    request.onerror = () => reject(request.error)
  })
}

async function readSettings(user: string) {
  const database = await openDatabase()
  try {
    return await new Promise<Settings>((resolve, reject) => {
      const request = database.transaction('ringtones').objectStore('ringtones').get(user)
      request.onsuccess = () => resolve(request.result ?? defaults)
      request.onerror = () => reject(request.error)
    })
  } finally { database.close() }
}

async function writeSettings(user: string, settings: Settings) {
  const database = await openDatabase()
  try {
    await new Promise<void>((resolve, reject) => {
      const transaction = database.transaction('ringtones', 'readwrite')
      transaction.oncomplete = () => resolve()
      transaction.onabort = () => reject(transaction.error)
      transaction.objectStore('ringtones').put(settings, user)
    })
  } finally { database.close() }
}

export function useProfileRingtone(user: string) {
  const [snapshot, setSnapshot] = useState<{ user: string; settings: Settings }>()
  useEffect(() => {
    let current = true
    void readSettings(user).then(settings => {
      if (current) setSnapshot({ user, settings })
    }).catch(() => undefined)
    return () => { current = false }
  }, [user])

  const settings = snapshot?.user === user ? snapshot.settings : defaults
  const save = useCallback(async (settings: Settings) => {
    await writeSettings(user, settings)
    setSnapshot({ user, settings })
  }, [user])
  return { settings, save }
}

export async function prepareRingtone(context: AudioContext, file: File) {
  if (!/\.(mp3|wav|ogg|m4a)$/i.test(file.name) || file.size === 0 || file.size > maxRingtoneSize) {
    throw new Error('Choose an MP3, WAV, Ogg, or M4A file up to 2 MiB.')
  }
  const url = URL.createObjectURL(file)
  const media = new Audio()
  try {
    const seconds = await new Promise<number>((resolve, reject) => {
      const timer = setTimeout(() => reject(new Error('The audio file took too long to read.')), 5000)
      media.onloadedmetadata = () => { clearTimeout(timer); resolve(media.duration) }
      media.onerror = () => { clearTimeout(timer); reject(new Error('This device could not read the audio file.')) }
      media.preload = 'metadata'
      media.src = url
    })
    if (!Number.isFinite(seconds) || seconds < 1 || seconds > maxRingtoneSeconds) {
      throw new Error(`Choose an audio clip between 1 and ${maxRingtoneSeconds} seconds.`)
    }
    const audio = await context.decodeAudioData(await file.arrayBuffer()).catch(() => {
      throw new Error('This device could not decode the audio file.')
    })
    if (audio.duration < 1 || audio.duration > maxRingtoneSeconds) {
      throw new Error(`Choose an audio clip between 1 and ${maxRingtoneSeconds} seconds.`)
    }
    return { file, name: file.name, seconds: audio.duration }
  } finally {
    media.onloadedmetadata = null
    media.onerror = null
    media.removeAttribute('src')
    media.load()
    URL.revokeObjectURL(url)
  }
}
