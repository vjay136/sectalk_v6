export const cameraFilters = {
  natural: 'none',
  soft: 'brightness(106%) contrast(92%) saturate(108%) blur(.35px)',
  warm: 'sepia(20%) saturate(118%) brightness(106%)',
  cool: 'hue-rotate(14deg) saturate(86%) contrast(105%)',
  vivid: 'saturate(142%) contrast(109%)',
  mono: 'grayscale(100%) contrast(112%)',
} as const

export const cameraDecorations = {
  none: '', fox: '🦊', owl: '🦉', butterfly: '🦋', hearts: '💕', stars: '✨', glitter: '✦',
} as const

export type CameraEffects = { filter: keyof typeof cameraFilters; decoration: keyof typeof cameraDecorations }
export const noCameraEffects: CameraEffects = { filter: 'natural', decoration: 'none' }

export function cameraEffectsSupported() {
  return typeof HTMLCanvasElement !== 'undefined' && typeof HTMLCanvasElement.prototype.captureStream === 'function' &&
    typeof CanvasRenderingContext2D !== 'undefined' && 'filter' in CanvasRenderingContext2D.prototype
}

export async function createCameraEffect(camera: MediaStreamTrack, effects: CameraEffects, signal: AbortSignal) {
  signal.throwIfAborted()
  const canvas = document.createElement('canvas')
  const context = canvas.getContext('2d', { alpha: false })
  if (!context || !cameraEffectsSupported()) throw new Error('Camera effects are unavailable')

  const video = document.createElement('video')
  video.muted = true
  video.playsInline = true
  video.srcObject = new MediaStream([camera])
  let track: MediaStreamTrack | undefined
  let frame = 0
  let current = effects
  const frameInterval = 1000 / 24
  let lastFrame = 0
  const videoFrames = typeof video.requestVideoFrameCallback === 'function'
  const reduceMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches
  let stopped = false

  function stop() {
    if (stopped) return
    stopped = true
    if (videoFrames) video.cancelVideoFrameCallback(frame)
    else cancelAnimationFrame(frame)
    track?.stop()
    video.pause()
    video.srcObject = null
    camera.removeEventListener('ended', stop)
    signal.removeEventListener('abort', stop)
  }

  function paint(now: number) {
    if (!context || !video.videoWidth || !video.videoHeight) return
    const scale = Math.min(1, 960 / Math.max(video.videoWidth, video.videoHeight))
    const width = Math.max(2, 2 * Math.floor(video.videoWidth * scale / 2))
    const height = Math.max(2, 2 * Math.floor(video.videoHeight * scale / 2))
    if (canvas.width !== width || canvas.height !== height) { canvas.width = width; canvas.height = height }
    if (!camera.enabled || camera.muted) {
      context.filter = 'none'
      context.fillStyle = '#000'
      context.fillRect(0, 0, width, height)
      return
    }
    context.filter = cameraFilters[current.filter]
    context.drawImage(video, 0, 0, width, height)
    context.filter = 'none'
    if (current.decoration === 'none') return
    const size = Math.min(width, height)
    const seconds = reduceMotion ? 0 : now / 1000
    context.textAlign = 'center'
    context.textBaseline = 'middle'
    if (current.decoration === 'glitter') {
      for (let i = 0; i < 14; i++) {
        const x = width * (0.05 + ((i * 37 % 89) / 100))
        const y = height * (0.08 + ((i * 29 % 68) / 100))
        context.globalAlpha = .54 + .34 * Math.sin(seconds * 2 + i)
        context.font = `${size * (.025 + i % 5 * .007)}px sans-serif`
        context.fillStyle = i % 2 ? '#fef3b8' : '#fff'
        context.fillText('✦', x, y)
      }
      context.globalAlpha = 1
    } else {
      const animal = current.decoration === 'fox' || current.decoration === 'owl'
      context.fillStyle = '#fff'
      context.font = `${size * (animal ? .2 : .125)}px sans-serif`
      const bounce = Math.sin(seconds * 1.8) * size * .017
      const emoji = cameraDecorations[current.decoration]
      if (animal) context.fillText(emoji, width * .5, height * .23 + bounce)
      else {
        context.fillText(emoji, width * .16, height * .24 + bounce)
        context.fillText(emoji, width * .83, height * .33 - bounce)
      }
    }
  }

  function render(now: number) {
    if (stopped) return
    const elapsed = now - lastFrame
    if (elapsed >= frameInterval) {
      lastFrame = now - elapsed % frameInterval
      paint(now)
    }
    frame = videoFrames ? video.requestVideoFrameCallback(render) : requestAnimationFrame(render)
  }

  signal.addEventListener('abort', stop, { once: true })
  camera.addEventListener('ended', stop, { once: true })
  const playbackTimeout = window.setTimeout(stop, 5000)
  try {
    await video.play()
    signal.throwIfAborted()
    if (stopped || !video.videoWidth || !video.videoHeight) throw new Error('Camera frames are unavailable')
    paint(performance.now())
    const output = canvas.captureStream()
    track = output.getVideoTracks()[0]
    if (!track) throw new Error('Camera effects are unavailable')
    // A paused/disabled camera must immediately mute the published output as well.
    track.enabled = camera.enabled
    render(performance.now())
    return { track, stream: output, update(next: CameraEffects) { current = next } }
  } catch (error) {
    stop()
    throw error
  } finally {
    window.clearTimeout(playbackTimeout)
  }
}
