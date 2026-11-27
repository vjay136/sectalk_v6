import { isIP } from 'node:net'

/** @param {NodeJS.ProcessEnv} env */
export function speechWorkerConfig(env = process.env) {
  const { MEETING_CAPTIONS_WORKER_URL: worker, MEETING_CAPTIONS_WORKER_TOKEN: secret,
    SECTALK_SPEECH_WORKER_HTTPS_ORIGIN: trustedOrigin } = env
  if (!worker || !secret || secret.length < 24 || /\s/.test(secret)) return null
  const endpoint = URL.parse(worker)
  if (!endpoint || endpoint.username || endpoint.password || endpoint.href !== endpoint.origin + '/transcribe') return null

  if (endpoint.protocol === 'http:' && endpoint.hostname === '127.0.0.1' && endpoint.port && !trustedOrigin) {
    return { endpoint, secret }
  }

  const hostname = endpoint.hostname
  if (endpoint.protocol !== 'https:' || endpoint.origin !== trustedOrigin || endpoint.port ||
    isIP(hostname) || !hostname.includes('.') || hostname.startsWith('[') ||
    /\.(?:localhost|local|internal|test|invalid|example|onion)\.?$/i.test(hostname)) return null

  return { endpoint, secret }
}
