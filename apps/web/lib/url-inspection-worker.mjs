import { lookup } from 'node:dns/promises'
import { request } from 'node:https'
import { publicWebhookAddress } from './webhook-transport.ts'
import { inspectionDomainSignals, normalizeInspectionUrl } from './url-inspection-policy.mjs'
import { urlReputation } from './url-reputation-feed.mjs'

const redirectStatuses = new Set([301,302,303,307,308])

function withDeadline(promise, signal) {
  return new Promise((resolve, reject) => {
    if (signal.aborted) { reject(signal.reason); return }
    const abort = () => reject(signal.reason)
    signal.addEventListener('abort', abort, { once: true })
    promise.then(resolve, reject).finally(() => signal.removeEventListener('abort', abort))
  })
}

export function chooseInspectionAddress(answers) {
  if (!answers.length || answers.some(answer => !publicWebhookAddress(answer.address))) return null
  return answers.find(answer => answer.family === 4)?.address ?? answers[0].address
}

async function resolveApprovedHost(host, signal) {
  return chooseInspectionAddress(await withDeadline(lookup(host, { all: true }), signal))
}

function inspectHeaders(url, address, signal) {
  return new Promise((resolve, reject) => {
    if (!publicWebhookAddress(address)) { reject(new Error('Destination denied')); return }
    const outgoing = request({
      hostname: address, servername: url.hostname, port: 443, path: url.pathname,
      method: 'HEAD', rejectUnauthorized: true, agent: false, signal, maxHeaderSize: 8192,
      headers: { Host: url.hostname, 'User-Agent': 'SecTalk-Link-Inspection/1.0', Accept: '*/*' },
    }, response => {
      const status = response.statusCode ?? 0
      const location = response.headers.location
      response.destroy()
      resolve({ status, location })
    })
    outgoing.on('error', reject)
    outgoing.end()
  })
}

export async function inspectUserUrl(raw, approvedHosts, feed, transport = { resolve: resolveApprovedHost, head: inspectHeaders }) {
  const initial = normalizeInspectionUrl(raw)
  if (!initial) return null
  const deadline = AbortSignal.timeout(6500)
  let current = initial.url
  let outcome = 'blocked'
  const hops = []
  const visited = new Set()
  for (let redirects = 0; redirects <= 3; redirects++) {
    if (current.protocol !== 'https:' || !approvedHosts.has(current.hostname)) break
    if (visited.has(current.href)) { outcome = 'redirect-limit'; break }
    visited.add(current.href)
    try {
      const hopDeadline = AbortSignal.any([deadline, AbortSignal.timeout(2300)])
      const address = await transport.resolve(current.hostname, hopDeadline)
      if (!address) break
      const result = await transport.head(current, address, hopDeadline)
      if (!Number.isInteger(result.status) || result.status < 100 || result.status > 599) {
        outcome = 'unavailable'; break
      }
      hops.push({ url: current.href, status: result.status })
      if (!redirectStatuses.has(result.status)) { outcome = 'checked'; break }
      if (redirects === 3) { outcome = 'redirect-limit'; break }
      outcome = 'blocked'
      if (typeof result.location !== 'string' || result.location.length > 1500) break
      const next = normalizeInspectionUrl(new URL(result.location, current).href)
      if (!next) break
      current = next.url
    } catch { outcome = 'unavailable'; break }
  }
  const hosts = new Map([[initial.url.hostname, initial.url]])
  for (const hop of hops) {
    const url = new URL(hop.url)
    hosts.set(url.hostname, url)
  }
  return { normalized: initial.url.href, stripped: initial.stripped, outcome, hops,
    domains: [...hosts.values()].map(url => ({ ...inspectionDomainSignals(url), reputation: urlReputation(url.hostname, feed) })) }
}
