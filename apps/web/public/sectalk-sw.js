const cachePrefix = 'sectalk-offline-'
const cacheName = cachePrefix + 'v1'
const offlinePage = '/offline.html'

self.addEventListener('install', event => {
  event.waitUntil((async () => {
    const cache = await caches.open(cacheName)
    await cache.add(new Request(offlinePage, { cache: 'reload' }))
    await self.skipWaiting()
  })())
})

self.addEventListener('activate', event => {
  event.waitUntil((async () => {
    const keys = await caches.keys()
    await Promise.all(keys.filter(key => key.startsWith(cachePrefix) && key !== cacheName).map(key => caches.delete(key)))
    await self.clients.claim()
  })())
})

self.addEventListener('fetch', event => {
  const request = event.request
  if (request.method !== 'GET' || request.mode !== 'navigate' || new URL(request.url).origin !== self.location.origin) return
  event.respondWith(fetch(request).catch(async () => {
    const cache = await caches.open(cacheName)
    return (await cache.match(offlinePage)) || Response.error()
  }))
})

self.addEventListener('push', event => {
  try {
    const payload = event.data?.json()
    if (!payload || payload.v !== 1) return
  } catch { return }
  event.waitUntil(self.registration.showNotification('SecTalk', {
    body: 'You have a new alert. Open SecTalk to view it.',
    icon: '/pwa-192.png',
    tag: 'sectalk-update',
  }))
})

self.addEventListener('notificationclick', event => {
  event.notification.close()
  event.waitUntil((async () => {
    const target = new URL('/', self.location.origin).href
    const windows = await self.clients.matchAll({ type: 'window', includeUncontrolled: true })
    const existing = windows.find(client => new URL(client.url).origin === self.location.origin
      && new URL(client.url).pathname === '/')
    if (existing) return existing.focus()
    return self.clients.openWindow(target)
  })())
})
