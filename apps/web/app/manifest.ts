import type { MetadataRoute } from 'next'

export default function manifest(): MetadataRoute.Manifest {
  return {
    id: '/',
    name: 'SecTalk by Eagle Security',
    short_name: 'SecTalk',
    description: 'SecTalk is a messaging and calling app by Eagle Security.',
    start_url: '/',
    scope: '/',
    display: 'standalone',
    background_color: '#0b1423',
    theme_color: '#0b1423',
    icons: [
      { src: '/pwa-192.png', sizes: '192x192', type: 'image/png' },
      { src: '/pwa-512.png', sizes: '512x512', type: 'image/png' },
    ],
  }
}
