'use client'

import { useEffect } from 'react'

export function OfflineRegistration() {
  useEffect(() => {
    if (process.env.NODE_ENV === 'production' && 'serviceWorker' in navigator) {
      void navigator.serviceWorker.register('/sectalk-sw.js', { updateViaCache: 'none' }).catch(() => undefined)
    }
  }, [])
  return null
}
