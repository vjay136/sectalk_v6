'use client'

import { useEffect, useState } from 'react'
import type { RealtimeChannel } from '@supabase/supabase-js'
import { db } from './data'

type AnalyticsRpc = 'st_v6_delivery_latency' | 'st_v6_usage_metrics'

export function useAnalyticsStream(enabled: boolean) {
  const [revision, setRevision] = useState(0)

  useEffect(() => {
    if (!enabled) return
    const client = db!
    let active = true
    let channel: RealtimeChannel | undefined
    let refreshTimer: number | undefined
    function scheduleRefresh() {
      if (!active || refreshTimer !== undefined) return
      refreshTimer = window.setTimeout(() => {
        refreshTimer = undefined
        if (active) setRevision(value => value + 1)
      }, 150)
    }

    void client.auth.getSession().then(async ({ data }) => {
      if (!active || !data.session) return
      // An MFA challenge changes the API token before Realtime's next automatic refresh.
      await client.realtime.setAuth(data.session.access_token)
      if (!active) return
      channel = client.channel('st:analytics:' + data.session.user.id, { config: { private: true } })
        .on('broadcast', { event: 'analytics_refresh' }, scheduleRefresh)
        .subscribe(status => {
          if (status === 'SUBSCRIBED') scheduleRefresh()
        })
    })
    window.addEventListener('online', scheduleRefresh)
    return () => {
      active = false
      window.clearTimeout(refreshTimer)
      window.removeEventListener('online', scheduleRefresh)
      if (channel) void client.removeChannel(channel)
    }
  }, [enabled])
  return revision
}

export function useAnalyticsSnapshot<T>(rpc: AnalyticsRpc, period: string, revision: number) {
  const [result, setResult] = useState<{ period: string; value: T | null; error: boolean } | null>(null)
  const [attempt, setAttempt] = useState(0)

  useEffect(() => {
    const request = new AbortController()
    void db!.rpc(rpc, { p_window: period, p_live: true }).abortSignal(request.signal).then(({ data, error }) => {
      if (!request.signal.aborted) setResult({ period, value: error ? null : data as T, error: Boolean(error) })
    })
    return () => request.abort()
  }, [rpc, period, revision, attempt])

  useEffect(() => {
    // Keep the viewer lease alive and catch up if Realtime cannot reconnect.
    const timer = window.setInterval(() => setAttempt(value => value + 1), 90000)
    return () => window.clearInterval(timer)
  }, [])

  return {
    snapshot: result?.period === period ? result.value : null,
    error: result?.period === period && result.error,
    refresh: () => setAttempt(value => value + 1),
  }
}
