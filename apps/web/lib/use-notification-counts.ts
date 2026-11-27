'use client'

import {useEffect, useState} from 'react'
import {db, liveChannel, onReconnect} from './data'

export function useNotificationCounts(user: string, hints: EventTarget) {
  const [counts, setCounts] = useState({meetings: 0, mentions: 0, tasks: 0})
  useEffect(() => {
    const client = db!
    let disposed = false
    let pending = false
    let dirty = false
    const refresh = async () => {
      if (disposed) return
      if (pending) { dirty = true; return }
      pending = true
      try {
        const deadline = AbortSignal.timeout(8000)
        const alerts = () => client.from('st_v3_notifications').select('id',{head:true,count:'exact'})
          .eq('recipient',user).is('read_at',null).abortSignal(deadline)
        const [meetings, mentions, tasks] = await Promise.all([
          alerts().like('kind','meeting.%').not('meeting_id','is',null),
          alerts().like('kind','mention.%').not('room_id','is',null),
          client.from('st_v6_task_notices').select('id',{head:true,count:'exact'})
            .eq('recipient',user).is('read_at',null).abortSignal(deadline),
        ])
        if (!disposed) setCounts(previous => ({
          meetings: meetings.count ?? previous.meetings,
          mentions: mentions.count ?? previous.mentions,
          tasks: tasks.count ?? previous.tasks,
        }))
      } catch {
        // Keep the last confirmed counts until the next sync.
      } finally {
        pending = false
        if (dirty) { dirty = false; void refresh() }
      }
    }
    const channel = liveChannel('notification-counts:'+user,refresh)
      .on('postgres_changes',{event:'*',schema:'public',table:'st_v3_notifications',filter:'recipient=eq.'+user},refresh)
      .on('postgres_changes',{event:'*',schema:'public',table:'st_v6_task_notices',filter:'recipient=eq.'+user},refresh)
      .subscribe()
    const reconnect = onReconnect(refresh)
    hints.addEventListener('notification_read',refresh)
    const poll = window.setInterval(refresh,20000)
    void refresh()
    return () => {
      disposed = true
      window.clearInterval(poll)
      hints.removeEventListener('notification_read',refresh)
      reconnect()
      void client.removeChannel(channel)
    }
  }, [user,hints])
  return counts
}
