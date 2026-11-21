'use client'

import { useEffect, useState, type ReactNode } from 'react'
import { db, onReconnect } from '../lib/data'

type Access = 'allowed' | 'required' | 'error'

export function useWorkspacePlannerAccess(workspace: string) {
  const [state, setState] = useState<{workspace: string; access: Access}>()
  useEffect(() => {
    let request: AbortController | undefined
    const load = async () => {
      request?.abort()
      const controller = new AbortController()
      request = controller
      const result = await db!.rpc('st_v8_workspace_planner_requires_sso', {
        p_workspace: workspace,
      }).abortSignal(controller.signal)
      if (!controller.signal.aborted) {
        setState({workspace, access: result.error ? 'error' : result.data ? 'required' : 'allowed'})
      }
    }
    void load()
    const reconnect = onReconnect(load)
    const timer = window.setInterval(load, 10000)
    return () => {
      request?.abort()
      reconnect()
      window.clearInterval(timer)
    }
  }, [workspace])
  return state?.workspace === workspace ? state.access : undefined
}

export function WorkspacePlannerAccessNotice({access}: {access?: Access}) {
  if (access === 'allowed') return null
  if (access === 'error') return <p role="alert">Could not check workspace planning access.</p>
  return <p role="status">{access === 'required'
    ? 'Sign in through your workspace provider to access workspace boards, tasks, and events.'
    : 'Checking workspace planning access…'}</p>
}

export function WorkspacePlannerAccess({workspace, children}: {workspace: string; children: ReactNode}) {
  const access = useWorkspacePlannerAccess(workspace)
  if (access === 'allowed') return children
  return <WorkspacePlannerAccessNotice access={access}/>
}
