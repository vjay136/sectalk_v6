'use client'

import { db } from './data'

export type ManagedSearchCursor = { before: string; beforeId: string }

export async function managedChannelRequest(channel: string, query?: URLSearchParams, input?: { id: string; body: string } |
  ({ search: string } & Partial<ManagedSearchCursor>)) {
  const {data:{session}}=await db!.auth.getSession()
  if (!session) throw new Error('Sign in again to access this channel.')
  const response=await fetch('/api/managed-channel/'+channel+(query?.size ? '?'+query : ''),{
    method:input ? 'POST' : 'GET',cache:'no-store',headers:{
      Authorization:'Bearer '+session.access_token,
      ...(input ? {'Content-Type':'application/json'} : {}),
    },body:input ? JSON.stringify(input) : undefined,
  })
  if (!response.ok) {
    const result=await response.json().catch(()=>null)
    throw Object.assign(new Error(result?.error ?? 'Managed channel access is unavailable.'),{code:result?.code,details:result?.details})
  }
  return input && 'id' in input ? undefined : response.json()
}
