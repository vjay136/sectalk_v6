import type { SupabaseClient } from '@supabase/supabase-js'

export type WorkspaceBillingAccess = 'allowed' | 'required' | 'unavailable'
export const workspaceBillingSsoMessage = 'Sign in through your workspace provider to access billing records.'

export async function workspaceBillingAccess(client: SupabaseClient, workspace: string,
  signal?: AbortSignal): Promise<WorkspaceBillingAccess> {
  const request=client.rpc('st_v8_workspace_billing_access',{p_workspace:workspace})
  const {data,error}=await (signal?request.abortSignal(signal):request)
  return !error&&(data==='allowed'||data==='required')?data:'unavailable'
}
