import { db } from './data'

export type GroupState={id:string;owner:string;topology:'mesh'|'promoting'|'sfu'|'demoting';generation:number;sfuGeneration:number;
  joined:string[];mesh:string[];expiresAt:string;names:Record<string,string>;video:boolean}
export type GroupTracks={audio?:MediaStream;video?:MediaStream}
export type GroupSignal={id:number;sender:string;kind:'offer'|'answer'|'ice';payload:RTCSessionDescriptionInit|RTCIceCandidateInit}
export type GroupAccess={url:string;token:string;generation:number}
export type GroupCommand=(action:string,call?:string,extra?:Record<string,unknown>)=>Promise<unknown>

export async function groupCommand(device:string,action:string,call?:string,extra:Record<string,unknown>={}) {
  const result=await db!.rpc('st_v6_group_call',{p_action:action,p_device:device,p_call:call ?? null,...extra})
    .abortSignal(AbortSignal.timeout(4500))
  if (result.error) throw result.error
  return result.data
}

export async function groupConfig(action:'ice'|'sfu',call:string,device:string,signal?:AbortSignal) {
  const {data}=await db!.auth.getSession()
  const timeout=AbortSignal.timeout(8000)
  const response=await fetch('/api/group-calls',{method:'POST',signal:signal?AbortSignal.any([signal,timeout]):timeout,headers:{'Content-Type':'application/json',
    Authorization:'Bearer '+data.session?.access_token},body:JSON.stringify({action,call,device})})
  if (!response.ok) throw new Error('Group connection unavailable')
  return response.json()
}

export async function reportGroupPromotionFailure(call:string,device:string,generation:number) {
  return db!.rpc('st_v6_group_promotion_failed',{
    p_call:call,p_device:device,p_generation:generation,
  }).abortSignal(AbortSignal.timeout(4500))
}
