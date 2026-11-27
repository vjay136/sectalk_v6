import { billingIdentity, billingWriter, origin, stripe } from '../../../../lib/stripe-server'
import { readBoundedText } from '../../../../lib/request-body'
import { billingMode, billingPausedResponse } from '../../../../lib/billing-mode'

export const runtime='nodejs'
const headers={'Cache-Control':'private, no-store'}
const uuid=/^[\da-f]{8}(?:-[\da-f]{4}){3}-[\da-f]{12}$/i
const response=(data:Record<string,unknown>,status=200)=>Response.json(data,{status,headers})

function trialPolicy() {
  const mode=process.env.SECTALK_WORKSPACE_TRIALS
  return mode==='optional'?'optional':mode==='required'&&stripe&&origin?'required':'unavailable'
}

export async function GET(request:Request) {
  if (billingMode() === 'free') return response({ policy: 'unavailable', billingPaused: true })
  const identity=await billingIdentity(request)
  if(!identity)return response({error:'Sign in to view your workspace trial.'},401)
  const workspace=new URL(request.url).searchParams.get('workspace')||''
  if(!uuid.test(workspace))return response({error:'Choose a workspace.'},400)
  const status=await identity.client.rpc('st_v7_workspace_trial_status',{p_workspace:workspace})
  if(status.error)return response({error:'Workspace trial unavailable.'},status.error.code==='42501'?403:503)
  return response({...status.data,policy:billingWriter?trialPolicy():'unavailable'})
}

export async function POST(request:Request) {
  if (billingMode() === 'free') return billingPausedResponse()
  const identity=await billingIdentity(request)
  if(!identity)return response({error:'Sign in to start a workspace trial.'},401)
  const policy=trialPolicy()
  if(policy==='unavailable'||!billingWriter)return response({error:'Workspace trials are unavailable on this deployment.'},503)
  const raw=await readBoundedText(request,2048)
  let payload
  try{payload=raw?JSON.parse(raw):null}catch{return response({error:'Invalid trial request.'},400)}
  if(!payload||typeof payload.workspace!=='string'||!uuid.test(payload.workspace)||!['professional','business'].includes(payload.plan)){
    return response({error:'Choose an available trial plan.'},400)
  }
  const proof=await identity.client.rpc('st_v8_workspace_trial_session',{p_workspace:payload.workspace})
  if(proof.error||!uuid.test(proof.data??''))return response({error:'Verify your current workspace sign-in to start a trial.'},403)
  const trial=await billingWriter.rpc('st_v8_start_workspace_trial_for_session',{
    p_workspace:payload.workspace,p_owner:identity.user.id,p_session:proof.data,p_plan:payload.plan,p_card_required:policy==='required',
  })
  if(trial.error){
    if(trial.error.code==='42501')return response({error:'Workspace trial unavailable.'},403)
    if(trial.error.code==='PT409')return response({error:trial.error.message},409)
    if(trial.error.code==='PT422')return response({error:'This trial plan is unavailable.'},422)
    return response({error:'The trial request could not be saved.'},503)
  }
  if(trial.data?.state==='active')return response({state:'active',expires_at:trial.data.expires_at})
  if(!stripe||!origin||!uuid.test(trial.data?.reservation||''))return response({error:'Card confirmation is unavailable.'},503)
  try{
    const session=trial.data.provider_session?await stripe.checkout.sessions.retrieve(trial.data.provider_session):
      await stripe.checkout.sessions.create({
        mode:'setup',currency:'usd',allowed_payment_method_types:['card'],customer_email:identity.user.email,
        client_reference_id:trial.data.reservation,metadata:{sectalk_workspace_trial:trial.data.reservation},
        expires_at:trial.data.expires_epoch,success_url:new URL('/?trial=return',origin).href,
        cancel_url:new URL('/?trial=return',origin).href,
      },{idempotencyKey:'sectalk-workspace-trial-'+trial.data.reservation})
    const attached=await billingWriter.rpc('st_v7_attach_trial_checkout',{
      p_reservation:trial.data.reservation,p_provider_session:session.id,
    })
    if(attached.error||!attached.data)return response({error:'Could not save the card confirmation session.'},503)
    return response({state:'pending',url:session.status==='open'?session.url:null})
  }catch{return response({error:'The card confirmation provider could not process this request.'},502)}
}
