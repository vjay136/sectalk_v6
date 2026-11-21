import {fileFailure,fileHeaders} from '../../../../../lib/authenticated-file-request'
import {exportIdPattern,exportStorage} from '../../../../../lib/export-storage-server'
import {operationalReportViewer} from '../../../../../lib/operational-report-server'
import {readBoundedText} from '../../../../../lib/request-body'
import {residencyRuntime,verifyProviderTarget,type ProviderTarget} from '../../../../../lib/residency-provider'

export const runtime='nodejs'
const unavailable=()=>fileFailure(404,'Dedicated target verification is unavailable for this session.')
const pending=()=>Response.json({status:'pending_verification'},{headers:fileHeaders,status:202})

export async function POST(request:Request) {
  const viewer=await operationalReportViewer(request)
  if(!viewer)return fileFailure(401,'Sign in with your reviewer account.')
  let id:unknown
  try {id=JSON.parse(await readBoundedText(request,2048)||'{}').request}
  catch {return fileFailure(400,'Choose a residency request.')}
  if(typeof id!=='string'||!exportIdPattern.test(id))return fileFailure(400,'Choose a residency request.')
  const storage=exportStorage()
  if(!storage)return pending()
  const begin=await viewer.client.rpc('st_v8_begin_residency_provider_check',{p_request:id})
  if(begin.error)return unavailable()
  if(typeof begin.data!=='string')return pending()
  const ticket=begin.data
  const result=await storage.rpc('st_v8_residency_provider_target',{p_ticket:ticket})
  const target=result.error?null:result.data as ProviderTarget|null
  if(!target)return pending()
  const config=residencyRuntime(target.project)
  if(!config||!await verifyProviderTarget(target,config))return pending()
  const finish=await storage.rpc('st_v8_finish_residency_provider_check',{
    p_ticket:ticket,p_cell:target.cell,p_project:target.project,p_region:target.region,p_organization:target.organization,
  })
  return !finish.error&&finish.data===true
    ?Response.json({status:'provider_target_verified'},{headers:fileHeaders})
    :pending()
}
