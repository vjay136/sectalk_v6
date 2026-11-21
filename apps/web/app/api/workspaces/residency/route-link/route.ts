import {fileFailure,fileHeaders} from '../../../../../lib/authenticated-file-request'
import {exportIdPattern} from '../../../../../lib/export-storage-server'
import {operationalReportViewer} from '../../../../../lib/operational-report-server'

export const runtime='nodejs'

export async function GET(request:Request) {
  const viewer=await operationalReportViewer(request)
  if(!viewer)return fileFailure(401,'Sign in to open an approved destination.')
  const current=new URL(request.url)
  const workspace=current.searchParams.get('workspace')
  if(!workspace||!exportIdPattern.test(workspace))return fileFailure(400,'Choose a workspace.')
  const unavailable=()=>fileFailure(404,'The approved destination is unavailable.')
  const installed=await viewer.client.rpc('st_v8_residency_active_route',{p_workspace:workspace})
  if(installed.error)return unavailable()
  const result=installed.data?.status==='inactive'||installed.data?.status==='ready'
    ? await viewer.client.rpc('st_v8_residency_routing_rehearsal',{p_workspace:workspace})
    : installed
  const {data,error}=result
  if(error||data?.status!=='active'||typeof data.project!=='string')return unavailable()

  try {
    const source=new URL(process.env.SECTALK_APP_URL||'')
    const configured=JSON.parse(process.env.SECTALK_RESIDENCY_ROUTING_ORIGINS||'{}')
    if(!configured||!Object.hasOwn(configured,data.project)||typeof configured[data.project]!=='string')return unavailable()
    const target=new URL(configured[data.project])
    if(target.origin===source.origin||target.username||target.password||target.pathname!=='/'||target.search||target.hash)
      return unavailable()
    if(data.fixture===true ? target.protocol!=='http:'||target.hostname!=='127.0.0.1'||!target.port||
      source.protocol!=='http:'||source.hostname!=='127.0.0.1' : source.protocol!=='https:'||target.protocol!=='https:'||target.port||
      !/^(?:[a-z0-9-]+\.)+[a-z]{2,}$/i.test(target.hostname)||/\.(localhost|local|internal|test|invalid)$/i.test(target.hostname))return unavailable()
    target.searchParams.set('workspace',workspace)
    return Response.json({url:target.href},{headers:fileHeaders})
  } catch {
    return unavailable()
  }
}
