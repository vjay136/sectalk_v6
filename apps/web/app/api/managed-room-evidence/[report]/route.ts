import {fileFailure,fileHeaders} from '../../../../lib/authenticated-file-request'
import {exportIdPattern,exportStorage} from '../../../../lib/export-storage-server'
import {managedRoomRevision} from '../../../../lib/managed-room-revision'
import {operationalReportViewer} from '../../../../lib/operational-report-server'
import {openTenantRecord} from '../../../../lib/tenant-artifact-keys'

export const runtime='nodejs'
const unavailable=()=>fileFailure(404,'This evidence is unavailable. Platform staff need a fresh authenticator verification.')

export async function GET(request:Request,{params}:{params:Promise<{report:string}>}){
  const report=(await params).report.toLowerCase()
  if(!exportIdPattern.test(report))return unavailable()
  const viewer=await operationalReportViewer(request)
  if(!viewer)return fileFailure(401,'Sign in to open managed room evidence.')
  const store=exportStorage()
  if(!store)return unavailable()
  const access=await viewer.client.rpc('st_v8_managed_room_evidence_access',{p_report:report})
  if(access.error||access.data!==true)return unavailable()
  const stored=await store.rpc('st_v8_managed_room_evidence_envelope',{p_report:report})
  if(stored.error||!stored.data)return unavailable()
  const snapshot=stored.data
  try{
    if(managedRoomRevision(snapshot)!==snapshot.revision)return unavailable()
    const clear=await openTenantRecord(snapshot.key,'room:'+snapshot.room,snapshot.id,snapshot.sender,snapshot.envelope)
    try{
      const body=new TextDecoder('utf-8',{fatal:true}).decode(clear)
      const audited=await viewer.client.rpc('st_v8_managed_room_evidence_access',{
        p_report:report,p_revision:snapshot.revision,
      })
      if(audited.error||audited.data!==true)return unavailable()
      return Response.json({body},{headers:fileHeaders})
    }finally{clear.fill(0)}
  }catch{return unavailable()}
}
