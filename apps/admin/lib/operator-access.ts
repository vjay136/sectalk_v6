import { operationalReportViewer } from '../../web/lib/operational-report-server'
import type { AccountOperatorAccess } from '../../web/components/account-administration'
import type { ThreatTriageAccess } from '../../web/components/threat-triage'

type Access = 'denied' | 'unavailable' | 'mfa' | 'verified'
type Assignment = 'none' | 'mfa' | 'verified'
type Admission = {access: Access; status: number; moderation?: boolean; queue?: Assignment; disclosures?: Assignment;
  workspaceReports?: Assignment; accounts?: AccountOperatorAccess; triage?: ThreatTriageAccess; responses?: boolean}

function assignment(value: unknown): Assignment {
  return value === 'verified' || value === 'mfa' ? value : 'none'
}

function recentTotp(methods: unknown, now: number) {
  return Array.isArray(methods) && methods.some(method => method?.method === 'totp'
    && Number.isSafeInteger(method.timestamp) && method.timestamp <= now && method.timestamp > now - 600)
}

export async function operatorAccess(request: Request): Promise<Admission> {
  const viewer = await operationalReportViewer(request)
  if (!viewer) return {access: 'denied', status: 401}
  const [risk, lock] = await Promise.all([
    viewer.client.rpc('st_v7_login_risk_status'),
    viewer.client.rpc('st_v7_account_lock_status'),
  ])
  if (risk.error || lock.error) return {access: 'unavailable', status: 503}
  if (risk.data === 'inactive') return {access: 'denied', status: 401}
  if (lock.data?.locked) return {access: 'denied', status: 423}
  // PostgREST denies business RPCs until the existing account assurance check clears.
  if (risk.data === 'authenticator') return {access: 'mfa', status: 200}
  if (risk.data !== 'clear') return {access: 'denied', status: 403}

  const [staff, queueRole, disclosureRole, workspaceRole, accountRole, triageRole, responseCatalog] = await Promise.all([
    viewer.client.rpc('st_staff_status'),
    viewer.client.rpc('st_v6_queue_operations_status'),
    viewer.client.rpc('st_v8_disclosure_access'),
    viewer.client.rpc('st_v6_room_report_review_access'),
    viewer.client.rpc('st_v7_account_operator_access'),
    viewer.client.rpc('st_v7_threat_triage_access'),
    viewer.client.rpc('st_v7_soc_response_catalog'),
  ])
  if (staff.error || queueRole.error) return {access: 'unavailable', status: 503}
  const workspaceReports = workspaceRole.error ? 'none' : assignment(workspaceRole.data)
  const accountCapability = accountRole.error ? null : accountRole.data
  const accounts = accountCapability === 'operator' || accountCapability === 'reviewer' || accountCapability === 'mfa'
    ? accountCapability : 'none'
  const accountVerified = accounts === 'operator' || accounts === 'reviewer'
  const nativeTriage = triageRole.error ? null : triageRole.data
  const triage: ThreatTriageAccess = nativeTriage?.status === 'verified' && Array.isArray(nativeTriage.scopes)
    ? {status:'verified', scopes:nativeTriage.scopes.filter((scope:unknown) => scope==='detection' || scope==='attachment_inspection' || scope==='malware')}
    : {status:nativeTriage?.status === 'mfa' ? 'mfa' : 'none'}
  const responses = !responseCatalog.error && Array.isArray(responseCatalog.data) && responseCatalog.data.length > 0
  if (staff.data === 'none' && workspaceReports === 'none' && accounts === 'none' && triage.status === 'none' && !responses)
    return {access: 'denied', status: 403}
  const verified = workspaceReports === 'verified' || accountVerified || triage.status === 'verified' || responses
  if (staff.data !== 'verified' && !verified) return {access: 'mfa', status: 200}
  const bearer = request.headers.get('Authorization')?.match(/^Bearer (\S+)$/i)?.[1]
  const proof = await viewer.client.auth.getClaims(bearer)
  if (proof.error) return {access: 'unavailable', status: 503}
  const claims = proof.data?.claims
  if (claims?.aal !== 'aal2' || !recentTotp(claims.amr, Math.floor(Date.now() / 1000)))
    return {access: 'mfa', status: 200}

  // The moderation business RPCs repeat the active-staff and native TOTP checks.
  const staffCheck = staff.data === 'verified' ? await viewer.client.rpc('st_v6_operational_report_settings') : null
  if (staffCheck?.error && staffCheck.error.code !== '42501') return {access: 'unavailable', status: 503}
  const moderation = staffCheck !== null && !staffCheck.error
  if (!moderation && !verified) return {access: 'denied', status: 403}
  return {access: 'verified', status: 200, moderation, workspaceReports, accounts, triage, responses,
    queue: moderation ? assignment(queueRole.data) : 'none',
    disclosures: moderation && !disclosureRole.error ? assignment(disclosureRole.data) : 'none'}
}
