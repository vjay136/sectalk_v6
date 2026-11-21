'use client'

import { useEffect, useState } from 'react'
import { db } from '../lib/data'
import { useWorkspaceContext } from './workspace-context'

type Policy = { access: string; required?: boolean; error?: string }
type ScopeProps = { workspace: string; providerAvailable: boolean; onPolicyChanged?: () => Promise<void> }
const entryScope = {
  rpc: 'st_v8_workspace_entry_policy', title: 'Workspace entry', name: 'workspace entry',
  label: 'Workspace entry sign-in',
  description: 'Require workspace single sign-on for the workspace home, people, planning, conversations, files, invitations, member meetings, and integration management. Enabling it revokes existing room guest message links.',
  access: 'workspace home, planning, conversations, files, invitations, meetings and integration management',
}
const mediaScope = {
  rpc: 'st_v8_workspace_member_media_policy', title: 'Member meeting media', name: 'member media',
  label: 'Member meeting media sign-in',
  description: 'This policy applies to new audio and video credentials for workspace members. Current connections, guest links, meeting information and other workspace access follow their existing rules.',
  access: 'new member media credentials',
}
const channelScope = {
  rpc: 'st_v8_workspace_standard_channel_policy', title: 'Standard channel messages', name: 'standard channel messages',
  label: 'Standard channel message sign-in',
  description: 'This policy covers reading, sending, searching and submitting new reports on standard channel messages. Channel listings, other storage modes and previously shared evidence follow their existing rules.',
  access: 'standard channel messages',
}
const channelStructureScope = {
  rpc: 'st_v8_workspace_channel_structure_policy', title: 'Workspace channel directory', name: 'the channel directory',
  label: 'Workspace channel directory sign-in',
  description: 'Protect channel listings, creation, access lists, visibility, ownership and archiving with workspace single sign-on.',
  access: 'the channel directory and channel management',
}
const roomScope = {
  rpc: 'st_v8_workspace_standard_room_policy', title: 'Standard room messages', name: 'standard room messages',
  label: 'Standard room message sign-in',
  description: 'This policy covers reading, sending, searching and other room message actions. Enabling it revokes guest message links for standard rooms.',
  access: 'standard room messages',
}
const roomStructureScope = {
  rpc: 'st_v8_workspace_room_structure_policy', title: 'Workspace room directory', name: 'the room directory',
  label: 'Workspace room directory sign-in',
  description: 'Protect room listings, creation, membership, visibility, moderation settings and archiving with workspace single sign-on.',
  access: 'the room directory and room management',
}
const managedScope = {
  rpc: 'st_v8_workspace_managed_content_policy', title: 'Managed encrypted messages', name: 'managed messages',
  label: 'Managed encrypted message sign-in',
  description: 'Protect the managed room and channel message feeds, search, sending and new reports. Existing reports and compliance artifacts keep their own access rules.',
  access: 'managed encrypted messages',
}
const plannerScope = {
  rpc: 'st_v8_workspace_planner_policy', title: 'Workspace boards and tasks', name: 'workspace planning',
  label: 'Workspace planning sign-in',
  description: 'Protect board posts, task assignments, room tasks, calendar events and task deadlines with workspace single sign-on.',
  access: 'workspace planning',
}
const directoryScope = {
  rpc: 'st_v8_workspace_directory_policy', title: 'Workspace people', name: 'the workspace directory',
  label: 'Workspace directory sign-in',
  description: 'Protect the member list, member management, and profiles shared through this workspace with single sign-on.',
  access: 'the workspace directory',
}
const invitationAdminScope = {
  rpc: 'st_v8_workspace_invitation_admin_policy', title: 'Workspace invitation management', name: 'invitation management',
  label: 'Workspace invitation management sign-in',
  description: 'Protect invitation lists, handle and CSV invitations, email link issuance and approved invitation domains. Invited people can accept using their existing verified accounts.',
  access: 'workspace invitation management',
}
const integrationAdminScope = {
  rpc: 'st_v8_workspace_integration_admin_policy', title: 'Workspace API keys and webhooks', name: 'API keys and webhooks',
  label: 'Workspace integration credential sign-in',
  description: 'Protect viewing, creating and revoking API keys and outbound webhooks. Existing integrations continue to use their own credentials.',
  access: 'API key and webhook management',
}
const customRoleAdminScope = {
  rpc: 'st_v8_workspace_custom_role_admin_policy', title: 'Workspace custom roles', name: 'custom role management',
  label: 'Workspace custom role sign-in',
  description: 'Protect custom role definitions, assignments, file requirements and decision simulation. Members can continue to use existing assignments under their resource policies.',
  access: 'custom role management',
}
const policyAdminScope = {
  rpc: 'st_v8_workspace_policy_admin_policy', title: 'Workspace policies', name: 'policy management',
  label: 'Workspace policy management sign-in',
  description: 'Protect policy history, previews, updates and revision restoration across the workspace policy editor and its related settings.',
  access: 'workspace policy management',
}
const legalHoldScope = {
  rpc: 'st_v8_workspace_legal_hold_policy', title: 'Workspace legal holds', name: 'legal holds',
  label: 'Workspace legal hold sign-in',
  description: 'Require workspace single sign-on to view preservation hold details, place a hold, or release it.',
  access: 'legal hold administration',
}
const complianceScope = {
  rpc: 'st_v8_workspace_compliance_policy', title: 'Compliance exports and evidence', name: 'compliance exports and evidence',
  label: 'Workspace compliance export sign-in',
  description: 'Protect compliance case records, export approvals and downloads, and evidence custody with workspace single sign-on.',
  access: 'compliance exports and evidence',
}
const auditScope = {
  rpc: 'st_v8_workspace_audit_policy', title: 'Workspace audit logs', name: 'workspace audit logs',
  label: 'Workspace audit sign-in',
  description: 'Protect recent workspace activity, workspace audit search, and signed audit exports with single sign-on.',
  access: 'workspace audit logs',
}
const scheduleScope = {
  rpc: 'st_v8_workspace_schedule_policy', title: 'Workspace meeting schedules and lobbies', name: 'workspace meetings',
  label: 'Workspace meeting schedule sign-in',
  description: 'Protect workspace meeting details, schedules, participants and lobby decisions with single sign-on.',
  access: 'workspace meeting schedules and lobbies',
}
const groupsScope = {
  rpc: 'st_v8_workspace_groups_policy', title: 'Workspace groups and teams', name: 'groups and teams',
  label: 'Workspace groups and teams sign-in',
  description: 'Protect group, team and department listings, rosters and management with single sign-on.',
  access: 'workspace groups and teams',
}
const fileScope = {
  rpc: 'st_v8_workspace_file_policy', title: 'Workspace and room files', name: 'workspace and room files',
  label: 'Workspace file sign-in',
  description: 'Protect file listings, uploads, downloads, workspace links and file access history with single sign-on.',
  access: 'workspace and room files',
}
const billingScope = {
  rpc: 'st_v8_workspace_billing_policy', title: 'Workspace billing administration', name: 'workspace billing',
  label: 'Workspace billing sign-in',
  description: 'Protect workspace billing delegates, metered usage, seat purchases, invoice adjustments and workspace copies of billing documents.',
  access: 'workspace billing administration',
}
const organizationScope = {
  rpc: 'st_v8_workspace_organization_policy', title: 'Organization settings', name: 'organization settings',
  label: 'Organization settings sign-in',
  description: 'Protect branding changes, DNS verification, room retention, region requests and invitation templates with workspace single sign-on.',
  access: 'organization settings',
}

export function WorkspaceMemberMediaSso(props: ScopeProps) {
  return <SsoScopeControl {...props} scope={mediaScope} />
}

export function WorkspaceStandardChannelSso(props: ScopeProps) {
  return <SsoScopeControl {...props} scope={channelScope} />
}

export function WorkspaceChannelStructureSso(props: ScopeProps) {
  return <SsoScopeControl {...props} scope={channelStructureScope} />
}

export function WorkspaceStandardRoomSso(props: ScopeProps) {
  return <SsoScopeControl {...props} scope={roomScope} />
}

export function WorkspaceRoomStructureSso(props: ScopeProps) {
  return <SsoScopeControl {...props} scope={roomStructureScope} />
}

export function WorkspaceManagedContentSso(props: ScopeProps) {
  return <SsoScopeControl {...props} scope={managedScope} />
}

export function WorkspacePlannerSso(props: ScopeProps) {
  return <SsoScopeControl {...props} scope={plannerScope} />
}

export function WorkspaceDirectorySso(props: ScopeProps) {
  return <SsoScopeControl {...props} scope={directoryScope} />
}

export function WorkspaceInvitationAdminSso(props: ScopeProps) {
  return <SsoScopeControl {...props} scope={invitationAdminScope} />
}

export function WorkspaceIntegrationAdminSso(props: ScopeProps) {
  return <SsoScopeControl {...props} scope={integrationAdminScope} />
}

export function WorkspaceCustomRoleAdminSso(props: ScopeProps) {
  return <SsoScopeControl {...props} scope={customRoleAdminScope} />
}

export function WorkspacePolicyAdminSso(props: ScopeProps) {
  return <SsoScopeControl {...props} scope={policyAdminScope} />
}

export function WorkspaceLegalHoldSso(props: ScopeProps) {
  return <SsoScopeControl {...props} scope={legalHoldScope} />
}

export function WorkspaceComplianceSso(props: ScopeProps) {
  return <SsoScopeControl {...props} scope={complianceScope} />
}

export function WorkspaceEntrySso(props: ScopeProps) {
  const {reload}=useWorkspaceContext()
  return <SsoScopeControl {...props} scope={entryScope} onPolicyChanged={()=>reload(props.workspace)} />
}

export function WorkspaceAuditSso(props: ScopeProps) {
  return <SsoScopeControl {...props} scope={auditScope} />
}

export function WorkspaceScheduleSso(props: ScopeProps) {
  return <SsoScopeControl {...props} scope={scheduleScope} />
}

export function WorkspaceGroupsSso(props: ScopeProps) {
  return <SsoScopeControl {...props} scope={groupsScope} />
}

export function WorkspaceFileSso(props: ScopeProps) {
  return <SsoScopeControl {...props} scope={fileScope} />
}

export function WorkspaceBillingSso(props: ScopeProps) {
  return <SsoScopeControl {...props} scope={billingScope} />
}

export function WorkspaceOrganizationSso(props: ScopeProps) {
  return <SsoScopeControl {...props} scope={organizationScope} />
}

function SsoScopeControl({workspace,providerAvailable,onPolicyChanged,scope}: ScopeProps & {scope: typeof mediaScope}) {
  const [required, setRequired] = useState<boolean>()
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  useEffect(() => {
    const controller = new AbortController()
    void db!.rpc(scope.rpc,{p_workspace:workspace}).abortSignal(controller.signal)
      .then(result => {
        if (controller.signal.aborted) return
        if (result.error) setError('The sign-in policy could not be loaded.')
        else setRequired((result.data as Policy).required)
      })
    return () => controller.abort()
  }, [workspace,scope.rpc])

  async function update(next: boolean) {
    setBusy(true)
    setError('')
    try {
      const result = await db!.rpc(scope.rpc,{p_workspace:workspace,p_require:next})
      if (result.error) throw result.error
      const policy = result.data as Policy
      if (policy.access !== 'verified') {
        setError('Verify your authenticator again before changing this policy.')
      } else if (policy.error === 'verified_provider_session_required') {
        setError('Complete a workspace SSO sign-in before requiring it for '+scope.name+'.')
      } else {
        setRequired(policy.required)
        await onPolicyChanged?.()
      }
    } catch {
      setError('The sign-in policy could not be changed.')
    } finally {
      setBusy(false)
    }
  }

  if (!required && !providerAvailable && !error) return null
  const buttonScope=scope===mediaScope?'new member media':scope.name
  return <section className="release-section" aria-label={scope.label}>
    <h4>{scope.title}</h4>
    <p>{scope.description}</p>
    {required !== undefined && <p role="status">
      {required ? 'Workspace single sign-on is required for '+scope.access+'.' : 'Standard sign-in is allowed for '+scope.access+'.'}
    </p>}
    {required !== undefined && providerAvailable && <button type="button" className="secondary" disabled={busy} onClick={() => void update(true)}>
      {required ? 'Use configured provider for '+scope.name : 'Require SSO for '+buttonScope}
    </button>}
    {required && <button type="button" className="secondary" disabled={busy} onClick={() => void update(false)}>
      Allow standard sign-in for {buttonScope}
    </button>}
    {error && <p role="alert">{error}</p>}
  </section>
}
