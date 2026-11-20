import {mkdirSync,writeFileSync} from 'node:fs'
import {pathToFileURL} from 'node:url'
import {rpcInventory} from './rpc-permission-inventory.mjs'

export const roles={
  owner:'Workspace owner; scoped roster, governance, and independently reviewed exports.',
  admin:'Workspace administrator; subordinate member access management and compliance requests.',
  security_admin:'Pending as a distinct delegated workspace role.',
  billing_admin:'Explicitly delegated workspace billing read access. Workspace owners manage grants after recent verification.',
  compliance_officer:'Pending as a distinct role. Existing compliance exports use separate workspace administrator and owner decisions.',
  soc_lead:'Pending as a distinct global role. Existing case escalation and operation grants remain scoped.',
  soc_analyst:'Pending as a distinct global role. Existing platform staff access does not confer all analyst permissions.',
  moderator:'Scoped to a room. Target hierarchy and room policy apply.',
  member:'Current workspace or room membership with per-record policy checks.',
  guest:'Only the authorized room or meeting under the corresponding guest grant.',
  managed_member:'Verified Family or School participant with a live, separately accepted scope.',
  'guardian/teacher':'Explicit, workspace-scoped oversight. Device health and contact controls require current consent.',
  platform_operator:'Assignment specific. Account operators and independent reviewers get different actions.',
  platform_security:'Assignment specific. Native verified staff and explicit queue, case, or evidence authority are checked separately.',
  read_only:'Existing room membership variant. It grants permitted reads only.',
}

export const permissions={
  'account.sign_in':'Native credential proof and optional gateway rate admission.',
  'account.sign_up':'Native signup with optional configured anonymous admission and proof.',
  'account.device.manage':'Native device session and verified proof of key possession.',
  'account.device.command':'Recipient device proof or one-use command acknowledgment.',
  'account.notification.manage':'Authenticated recipient and current preferences.',
  'account.notification.unsubscribe':'Hashed unsubscribe capability.',
  'workspace.member.read':'Active workspace owner or admin with fresh native MFA.',
  'workspace.member.invite':'Active workspace manager, recipient/domain policy and available seat.',
  'workspace.read_api':'Scoped, active API key with current tenant entitlement.',
  'workspace.organization.manage':'Current workspace owner with fresh native assurance for settings, verified domains and invitation templates.',
  'workspace.managed_account':'Current Family or School membership and separately accepted, revocable oversight authority.',
  'admin.user.role.write':'Workspace owner with fresh native MFA; target hierarchy still applies.',
  'admin.user.suspend':'Verified workspace owner or admin; admins can act on members only.',
  'audit.log.read':'Workspace owner or admin with current scope.',
  'audit.log.export':'Scoped workspace manager with fresh native MFA and journal integrity.',
  'compliance.export.request':'Workspace admin with fresh native MFA and exact shared-source authorization.',
  'compliance.export.review':'Independent workspace owner with fresh native MFA and live evidence scope.',
  'compliance.export.download':'Requester or reviewer within a live approved case capability and access conditions.',
  'messaging.message.send':'Authorized conversation participants or an eligible room member under current posting policy.',
  'messaging.message.report':'Current message visibility and explicit evidence consent. Private notes stay within Platform review.',
  'messaging.message.delete_any':'Existing room moderation for eligible scoped posts; no global arbitrary message deletion.',
  'room.member.remove':'Room owner or moderator; target hierarchy and live workspace membership still apply.',
  'room.permission.write':'Eligible room owner or moderator with fresh native proof and the permitted target role.',
  'room.reaction.add':'Eligible room member with current room reaction policy.',
  'room.mention.all':'Eligible room member with the effective mention rule.',
  'room.guest.access':'Scoped room capability or an authorized host action.',
  'room.thread.summarize':'Eligible room participant under workspace summary policy.',
  'call.media.join':'Current admitted caller, participant or meeting host scope.',
  'call.network.test':'Native signed-in diagnostic authorization.',
  'call.record.start':'Authorized meeting host, current policy and participant consent.',
  'call.record.read':'Authorized recording read, or host controls with their additional checks.',
  'meeting.caption.manage':'Live verified meeting identity with distinct language/control scope.',
  'meeting.guest.access':'Authorized guest invitation, challenge or host assignment.',
  'meeting.moderate':'Current meeting host or configured moderation authority.',
  'meeting.summary.read':'Authorized meeting visibility with scoped summary policy.',
  'meeting.presenter.manage':'Live authorized meeting and issued presenter lease.',
  'file.download':'Current file authorization or a separately scoped signed grant.',
  'file.share_external':'Eligible sender and share policy to issue; unexpired capability for permitted redemption.',
  'file.upload':'Eligible file contributor, current storage scope and platform scanning.',
  'file.delete':'Authorized owner or permitted moderator subject to holds and scope.',
  'integration.key.manage':'Eligible workspace owner, fresh native MFA and plan entitlement.',
  'integration.webhook.manage':'Eligible workspace owner, fresh native MFA and plan entitlement.',
  'policy.write':'Existing workspace-owner policy path with fresh MFA; delegated security_admin role pending.',
  'policy.rule.evaluate':'Authenticated workspace operator with current scoped rule access.',
  'billing.invoice.read':'Linked subscription owner or active billing administrator with invoice-bound signed tickets.',
  'billing.workspace.read':'Active workspace billing administrator; linked subscription payment status and invoices only.',
  'billing.workspace.delegate':'Workspace owner with fresh billing proof; eligible members only.',
  'billing.checkout':'Own subscription, current identity and fresh native proof.',
  'billing.trial':'Current workspace owner. Starting a trial requires fresh native proof and the tenant’s unused eligibility.',
  'billing.invoice.refund':'Pending. No refund mutation is authorized by this catalog.',
  'soc.queue.read':'Verified authorized platform moderation staff.',
  'soc.action.quarantine':'Pending. Automatic scanner quarantine has its own policy.',
  'soc.siem.export':'Enterprise workspace owner with fresh native MFA.',
  'soc.report.export':'Verified authorized staff with fresh native MFA.',
  'soc.evidence.access':'Scoped evidence ticket and current authorized case action.',
  'safety.url.inspect':'Current eligible account session and rate-limited URL inspection.',
  'platform.account.read':'Explicitly assigned account operator or independent reviewer with fresh native MFA.',
  'platform.session.revoke':'Explicit account operator, fresh native MFA and eligible target.',
  'platform.recovery.review':'Independent assigned account reviewer with fresh native MFA.',
}

export const pendingPermissionRoles={
  'billing.invoice.refund':{
    roles:['owner','billing_admin'],
    surface:'No invoice refund action is available. The refund workflow is pending.',
  },
  'soc.action.quarantine':{
    roles:['soc_lead'],
    surface:'No standalone SOC quarantine action is available. Existing upload scanner quarantine uses a separate service policy.',
  },
}

const entries=[]
const add=(path,methods,mode,permission,guards,details)=>methods.split(',').forEach(method=>
  entries.push({path,method,mode,permissions:permission?permission.split(','):[],guards,details}))
const publicly=(path,methods,details)=>add(path,methods,'Public','',[],details)
const account=(path,methods,permission,...guards)=>add(path,methods,'Account',permission,guards,'')
const capability=(path,methods,permission,...guards)=>add(path,methods,'Scoped capability',permission,guards,'')
const signed=(path,methods,details,...guards)=>add(path,methods,'Signed service','',guards,details)
const credential=(path,permission,...guards)=>add(path,'POST','Credential exchange',permission,guards,'Native Auth and configured admission controls.')

account('account/devices/bundle','POST','account.device.manage','getUser','rpc:st_v7_pending_device_bundle','verify')
capability('account/devices/commands','POST','account.device.command','rpc:st_v7_ack_device_command','verify','rpc:st_v7_claim_device_command')
account('account/devices/reputation-link','POST','account.device.manage','getUser','rpc:st_v7_manage_browser_reputation_link','verify')
publicly('audit/export','GET','Ed25519 public verification key only.')
account('audit/export','POST','audit.log.export','getUser','rpc:st_v7_sensitive_action_status','rpc:st_v6_record_audit_export')
credential('auth/sign-in','account.sign_in','admit','signInWithPassword')
credential('auth/sign-up','account.sign_up','rpc:st_v7_signup_admission','signUp','resend')
account('billing/action','POST','billing.checkout','billingIdentity','rpc:st_v7_sensitive_action_status')
account('billing/invoices','GET','billing.invoice.read','billingIdentity','rpc:st_v7_current_session_valid','rpc:st_v7_billing_admin_view','readInvoiceTicket','rpc:st_v7_pin_stripe_invoice')
account('billing/workspace','GET','billing.workspace.read','billingIdentity','rpc:st_v7_billing_admin_view','rpc:st_v7_billing_admin_provider_scope')
publicly('billing/catalog','GET','Published pricing only.')
signed('billing/webhook','POST','Stripe raw body signature and durable receipt.','constructEvent','rpc:st_v7_stripe_claim','rpc:st_v7_stripe_finish')
signed('billing/reconcile','POST','Private Stripe reconciliation worker bearer.','notificationDrainAuthorized','rpc:st_v7_stripe_reconcile_claim','rpc:st_v7_stripe_reconcile_finish','rpc:st_v7_renewal_probe_claim','rpc:st_v7_renewal_probe_finish')
signed('billing/renewal-mail','POST','Private transactional renewal mail worker bearer.','notificationDrainAuthorized','rpc:st_v7_renewal_mail_claim','rpc:st_v7_renewal_mail_confirm','rpc:st_v7_renewal_mail_finish')
account('compliance-exports/[caseId]','GET,POST','compliance.export.download','operationalReportViewer','rpc:st_v7_begin_compliance_operation')
account('evidence-vault','GET,POST','soc.evidence.access','operationalReportViewer','rpc:st_v7_begin_evidence_operation')
account('exports/[artifact]','GET','audit.log.export,soc.report.export','operationalReportViewer','rpc:st_v7_sensitive_action_status','rpc:st_v6_get_export_object')
signed('exports/purge','POST','Private cleanup bearer.','timingSafeEqual','rpc:st_v6_claim_export_cleanup')
account('files/download','GET,POST','file.download','authenticateFileRequest','rpc:st_v6_file_can_read')
account('files/preview','GET','file.download','authenticateFileRequest','rpc:st_v6_view_file_details')
account('files/publish','POST','file.upload','authenticateFileRequest','rpc:st_v6_pending_file')
signed('files/purge','POST','Private cleanup bearer.','timingSafeEqual')
account('files/resumable','POST,PUT','file.upload','authenticateFileRequest','rpc:st_v6_resumable_attachment')
capability('files/share','POST','file.share_external','rpc:st_v6_access_file_share')
account('files/upload','POST','file.upload','authenticateFileRequest','rpc:st_v6_authorize_file_upload')
publicly('group-calls','GET','Media capability boolean only.')
account('group-calls','POST','call.media.join','getUser','rpc:st_v6_group_call')
account('group-files','GET','file.download','authenticateFileRequest','rpc:st_v7_group_file_access')
account('group-files','POST','file.upload','authenticateFileRequest','rpc:st_v7_group_file_access','rpc:st_v7_lease_group_file_upload')
signed('group-files/purge','POST','Private cleanup bearer for expired encrypted group attachment reservations.','timingSafeEqual','rpc:st_v7_claim_group_file_cleanup','rpc:st_v7_finish_group_file_cleanup')
account('group-history','POST','account.device.manage','getUser','rpc:st_v7_group_history_proof','verify','rpc:st_v7_finish_group_history')
publicly('health','GET','Read-only process health.')
account('ice','GET','call.media.join','getUser','rpc:st_v6_call_ice_session')
account('ice/diagnostics','POST','call.network.test','getUser','rpc:st_v6_network_diagnostic_run')
account('integrations/keys','POST','integration.key.manage','integrationIdentity','rpc:st_v6_create_integration_key','rpc:st_v6_revoke_integration_key')
account('integrations/webhooks','POST','integration.webhook.manage','integrationIdentity','rpc:st_v6_revoke_webhook')
signed('integrations/webhooks/drain','POST','Private webhook worker bearer.','timingSafeEqual','rpc:st_v6_webhook_lease_active')
publicly('meetings/captions','GET','Caption capability boolean only.')
account('meetings/captions','POST,PUT','meeting.caption.manage','getUser','rpc:st_v6_meeting_caption_command')
publicly('meetings/guests','GET','Guest capability and site key only.')
capability('meetings/guests','POST','meeting.guest.access','rpc:st_v6_meeting_guest_command','verifyCaptcha')
account('meetings/moderate','POST','meeting.moderate','getUser','rpc:st_v6_moderate_meeting')
publicly('meetings/protected','GET','Protected media capability boolean only.')
account('meetings/protected','POST','call.media.join','getUser','rpc:st_v6_create_protected_meeting')
account('meetings/recordings','GET','call.record.read','getUser','command')
account('meetings/recordings','POST','call.record.start','getUser','command')
signed('meetings/recordings/webhook','POST','LiveKit receiver signature and event scope.','receive','command')
account('meetings/screen-share','POST','meeting.presenter.manage','getUser','rpc:st_v6_screen_presenter')
publicly('meetings/summaries','GET','Summary capability boolean only.')
account('meetings/summaries','POST','meeting.summary.read','getUser','rpc:st_v6_meeting_summary_command')
publicly('meetings/token','GET','Media capability boolean only.')
account('meetings/token','POST','call.media.join','getUser','rpc:st_v3_media_access')
publicly('notification-email/drain','GET','Email capability boolean only.')
signed('notification-email/drain','POST','Private notification worker bearer.','notificationDrainAuthorized','rpc:st_v6_claim_notification_email')
publicly('notification-email/unsubscribe','GET','Read-only unsubscribe confirmation page.')
capability('notification-email/unsubscribe','POST','account.notification.unsubscribe','rpc:st_v6_unsubscribe_notification_email')
publicly('operational-reports/drain','GET','Report delivery capability boolean only.')
signed('operational-reports/drain','POST','Private report worker bearer.','notificationDrainAuthorized','rpc:st_v6_claim_operational_reports')
account('operational-reports/export','GET','soc.report.export','operationalReportViewer','rpc:st_v6_operational_report_export')
publicly('preferences/language','POST','Browser-local language cookie. The app request origin policy applies.')
signed('push/dispatch','POST','Private Web Push worker bearer.','dispatchAuthorized','rpc:st_v6_claim_web_push')
account('push/subscription','GET,POST,DELETE','account.notification.manage','authenticatePush','rpc:st_v6_push_subscription')
publicly('ready','GET','Read-only readiness.')
account('room-files','GET','file.download','authenticateFileRequest','rpc:st_v6_room_file_command')
account('room-files','POST','file.upload','authenticateFileRequest','rpc:st_v6_room_file_command')
account('room-files','DELETE','file.delete','authenticateFileRequest','rpc:st_v6_room_file_command')
publicly('rooms/guests','GET','Room guest capability boolean only.')
capability('rooms/guests','POST','room.guest.access','getUser','rpc:st_v6_room_guest_command')
account('rooms/thread-summary','POST','room.thread.summarize','getUser','rpc:st_v6_room_thread_summary_command')
account('safety/url-inspection','POST','safety.url.inspect','rpc:st_v7_authorize_url_inspection')
account('security-reports/export','GET','soc.report.export','operationalReportViewer','rpc:st_v7_sensitive_action_status','rpc:st_v6_security_report')
account('siem','GET','soc.siem.export','operationalReportViewer','rpc:st_v7_siem_batch_read')
account('siem','POST','soc.siem.export','operationalReportViewer','rpc:st_v7_siem_batch_read','rpc:st_v7_siem_batch')
signed('siem/drain','POST','Private SIEM worker bearer.','notificationDrainAuthorized','rpc:st_v7_siem_claim','rpc:st_v7_siem_finish')
publicly('status','GET','Read-only status.')
capability('v1/[resource]','GET','workspace.read_api','apiKeyHash','rpc:st_v6_integration_read')
account('voice-notes','GET','file.download','getUser','rpc:st_v6_voice_note_command')
account('voice-notes','POST','file.upload','getUser','rpc:st_v6_voice_note_command')
signed('workspace-files/maintenance','POST','Private cleanup bearer.','timingSafeEqual')
account('workspace-files','GET','file.download','authenticateFileRequest','rpc:st_v6_workspace_file_command')
account('workspace-files','POST','file.upload,file.share_external','authenticateFileRequest','rpc:st_v6_workspace_file_command','rpc:st_v6_record_workspace_file_access')
account('workspace-files','DELETE','file.delete','authenticateFileRequest','rpc:st_v6_workspace_file_command')
account('workspaces/invitations','POST','workspace.member.invite','getUser','rpc:st_v6_workspace_link_create','rpc:st_v7_workspace_email_template')
account('workspaces/organization','POST','workspace.organization.manage','rpc:st_v7_org_settings','rpc:st_v7_finish_org_domain')
account('workspaces/rule-registry','POST','policy.rule.evaluate','getUser','rpc:st_v7_workspace_rule_registry')
account('workspaces/trial','GET','billing.trial','billingIdentity','rpc:st_v7_workspace_trial_status')
account('workspaces/trial','POST','billing.trial','billingIdentity','rpc:st_v7_sensitive_action_status','rpc:st_v7_start_workspace_trial')

export const entrypoints=entries.sort((a,b)=>a.path.localeCompare(b.path)||a.method.localeCompare(b.method))

export const databaseEntryPoints={
  'messaging.message.report':'st_v7_submit_channel_report',
  'workspace.organization.manage':'st_v7_org_settings',
  'workspace.managed_account':'st_v7_managed_account',
  'billing.workspace.delegate':'st_v7_billing_admin_manage',
  'workspace.member.read':'st_v7_workspace_people',
  'admin.user.role.write':'st_v2_set_member',
  'admin.user.suspend':'st_v2_set_member',
  'audit.log.read':'st_v6_audit_search',
  'compliance.export.request':'st_v7_request_compliance_export',
  'compliance.export.review':'st_v7_review_compliance_export',
  'messaging.message.send':'st_v6_room_post',
  'messaging.message.delete_any':'st_v6_room_settings',
  'room.member.remove':'st_v6_room_membership',
  'room.permission.write':'st_v6_set_room_role_overrides',
  'room.reaction.add':'st_v6_react_room_post',
  'room.mention.all':'st_v6_room_post',
  'policy.write':'st_v6_change_workspace_policy',
  'soc.queue.read':'st_staff_status',
  'platform.account.read':'st_v7_account_admin_directory',
  'platform.session.revoke':'st_v7_account_admin_revoke_session',
  'platform.recovery.review':'st_v7_account_admin_action',
}

export function renderPermissionMatrix() {
  const roleRows=Object.entries(roles).map(([id,detail])=>'| `'+id+'` | '+detail+' |')
  const permissionRows=Object.entries(permissions).sort(([a],[b])=>a.localeCompare(b)).map(([id,detail])=>
    '| `'+id+'` | '+detail+' | '+(databaseEntryPoints[id]?'`'+databaseEntryPoints[id]+'`':'—')+' |')
  const routes=entrypoints.map(({path,method,mode,permissions,guards,details})=>
    '| `'+method+' /api/'+path+'` | '+mode+' | '+(permissions.map(p=>'`'+p+'`').join(', ')||'—')+
    ' | '+[details,...guards.map(guard=>'`'+guard+'`')].filter(Boolean).join(' ')+' |')
  const native=rpcInventory().map(({rpc,roles,security,gate,evidence})=>
    '| `'+rpc+'` | '+roles.map(role=>'`'+role+'`').join(', ')+' | '+security+' | '+gate+' | '+
    evidence.map(item=>'`'+item+'`').join(', ')+' |')
  const pending=Object.entries(pendingPermissionRoles).map(([permission,details])=>
    '| `'+permission+'` | '+details.roles.map(role=>'`'+role+'`').join(', ')+' | '+details.surface+' |')
  return ['# Permission matrix','','Generated by `node scripts/permission-matrix.mjs --write`.','','## Roles and current support','',
    '| Role | Scope or dependency |','| --- | --- |',...roleRows,'','## Permissions','',
    '| Permission | Runtime conditions and coverage | Direct database entry point |','| --- | --- | --- |',...permissionRows,
    '','## Unavailable permission surfaces','','These rows describe intended roles. They confer no authority.','',
    '| Permission | Intended roles | Current availability |','| --- | --- | --- |',...pending,
    '','## App route authorization','','Account and capability routes apply the listed guards. Public and signed worker routes have explicit purposes.',
    'Database RPC and RLS policies continue to enforce record scope. Pending roles and operations confer no access.','',
    '| Method and route | Access type | Permission | Verified guard or public purpose |','| --- | --- | --- | --- |',
    ...routes,'','## Native PostgREST and Auth entry points','',
    'The native inventory records effective execute grants for the public and GraphQL schemas. The separate native signup hook is included for clarity.',
    'Database scope evidence identifies the principal or authorization helpers used by the SQL implementation. Service-only RPCs rely on the private server credential.',
    'The live test compares grants, function fingerprints, and the bound PostgREST account guard with the checked-in inventory. It also exercises selected role, RLS, public, and service paths.',
    'To refresh after an intentional schema change, apply the complete migration set to local QA and run `node scripts/rpc-permission-inventory.mjs --write` followed by `node scripts/permission-matrix.mjs --write`.','',
    '| Signature | Execute roles | SQL security | Authorization | Evidence |','| --- | --- | --- | --- | --- |',
    ...native,''].join('\n')
}

if(process.argv[1]&&pathToFileURL(process.argv[1]).href===import.meta.url&&process.argv.includes('--write')) {
  mkdirSync(new URL('../docs/spec/',import.meta.url),{recursive:true})
  writeFileSync(new URL('../docs/spec/permission-matrix.md',import.meta.url),renderPermissionMatrix())
}
