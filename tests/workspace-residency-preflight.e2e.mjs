import assert from 'node:assert/strict'
import {spawnSync} from 'node:child_process'
import {readFileSync} from 'node:fs'

const container = 'supabase_db_v4-auth-qa'
const script = readFileSync(new URL('../scripts/workspace-residency-preflight.sql', import.meta.url), 'utf8')
const id = suffix => 'b8090000-0000-4000-8000-' + String(suffix).padStart(12, '0')
const owner = id(1)
const member = id(2)
const outsider = id(3)
const workspace = id(21)
const other = id(22)
const group = id(31)

function psql(input, workspaceId) {
  const output = spawnSync('docker', ['exec', '-i', container, 'psql', '-XqAt', '--no-password',
    '--set=ON_ERROR_STOP=1', '--set=workspace_id=' + workspaceId, '-U', 'postgres', '-d', 'postgres'], {
    input, encoding: 'utf8', windowsHide: true,
  })
  if (output.error) throw output.error
  return output
}

const absent = psql(script, id(99))
assert.equal(absent.status, 0, absent.stderr)
assert.deepEqual(JSON.parse(absent.stdout), {status: 'workspace_not_found', eligibleForAutomatedCutover: false})

const fixture = `
insert into auth.users(id,email,email_confirmed_at) values
  ('${owner}','residency-preflight-owner@example.invalid',now()),
  ('${member}','residency-preflight-member@example.invalid',now()),
  ('${outsider}','residency-preflight-outsider@example.invalid',now());
insert into public.st_profiles(id,handle,name) values
  ('${owner}','res_preflight_owner','Preflight private owner'),
  ('${member}','res_preflight_member','Preflight private member'),
  ('${outsider}','res_preflight_other','Preflight private outsider');
insert into public.st_v2_workspaces(id,name,owner) values
  ('${workspace}','Preflight private workspace','${owner}'),
  ('${other}','Preflight private neighbor','${outsider}');
insert into public.st_v2_members(workspace_id,user_id,role) values
  ('${workspace}','${owner}','owner'),('${workspace}','${member}','member'),
  ('${other}','${outsider}','owner'),('${other}','${member}','member');
insert into public.st_chats(id,member_a,member_b,requester,status) values
  ('${id(32)}','${owner}','${member}','${owner}','accepted'),
  ('${id(33)}','${member}','${outsider}','${member}','accepted');
insert into sectalk_private.st_group_chats(id,owner,name,epoch,member_cap)
  values ('${group}','${member}','Preflight private group',1,4);
insert into sectalk_private.st_group_members(group_id,actor) values ('${group}','${owner}'),('${group}','${member}');
insert into sectalk_private.st_v6_workspace_files(workspace,id,uploader,filename,size_bytes,published_at,deleted_at) values
  ('${workspace}','${id(40)}','${owner}','preflight-private-aligned.pdf',17,now(),null),
  ('${workspace}','${id(41)}','${owner}','preflight-private-missing.pdf',19,now(),null),
  ('${workspace}','${id(42)}','${owner}','preflight-private-drift.pdf',23,now(),null),
  ('${workspace}','${id(43)}','${owner}','preflight-private-pending.pdf',29,null,null),
  ('${workspace}','${id(44)}','${owner}','preflight-private-retained.pdf',31,now(),now()),
  ('${other}','${id(40)}','${outsider}','preflight-private-neighbor.pdf',61,now(),null);
insert into storage.objects(bucket_id,name,metadata) values
  ('sectalk-workspace-files','${workspace}/${id(40)}','{"size":17}'),
  ('sectalk-workspace-files','${workspace}/${id(42)}','{"size":24}'),
  ('sectalk-workspace-files','${workspace}/${id(44)}','{"size":31}'),
  ('sectalk-workspace-files','${workspace}/${id(45)}','{"size":99}'),
  ('sectalk-workspace-files','${other}/${id(40)}','{"size":13}');
`

// Seed metadata and run the production query in one rollback transaction. The
// production file above ran separately with its actual read-only transaction.
const rollbackScript = script.replace('begin isolation level repeatable read read only;', 'begin;\n' + fixture)
  .replace('commit;', 'rollback;')
const result = psql(rollbackScript, workspace)
assert.equal(result.status, 0, result.stderr)
const report = JSON.parse(result.stdout)
assert.equal(report.status, 'scope_review_required')
assert.equal(report.eligibleForAutomatedCutover, false)
assert.equal(report.sharedProjectRouting, true)
assert.ok(report.otherWorkspacesInProject >= 1)
assert.equal(report.memberIdentities, 2)
assert.equal(report.otherWorkspacesSharingIdentities, 1)
assert.equal(report.globalDirectChatsInvolvingIdentities, 2)
assert.equal(report.globalPrivateGroupsInvolvingIdentities, 1)
assert.ok(report.foreignKeyReachableRelations.includes('public.st_v2_posts'))
assert.ok(report.unconstrainedScopeCandidates.includes('sectalk_private.st_v6_workspace_files'))
assert.ok(report.outsideForeignKeys.some(edge => edge.child === 'public.st_v2_members' && edge.parent === 'public.st_profiles'))
assert.deepEqual(report.workspaceFileMetadata,
  {privateBucket: true, published: 3, pending: 1, retained: 1, missing: 1, mismatchedSize: 1, unmatched: 1})
assert.doesNotMatch(result.stdout, /preflight-private|Preflight private|example\.invalid|b8090000/)

const rolledBack = psql(script, workspace)
assert.equal(rolledBack.status, 0, rolledBack.stderr)
assert.equal(JSON.parse(rolledBack.stdout).status, 'workspace_not_found')
console.log('Residency preflight found native workspace boundaries, shared identities, and scoped Storage metadata drift.')
