begin;

do $$
declare
  actor uuid:=gen_random_uuid(); workspace_id uuid:=gen_random_uuid(); other_workspace uuid:=gen_random_uuid();
  approval_id uuid:=gen_random_uuid(); handoff_id uuid:=gen_random_uuid(); hold_id uuid:=gen_random_uuid();
  secret_id uuid:=vault.create_secret(encode(extensions.gen_random_bytes(32),'hex'));
  other_secret uuid:=vault.create_secret(encode(extensions.gen_random_bytes(32),'hex'));
  retired timestamptz;
  expiry timestamptz:=clock_timestamp()-interval '1 day';
begin
  insert into auth.users(id,email) values(actor,actor||'@example.invalid');
  insert into public.st_profiles(id,handle,name) values(actor,'linkqa_'||left(actor::text,8),'Link retirement fixture');
  insert into public.st_v2_workspaces(id,name,owner) values(workspace_id,'Disposable link workspace',actor);
  insert into sectalk_private.st_v8_residency_history_links
    (workspace,approval,source_project,destination_project,side,vault_id,expires_at)
    values(workspace_id,approval_id,'fixture-origin','fixture-destination','source',secret_id,clock_timestamp()+interval '1 hour'),
      (other_workspace,approval_id,'fixture-origin','fixture-destination','destination',other_secret,expiry);
  begin
    perform sectalk_private.st_v8_retire_residency_history_link(workspace_id,approval_id,'source',secret_id,'fixture-ticket');
    raise exception 'Attempt retired a live link';
  exception when sqlstate 'PT409' then null; end;
  update sectalk_private.st_v8_residency_history_links h set expires_at=expiry where h.vault_id=secret_id;
  begin
    perform sectalk_private.st_v8_retire_residency_history_link(workspace_id,approval_id,'source',other_secret,'fixture-ticket');
    raise exception 'Attempt accepted the wrong Vault record';
  exception when sqlstate 'PT409' then null; end;

  insert into sectalk_private.st_v6_workspace_holds(id,workspace_id,member_id,reason,placed_by)
    values(hold_id,workspace_id,actor,'Hold disposable transfer evidence.',actor);
  begin
    perform sectalk_private.st_v8_retire_residency_history_link(workspace_id,approval_id,'source',secret_id,'fixture-ticket');
    raise exception 'Attempt retired a link under preservation hold';
  exception when sqlstate 'PT409' then null; end;
  update sectalk_private.st_v6_workspace_holds h set released_at=now(),released_by=actor,
    release_reason='Release disposable transfer evidence.' where h.id=hold_id;
  insert into sectalk_private.st_v8_content_exports(id,workspace,requester,approved_at,expires_at)
    values(approval_id,workspace_id,actor,now(),now()+interval '1 hour');
  begin
    perform sectalk_private.st_v8_retire_residency_history_link(workspace_id,approval_id,'source',secret_id,'fixture-ticket');
    raise exception 'Attempt retired a link with current export approval';
  exception when sqlstate 'PT409' then null; end;
  update sectalk_private.st_v8_content_exports c set withdrawn_at=now() where c.id=approval_id;

  insert into sectalk_private.st_v8_residency_write_handoffs
    (workspace,approval,handoff,source_project,destination_project,phase)
    values(workspace_id,approval_id,handoff_id,'fixture-origin','fixture-destination','held');
  begin
    perform sectalk_private.st_v8_retire_residency_history_link(workspace_id,approval_id,'source',secret_id,'fixture-ticket');
    raise exception 'Attempt discarded the key for a held handoff';
  exception when sqlstate 'PT409' then null; end;
  update sectalk_private.st_v8_residency_write_handoffs h set phase='restored' where h.handoff=handoff_id;
  insert into sectalk_private.st_v8_residency_rollback_manifest_admissions(handoff,vault_id,plan_sha256,expires_at)
    values(handoff_id,secret_id,repeat('0',64),expiry);
  begin
    perform sectalk_private.st_v8_retire_residency_history_link(workspace_id,approval_id,'source',secret_id,'fixture-ticket');
    raise exception 'Attempt removed a key referenced by rollback evidence';
  exception when sqlstate 'PT409' then null; end;
  delete from sectalk_private.st_v8_residency_rollback_manifest_admissions a where a.handoff=handoff_id;

  retired:=sectalk_private.st_v8_retire_residency_history_link(workspace_id,approval_id,'source',secret_id,'fixture-ticket');
  if retired is null or retired is distinct from
    sectalk_private.st_v8_retire_residency_history_link(workspace_id,approval_id,'source',secret_id,'fixture-ticket')
    or exists(select 1 from vault.secrets v where v.id=secret_id)
    or exists(select 1 from sectalk_private.st_v8_residency_history_links h where h.vault_id=secret_id)
    or not exists(select 1 from vault.secrets v where v.id=other_secret)
    or not exists(select 1 from sectalk_private.st_v8_residency_history_links h where h.vault_id=other_secret)
    or not exists(select 1 from sectalk_private.st_v8_residency_history_link_retirements r
      where (r.workspace,r.approval,r.side,r.link_expires_at,r.retired_at,r.vault_row_removed)=
        (workspace_id,approval_id,'source',expiry,retired,true) and to_jsonb(r)::text not like '%'||secret_id::text||'%') then
    raise exception 'Retirement did not preserve exact scope and redacted custody';
  end if;
  begin
    insert into sectalk_private.st_v8_residency_history_links
      (workspace,approval,source_project,destination_project,side,vault_id,expires_at)
      values(workspace_id,approval_id,'fixture-origin','fixture-destination','source',gen_random_uuid(),clock_timestamp()+interval '1 hour');
    raise exception 'A retired link was recreated';
  exception when sqlstate 'PT409' then null; end;
  delete from vault.secrets v where v.id=other_secret;
  perform sectalk_private.st_v8_retire_residency_history_link(other_workspace,approval_id,'destination',other_secret,'fixture-ticket');
  if not exists(select 1 from sectalk_private.st_v8_residency_history_link_retirements r
    where (r.workspace,r.approval,r.side)=(other_workspace,approval_id,'destination') and not r.vault_row_removed) then
    raise exception 'Already missing Vault row was reported as removed';
  end if;
  if exists(select 1 from unnest(array['anon','authenticated','service_role']) r
    where has_function_privilege(r,'sectalk_private.st_v8_retire_residency_history_link(uuid,uuid,text,uuid,text)','EXECUTE')
      or has_table_privilege(r,'sectalk_private.st_v8_residency_history_link_retirements','SELECT,INSERT,UPDATE,DELETE')) then
    raise exception 'An API role can inspect or invoke trusted link retirement';
  end if;
end $$;

select 'passed: expiry, exact identity, hold and approval protection, redacted custody, idempotent local Vault retirement';
rollback;
