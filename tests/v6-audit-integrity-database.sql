begin;

insert into auth.users(id,email,aud,role) values
  ('66060000-0000-4000-8000-000000000001','audit-integrity@example.invalid','authenticated','authenticated');
insert into public.st_profiles(id,handle,name) values
  ('66060000-0000-4000-8000-000000000001','audit_integrity_fixture','Audit integrity fixture');
insert into public.st_v2_workspaces(id,name,owner) values
  ('66060000-0001-4000-8000-000000000001','Audit integrity fixture','66060000-0000-4000-8000-000000000001');
insert into public.st_v2_channels(id,workspace_id,name,owner) values
  ('66060000-0002-4000-8000-000000000001','66060000-0001-4000-8000-000000000001','audit-channel',
   '66060000-0000-4000-8000-000000000001');

set local timezone = 'Asia/Kolkata';
set local datestyle = 'SQL, DMY';

do $$
declare
  before_fixture record;
  anchored record;
  fixture_audit_id bigint;
  channel_audit_id bigint;
  fixture_workspace constant uuid := '66060000-0001-4000-8000-000000000001';
  fixture_actor constant uuid := '66060000-0000-4000-8000-000000000001';
  fixture_channel constant uuid := '66060000-0002-4000-8000-000000000001';
begin
  insert into sectalk_private.st_v6_channel_audit(channel_id, actor, action, detail)
    values (fixture_channel, fixture_actor, 'visibility', 'private') returning id into channel_audit_id;
  select * into strict before_fixture from sectalk_private.st_v6_audit_verify();
  if not exists (select 1 from sectalk_private.st_v6_audit_chain c
    where c.entry_no = before_fixture.entry_no and c.source_id = channel_audit_id
      and c.source = 'sectalk_private.st_v6_channel_audit' and c.operation = 'INSERT') then
    raise exception 'Channel audit insert was not recorded';
  end if;
  insert into public.st_v2_workspace_audit(workspace_id, actor, event) values
    (fixture_workspace, fixture_actor, 'workspace.created') returning id into fixture_audit_id;
  update public.st_v2_workspace_audit set target = fixture_actor where id = fixture_audit_id;
  select * into strict anchored from sectalk_private.st_v6_audit_verify();
  if anchored.entry_no <> before_fixture.entry_no + 2 then
    raise exception 'Insert and update did not advance the journal transactionally';
  end if;

  perform sectalk_private.st_v6_audit_anchor();
  perform sectalk_private.st_v6_audit_anchor();
  if (select count(*) from sectalk_private.st_v6_audit_anchors a
      where a.entry_no = anchored.entry_no and a.entry_hash = anchored.entry_hash) <> 1 then
    raise exception 'Checkpoint failed or was not idempotent';
  end if;
  if not exists (select 1 from cron.job where jobname = 'sectalk-v6-audit-verify-and-anchor'
    and active and command = 'select sectalk_private.st_v6_audit_anchor()') then
    raise exception 'Verifier cron job is missing';
  end if;

  begin
    alter table public.st_v2_workspace_audit disable trigger st_v6_audit_capture;
    update public.st_v2_workspace_audit set event = 'tampered' where id = fixture_audit_id;
    perform sectalk_private.st_v6_audit_anchor();
    raise exception 'Verifier accepted a changed source row';
  exception when raise_exception then
    if sqlerrm <> 'SecTalk audit source rows do not match the journal' then raise; end if;
  end;

  begin
    alter table sectalk_private.st_v6_channel_audit disable trigger st_v6_audit_capture;
    update sectalk_private.st_v6_channel_audit set detail = 'tampered' where id = channel_audit_id;
    perform sectalk_private.st_v6_audit_verify();
    raise exception 'Verifier accepted a changed channel audit row';
  exception when raise_exception then
    if sqlerrm <> 'SecTalk audit source rows do not match the journal' then raise; end if;
  end;

  begin
    alter table public.st_v2_workspace_audit disable trigger st_v6_audit_capture;
    delete from public.st_v2_workspace_audit where id = fixture_audit_id;
    perform sectalk_private.st_v6_audit_verify();
    raise exception 'Verifier accepted an unrecorded deletion';
  exception when raise_exception then
    if sqlerrm <> 'SecTalk audit source rows do not match the journal' then raise; end if;
  end;

  begin
    update sectalk_private.st_v6_audit_chain c set operation = 'INSERT'
      where c.entry_no = anchored.entry_no;
    perform sectalk_private.st_v6_audit_verify();
    raise exception 'Verifier accepted a changed chain entry';
  exception when raise_exception then
    if sqlerrm not like 'SecTalk audit chain mismatch at entry %' then raise; end if;
  end;

  -- Simulate removal of a complete suffix, including the local anchor and
  -- source row. The checkpoint kept outside the database detects the rewind.
  begin
    alter table public.st_v2_workspace_audit disable trigger st_v6_audit_capture;
    delete from public.st_v2_workspace_audit where id = fixture_audit_id;
    delete from sectalk_private.st_v6_audit_anchors a where a.entry_no > before_fixture.entry_no;
    delete from sectalk_private.st_v6_audit_chain c where c.entry_no > before_fixture.entry_no;
    update sectalk_private.st_v6_audit_chain_head h
      set entry_no = before_fixture.entry_no, entry_hash = before_fixture.entry_hash;
    perform sectalk_private.st_v6_audit_verify();
    perform sectalk_private.st_v6_audit_verify(anchored.entry_no, anchored.entry_hash);
    raise exception 'Verifier accepted a rewind past the independent checkpoint';
  exception when raise_exception then
    if sqlerrm not like 'SecTalk audit anchor mismatch at entry %' then raise; end if;
  end;

  delete from public.st_v2_channels where id = fixture_channel;
  if not exists (
    select 1 from sectalk_private.st_v6_audit_verify(anchored.entry_no, anchored.entry_hash) v
      join sectalk_private.st_v6_audit_chain c using (entry_no, entry_hash)
      where c.entry_no = anchored.entry_no + 1 and c.source_id = channel_audit_id
        and c.source = 'sectalk_private.st_v6_channel_audit' and c.operation = 'DELETE'
  ) then
    raise exception 'Existing channel cascade did not leave a verifiable deletion commitment';
  end if;

  if to_regclass('sectalk_private.st_v8_workspace_audit_actors') is not null then
    delete from public.st_v2_workspaces where id = fixture_workspace;
    if not exists(
      select 1 from sectalk_private.st_v6_audit_verify(anchored.entry_no,anchored.entry_hash) v
      where v.entry_no=anchored.entry_no+1 and exists(
        select 1 from public.st_v2_workspace_audit a where a.id=fixture_audit_id and a.workspace_id=fixture_workspace)
    ) then raise exception 'Ordinary workspace removal rewrote retained audit'; end if;
  elsif to_regclass('sectalk_private.st_v8_workspace_audit_custody') is null then
    delete from public.st_v2_workspaces where id = fixture_workspace;
  else
    begin
      delete from public.st_v2_workspaces where id = fixture_workspace;
      raise exception 'Workspace audit cascade bypassed reviewed custody';
    exception when foreign_key_violation then null; end;
    delete from public.st_v2_workspace_audit where id = fixture_audit_id;
  end if;
  if to_regclass('sectalk_private.st_v8_workspace_audit_actors') is null and not exists (
    select 1 from sectalk_private.st_v6_audit_verify(anchored.entry_no, anchored.entry_hash) v
      join sectalk_private.st_v6_audit_chain c using (entry_no, entry_hash)
      where c.entry_no = anchored.entry_no + 2 and c.source_id = fixture_audit_id
        and c.source = 'public.st_v2_workspace_audit' and c.operation = 'DELETE'
  ) then
    raise exception 'Workspace audit deletion did not leave a verifiable journal commitment';
  end if;

  if exists (
    select 1 from unnest(array['anon', 'authenticated', 'service_role']) as role_name
    where has_table_privilege(role_name, 'sectalk_private.st_v6_audit_chain', 'SELECT,INSERT,UPDATE,DELETE')
      or has_table_privilege(role_name, 'sectalk_private.st_v6_audit_anchors', 'SELECT,INSERT,UPDATE,DELETE')
      or has_function_privilege(role_name, 'sectalk_private.st_v6_audit_verify(bigint,bytea)', 'EXECUTE')
      or has_function_privilege(role_name, 'sectalk_private.st_v6_audit_anchor()', 'EXECUTE')
  ) then
    raise exception 'Audit internals are accessible to an API role';
  end if;
end
$$;

select 'passed: audit chain, source verification, hourly checkpoints, independent receipts, cascade and access controls' as result;
rollback;
