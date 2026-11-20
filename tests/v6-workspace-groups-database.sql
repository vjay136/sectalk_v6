begin;

-- Set up a fresh TOTP session for a roster mutation in this SQL fixture.
create function pg_temp.set_verified_member(p_workspace uuid,p_member uuid,p_role text)
returns void language plpgsql security definer set search_path='' as $$
declare actor uuid:=auth.uid(); session_id uuid:=gen_random_uuid(); factor_id uuid;
  prior text:=current_setting('request.jwt.claims',true);
begin
  select f.id into factor_id from auth.mfa_factors f
    where f.user_id=actor and f.status='verified' and f.factor_type='totp' limit 1;
  if factor_id is null then
    factor_id:=gen_random_uuid();
    insert into auth.mfa_factors(id,user_id,factor_type,status,created_at,updated_at)
      values(factor_id,actor,'totp','verified',now(),now());
  end if;
  insert into auth.sessions(id,user_id,aal,factor_id) values(session_id,actor,'aal2',factor_id);
  insert into auth.mfa_amr_claims(id,session_id,authentication_method,created_at,updated_at)
    values(gen_random_uuid(),session_id,'totp',now(),now());
  perform set_config('request.jwt.claims',jsonb_build_object('sub',actor,'role','authenticated','session_id',session_id,'aal','aal2')::text,true);
  perform public.st_v2_set_member(p_workspace,p_member,p_role);
  perform set_config('request.jwt.claims',coalesce(prior,''),true);
end $$;


insert into auth.users(id,email,aud,role) values
  ('72000000-0000-4000-8000-000000000001','teams-owner@example.invalid','authenticated','authenticated'),
  ('72000000-0000-4000-8000-000000000002','teams-admin@example.invalid','authenticated','authenticated'),
  ('72000000-0000-4000-8000-000000000003','teams-member@example.invalid','authenticated','authenticated'),
  ('72000000-0000-4000-8000-000000000004','teams-other@example.invalid','authenticated','authenticated');
insert into public.st_profiles(id,handle,name) values
  ('72000000-0000-4000-8000-000000000001','teams_fixture_owner','Directory owner'),
  ('72000000-0000-4000-8000-000000000002','teams_fixture_admin','Directory admin'),
  ('72000000-0000-4000-8000-000000000003','teams_fixture_member','Directory member'),
  ('72000000-0000-4000-8000-000000000004','teams_fixture_other','Other workspace owner');

set local role authenticated;
do $$
declare
  own_id constant uuid:='72000000-0000-4000-8000-000000000001';
  admin_id constant uuid:='72000000-0000-4000-8000-000000000002';
  member_id constant uuid:='72000000-0000-4000-8000-000000000003';
  other_id constant uuid:='72000000-0000-4000-8000-000000000004';
  groups_id constant uuid:='72000000-0000-4000-8000-000000000011';
  team_id constant uuid:='72000000-0000-4000-8000-000000000012';
  dept_id constant uuid:='72000000-0000-4000-8000-000000000013';
  space uuid;
  other_space uuid;
  invite uuid;
begin
  perform set_config('request.jwt.claims',json_build_object('sub',own_id,'role','authenticated')::text,true);
  space:=public.st_v2_create_workspace('Group fixture workspace');
  perform public.st_v2_invite(space,'teams_fixture_admin');
  perform public.st_v2_invite(space,'teams_fixture_member');
  perform public.st_v6_workspace_group_create(space,groups_id,'group','Security','');
  perform public.st_v6_workspace_group_create(space,groups_id,'group','Security','');
  perform public.st_v6_workspace_group_create(space,team_id,'team','Security','Engineering collaboration');
  begin
    perform public.st_v6_workspace_group_create(space,gen_random_uuid(),'team','security','');
    raise exception 'Duplicate case-insensitive group name accepted' using errcode='P0004';
  exception when raise_exception then null; end;
  begin
    perform public.st_v6_workspace_group_change(space,groups_id,'member_added',p_user=>other_id);
    raise exception 'A nonmember was added to the group' using errcode='P0004';
  exception when raise_exception then null; end;

  perform set_config('request.jwt.claims',json_build_object('sub',other_id,'role','authenticated')::text,true);
  other_space:=public.st_v2_create_workspace('Other group fixture workspace');
  perform public.st_v6_workspace_group_create(other_space,groups_id,'group','Security','');
  if exists(select 1 from public.st_v6_workspace_groups where workspace_id=space) then raise exception 'Directory crossed tenants'; end if;
  begin
    perform public.st_v6_workspace_group_change(space,groups_id,'archive');
    raise exception 'Another workspace owner changed this group' using errcode='P0004';
  exception when raise_exception then null; end;

  perform set_config('request.jwt.claims',json_build_object('sub',member_id,'role','authenticated')::text,true);
  if exists(select 1 from public.st_v6_workspace_groups) then raise exception 'A pending invitation exposed the directory'; end if;
  select id into invite from public.st_v2_invites where workspace_id=space;
  perform public.st_v2_reply_invite(invite,true);
  if (select count(*) from public.st_v6_workspace_groups)<>2 then raise exception 'Workspace member did not inherit directory access'; end if;
  begin
    perform public.st_v6_workspace_group_create(space,gen_random_uuid(),'group','Disallowed','');
    raise exception 'A member created a group' using errcode='P0004';
  exception when raise_exception then null; end;
  begin
    perform public.st_v6_workspace_group_change(space,groups_id,'member_added',p_user=>member_id);
    raise exception 'A member changed group membership' using errcode='P0004';
  exception when raise_exception then null; end;
  begin
    insert into public.st_v6_workspace_group_members(workspace_id,group_id,user_id) values(space,groups_id,member_id);
    raise exception 'Direct table writes bypassed the RPC' using errcode='P0004';
  exception when insufficient_privilege then null; end;

  perform set_config('request.jwt.claims',json_build_object('sub',admin_id,'role','authenticated')::text,true);
  select id into invite from public.st_v2_invites where workspace_id=space;
  perform public.st_v2_reply_invite(invite,true);
  perform set_config('request.jwt.claims',json_build_object('sub',own_id,'role','authenticated')::text,true);
  perform pg_temp.set_verified_member(space,admin_id,'admin');
  perform set_config('request.jwt.claims',json_build_object('sub',admin_id,'role','authenticated')::text,true);
  perform public.st_v6_workspace_group_create(space,dept_id,'department','Engineering','Engineering department');
  perform public.st_v6_workspace_group_change(space,team_id,'rename','Platform','Platform collaboration');
  perform public.st_v6_workspace_group_change(space,team_id,'member_added',p_user=>member_id);
  perform public.st_v6_workspace_group_change(space,team_id,'member_added',p_user=>member_id);
  perform public.st_v6_workspace_group_change(space,dept_id,'member_added',p_user=>member_id);
  perform public.st_v6_workspace_group_change(space,dept_id,'member_removed',p_user=>member_id);
  perform public.st_v6_workspace_group_change(space,team_id,'archive');
  if not exists(select 1 from public.st_v6_workspace_groups where id=team_id and name='Platform' and archived_at is not null)
    then raise exception 'Rename or archive failed'; end if;
  begin
    perform public.st_v6_workspace_group_change(space,team_id,'member_removed',p_user=>member_id);
    raise exception 'An archived entry was modified' using errcode='P0004';
  exception when raise_exception then null; end;
  perform public.st_v6_workspace_group_change(space,team_id,'restore');
  if not exists(select 1 from public.st_v6_workspace_group_members where workspace_id=space and user_id=member_id and group_id=team_id)
    or exists(select 1 from public.st_v6_workspace_group_members where workspace_id=space and user_id=member_id and group_id=dept_id)
    then raise exception 'Member removal or restored roster failed'; end if;
  if (select count(*) from public.st_v2_workspace_audit where workspace_id=space and event='group.created')<>3
    or (select count(*) from public.st_v2_workspace_audit where workspace_id=space and event='group.member_added')<>2
    or (select count(*) from public.st_v2_workspace_audit where workspace_id=space and event='group.member_removed')<>1
    or (select count(*) from public.st_v2_workspace_audit where workspace_id=space
      and event in ('group.rename','group.archive','group.restore'))<>3
    then raise exception 'Directory audit is incomplete or recorded retries twice'; end if;

  perform set_config('request.jwt.claims',json_build_object('sub',own_id,'role','authenticated')::text,true);
  perform pg_temp.set_verified_member(space,member_id,'remove');
  if exists(select 1 from public.st_v6_workspace_group_members where user_id=member_id)
    then raise exception 'Removing workspace access kept a directory membership'; end if;
  perform set_config('request.jwt.claims',json_build_object('sub',member_id,'role','authenticated')::text,true);
  if exists(select 1 from public.st_v6_workspace_groups) then raise exception 'Revoked member retained directory access'; end if;
end $$;
reset role;

select 'passed: workspace groups, teams, departments, audited lifecycle and membership, RLS, and cascade' as result;
rollback;
