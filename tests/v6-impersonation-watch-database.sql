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

insert into auth.users(id,email)
  select ('99300000-0000-4000-8000-'||lpad(n::text,12,'0'))::uuid,'impersonation-'||n||'@example.invalid'
  from generate_series(1,3) n;
insert into public.st_profiles(id,name,handle)
  select ('99300000-0000-4000-8000-'||lpad(n::text,12,'0'))::uuid,'Impersonation '||n,'impersonation_'||n
  from generate_series(1,3) n;

do $$
declare
  owner_id constant uuid:='99300000-0000-4000-8000-000000000001';
  member_id constant uuid:='99300000-0000-4000-8000-000000000002';
  outsider_id constant uuid:='99300000-0000-4000-8000-000000000003';
  workspace uuid;
begin
  set local role authenticated;
  perform set_config('request.jwt.claims',json_build_object('sub',owner_id,'role','authenticated')::text,true);
  workspace:=public.st_v2_create_workspace('Impersonation test workspace');
  perform public.st_v2_invite(workspace,'impersonation_2');
  perform set_config('request.jwt.claims',json_build_object('sub',member_id,'role','authenticated')::text,true);
  perform public.st_v2_reply_invite((select id from public.st_v2_invites where workspace_id=workspace),true);
  begin
    perform * from public.st_v6_impersonation_watch_list(workspace);
    raise exception 'Ordinary workspace member read the watch list';
  exception when insufficient_privilege then null; end;
  begin
    perform public.st_v6_set_impersonation_watch(workspace,member_id,'executive');
    raise exception 'Ordinary workspace member changed the watch list';
  exception when insufficient_privilege then null; end;

  perform set_config('request.jwt.claims',json_build_object('sub',owner_id,'role','authenticated')::text,true);
  begin
    perform public.st_v6_set_impersonation_watch(workspace,outsider_id,'executive');
    raise exception 'Cross-workspace account was added' using errcode='P0100';
  exception when raise_exception then null; end;
  perform public.st_v6_set_impersonation_watch(workspace,member_id,'executive');
  perform public.st_v6_set_impersonation_watch(workspace,member_id,'executive');
  perform public.st_v6_set_impersonation_watch(workspace,member_id,'vip');
  if (select count(*) from public.st_v6_impersonation_watch_list(workspace))<>1
    or not exists(select 1 from public.st_v6_impersonation_watch_list(workspace) a where a.tier='vip')
    or (select count(*) from public.st_v2_workspace_audit a where a.workspace_id=workspace
      and a.event='impersonation.watch_saved')<>2 then
    raise exception 'Classification, replay, or workspace audit failed';
  end if;
  perform pg_temp.set_verified_member(workspace,member_id,'suspend');
  begin
    perform public.st_v6_set_impersonation_watch(workspace,member_id,'executive');
    raise exception 'Suspended account was made active on the watch list' using errcode='P0100';
  exception when raise_exception then null; end;
  perform public.st_v6_set_impersonation_watch(workspace,member_id,null);
  if exists(select 1 from public.st_v6_impersonation_watch_list(workspace))
    or not exists(select 1 from public.st_v2_workspace_audit a where a.workspace_id=workspace
      and a.event='impersonation.watch_removed') then
    raise exception 'Watch removal or audit failed';
  end if;
end $$;

select 'passed: workspace permissions, watch tier, retry, suspension and audit' as result;
rollback;
