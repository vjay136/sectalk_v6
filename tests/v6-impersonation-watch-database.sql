begin;
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
  perform public.st_v2_set_member(workspace,member_id,'suspend');
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
