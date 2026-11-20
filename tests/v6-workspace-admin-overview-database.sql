begin;
insert into auth.users(id,email,email_confirmed_at)
select ('a1dc3476-1831-4dba-89ac-'||lpad(n::text,12,'0'))::uuid,
  'workspace-overview-'||n||'@example.invalid',now() from generate_series(1,7) n;
insert into public.st_profiles(id,name,handle)
select ('a1dc3476-1831-4dba-89ac-'||lpad(n::text,12,'0'))::uuid,
  'Overview fixture '||n,'overview_fixture_'||n from generate_series(1,7) n;

do $$
declare
  owner_id uuid:='a1dc3476-1831-4dba-89ac-000000000001';
  outsider uuid:='a1dc3476-1831-4dba-89ac-000000000007';
  actor uuid;
  workspace uuid;
  other_workspace uuid;
  room uuid:=gen_random_uuid();
  private_room uuid:=gen_random_uuid();
  invite_id uuid;
  summary jsonb;
begin
  set local role authenticated;
  perform set_config('request.jwt.claims',json_build_object('sub',owner_id,'role','authenticated')::text,true);
  workspace:=public.st_v2_create_workspace('Overview fixture');
  perform public.st_v6_room_create(room,workspace,'Shared discussion','public','blank');
  perform public.st_v6_room_create(private_room,workspace,'Restricted discussion','private','blank');
  for n in 2..6 loop perform public.st_v2_invite(workspace,'overview_fixture_'||n); end loop;
  perform public.st_v6_workspace_link_create(workspace,'guest-overview@example.invalid',1);
  summary:=public.st_v6_workspace_admin_overview(workspace);
  if (summary->>'occupied')::integer<>1 or (summary->>'seat_limit')::integer<>5
    or summary->>'contributors' is not null or (summary->>'pending_invites')::integer<>6
  then raise exception 'Initial seat or alert snapshot was inaccurate'; end if;
  for n in 2..5 loop
    actor:=('a1dc3476-1831-4dba-89ac-'||lpad(n::text,12,'0'))::uuid;
    perform set_config('request.jwt.claims',json_build_object('sub',actor,'role','authenticated')::text,true);
    select i.id into invite_id from public.st_v2_invites i where i.workspace_id=workspace and i.invitee=actor;
    perform public.st_v2_reply_invite(invite_id,true);
    if n<5 then
      perform public.st_v6_room_membership(room,'join');
      perform public.st_v6_room_post(room,gen_random_uuid(),'Shared adoption fixture');
    end if;
  end loop;
  perform public.st_v6_room_membership(private_room,'request');
  begin
    perform public.st_v6_workspace_admin_overview(workspace);
    raise exception 'Ordinary members could read admin numbers';
  exception when insufficient_privilege then null; end;
  perform set_config('request.jwt.claims',json_build_object('sub',outsider,'role','authenticated')::text,true);
  other_workspace:=public.st_v2_create_workspace('Another overview fixture');
  perform public.st_v6_workspace_link_create(other_workspace,'foreign-overview@example.invalid',1);
  begin
    perform public.st_v6_workspace_admin_overview(workspace);
    raise exception 'Cross-tenant owner saw unrelated data';
  exception when insufficient_privilege then null; end;
  perform set_config('request.jwt.claims',json_build_object('sub',owner_id,'role','authenticated')::text,true);
  summary:=public.st_v6_workspace_admin_overview(workspace);
  if (summary->>'occupied')::integer<>5 or (summary->>'active')::integer<>5
    or (summary->>'contributors')::integer<>3 or (summary->>'pending_invites')::integer<>2
    or (summary->>'expiring_links')::integer<>1 or (summary->>'access_requests')::integer<>1
    or summary::text like '%fixture%' or summary::text like '%example.invalid%'
  then raise exception 'Adoption, invitation deadlines or workspace scope was inaccurate'; end if;
  reset role;
  update public.st_v2_members set suspended_at=now() where workspace_id=workspace
    and user_id='a1dc3476-1831-4dba-89ac-000000000002';
  set local role authenticated;
  summary:=public.st_v6_workspace_admin_overview(workspace);
  if (summary->>'occupied')::integer<>5 or (summary->>'active')::integer<>4 or summary->>'contributors' is not null
  then raise exception 'Suspension did not preserve occupied seats and suppress small cohorts'; end if;
end $$;
select 'passed: plan seats, pending requests, expiring links, scoped adoption and cross-tenant denial' as result;
rollback;
