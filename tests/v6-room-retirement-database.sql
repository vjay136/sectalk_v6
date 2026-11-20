begin;
insert into auth.users(id,email) values
  ('6319aa0a-ad64-4548-9d6d-683b6da3e101','retirement-owner@example.invalid'),
  ('6319aa0a-ad64-4548-9d6d-683b6da3e102','retirement-member@example.invalid');
insert into public.st_profiles(id,handle,name) values
  ('6319aa0a-ad64-4548-9d6d-683b6da3e101','retirement_owner','Retirement owner'),
  ('6319aa0a-ad64-4548-9d6d-683b6da3e102','retirement_member','Retirement member');
insert into auth.mfa_factors(id,user_id,factor_type,status,created_at,updated_at) values
  ('6319aa0a-ad64-4548-9d6d-683b6da3e111','6319aa0a-ad64-4548-9d6d-683b6da3e101','totp','verified',now(),now());
insert into auth.sessions(id,user_id,aal,factor_id) values
  ('6319aa0a-ad64-4548-9d6d-683b6da3e121','6319aa0a-ad64-4548-9d6d-683b6da3e101','aal2','6319aa0a-ad64-4548-9d6d-683b6da3e111');

do $$
declare
  owner_id constant uuid:='6319aa0a-ad64-4548-9d6d-683b6da3e101';
  member_id constant uuid:='6319aa0a-ad64-4548-9d6d-683b6da3e102';
  session_id constant uuid:='6319aa0a-ad64-4548-9d6d-683b6da3e121';
  workspace uuid;
  held uuid:=gen_random_uuid();
  candidate uuid:=gen_random_uuid();
  restored uuid:=gen_random_uuid();
  hold_id uuid:=gen_random_uuid();
  invite_id uuid;
  purged integer;
  owner_claims text:=json_build_object('sub',owner_id,'role','authenticated','aal','aal2','session_id',session_id)::text;
begin
  set local role authenticated;
  perform set_config('request.jwt.claims',owner_claims,true);
  workspace:=public.st_v2_create_workspace('Room retirement fixture');
  if public.st_v6_room_retention_policy(workspace)<>30 then raise exception 'Wrong retention default'; end if;
  perform public.st_v6_room_retention_policy(workspace,7);
  perform public.st_v6_room_create(held,workspace,'Held retirement room','public','blank');
  perform public.st_v6_room_create(candidate,workspace,'Ordinary retirement room','public','blank');
  perform public.st_v6_room_create(restored,workspace,'Restore retirement room','public','blank');
  perform public.st_v2_invite(workspace,'retirement_member');
  begin
    perform public.st_v6_room_retirement(held,'schedule');
    raise exception 'Active room could be scheduled' using errcode='P0100';
  exception when raise_exception then
    if sqlerrm not like '%Archive the room%' then raise; end if;
  end;
  perform set_config('request.jwt.claims',json_build_object('sub',member_id,'role','authenticated')::text,true);
  select id into invite_id from public.st_v2_invites where workspace_id=workspace;
  perform public.st_v2_reply_invite(invite_id,true);
  perform public.st_v6_room_membership(held,'join');
  begin
    perform public.st_v6_room_retention_policy(workspace,7);
    raise exception 'Ordinary member changed retention';
  exception when insufficient_privilege then null; end;
  perform set_config('request.jwt.claims',owner_claims,true);
  perform public.st_v6_room_settings(held,'archive');
  perform public.st_v6_room_settings(candidate,'archive');
  perform public.st_v6_room_settings(restored,'archive');
  perform public.st_v6_room_retirement(held,'schedule');
  perform public.st_v6_room_retirement(held,'schedule');
  perform public.st_v6_room_retirement(candidate,'schedule');
  perform public.st_v6_room_retirement(restored,'schedule');
  perform public.st_v6_room_settings(restored,'restore');
  if public.st_v6_room_retirement(restored)->>'requested_at' is not null then
    raise exception 'Restore did not cancel scheduled deletion'; end if;
  perform public.st_v6_place_workspace_hold(workspace,hold_id,held,null,null,null,'Fixture preserves the archived room');
  if (public.st_v6_room_retirement(held)->>'held')::boolean is not true then
    raise exception 'Failure to report an active hold'; end if;
  perform set_config('request.jwt.claims',json_build_object('sub',member_id,'role','authenticated')::text,true);
  if (public.st_v6_room_retirement(held)->>'held')::boolean is not false then
    raise exception 'Preservation status was exposed to an ordinary room member'; end if;
  perform set_config('request.jwt.claims',owner_claims,true);
  reset role;
  if sectalk_private.st_v6_purge_retired_rooms()<>0 then raise exception 'Grace period was skipped'; end if;
  update sectalk_private.st_v6_room_retirements set requested_at=now()-interval '8 days' where room_id in (held,candidate);
  purged:=sectalk_private.st_v6_purge_retired_rooms();
  if purged<>1
    or exists(select 1 from public.st_v6_rooms where id=candidate)
    or not exists(select 1 from public.st_v6_rooms where id=held)
  then raise exception 'A hold blocked other work or allowed a held room to purge'; end if;
  set local role authenticated;
  perform public.st_v6_release_workspace_hold(workspace,hold_id,'Fixture clears the preservation hold');
  reset role;
  purged:=sectalk_private.st_v6_purge_retired_rooms();
  if purged<>1 or exists(select 1 from public.st_v6_rooms where id=held)
    or not exists(select 1 from public.st_v6_rooms where id=restored and not archived)
  then raise exception 'Release/restore purge rules were not enforced'; end if;
  if (select count(*) from public.st_v2_workspace_audit where workspace_id=workspace and event='room.purged')<>2 then
    raise exception 'Purge auditing diverged'; end if;
end $$;
select 'passed: owner-only scheduling, policy, grace, restore cancellation, scoped hold and actual purge' as result;
rollback;
