begin;

insert into auth.users(id,email,aud,role) values
  ('66000000-0020-4000-8000-000000000001','privacy-owner@example.invalid','authenticated','authenticated'),
  ('66000000-0020-4000-8000-000000000002','privacy-contact@example.invalid','authenticated','authenticated'),
  ('66000000-0020-4000-8000-000000000003','privacy-outsider@example.invalid','authenticated','authenticated');
insert into public.st_profiles(id,handle,name) values
  ('66000000-0020-4000-8000-000000000001','privacy_owner','Privacy owner'),
  ('66000000-0020-4000-8000-000000000002','privacy_contact','Privacy contact'),
  ('66000000-0020-4000-8000-000000000003','privacy_outsider','Privacy outsider');
insert into public.st_chats(id,member_a,member_b,requester,status) values
  ('66000000-0021-4000-8000-000000000001','66000000-0020-4000-8000-000000000001',
   '66000000-0020-4000-8000-000000000002','66000000-0020-4000-8000-000000000001','accepted');
insert into public.st_v2_workspaces(id,name,owner) values
  ('66000000-0022-4000-8000-000000000001','Privacy workspace','66000000-0020-4000-8000-000000000001');
insert into public.st_v2_members(workspace_id,user_id,role) values
  ('66000000-0022-4000-8000-000000000001','66000000-0020-4000-8000-000000000001','owner'),
  ('66000000-0022-4000-8000-000000000001','66000000-0020-4000-8000-000000000002','member');

set local role authenticated;
do $$
declare
  owner_id constant uuid:='66000000-0020-4000-8000-000000000001';
  peer_id constant uuid:='66000000-0020-4000-8000-000000000002';
  outsider_id constant uuid:='66000000-0020-4000-8000-000000000003';
  chat_id constant uuid:='66000000-0021-4000-8000-000000000001';
  workspace_id constant uuid:='66000000-0022-4000-8000-000000000001';
  photo uuid;
  expiry timestamptz;
begin
  perform set_config('request.jwt.claims',json_build_object('sub',owner_id,'role','authenticated')::text,true);
  if public.st_v6_presence_settings() is distinct from '{"required":false,"sharing":true}'::jsonb
    or public.st_v6_workspace_presence_policy(workspace_id) then
    raise exception 'Legacy account or workspace defaults changed';
  end if;
  perform public.st_v3_set_presence('online');
  perform public.st_v5_set_last_seen(true);
  perform public.st_v5_profile_details_save('Shared status',true);
  select photo_revision into strict photo from public.st_v5_profile_details where user_id=owner_id;

  perform set_config('request.jwt.claims',json_build_object('sub',peer_id,'role','authenticated')::text,true);
  if not exists(select 1 from public.st_v3_presence where user_id=owner_id and state='online')
    or public.st_v5_last_seen(chat_id) is null
    or public.st_v6_effective_availability(owner_id)->>'status' is distinct from 'Shared status' then
    raise exception 'Accepted contact lost shared availability';
  end if;
  begin
    perform public.st_v6_set_workspace_presence_policy(workspace_id,true);
    raise exception 'Member changed policy' using errcode='22023';
  exception when insufficient_privilege then null;
  end;

  perform set_config('request.jwt.claims',json_build_object('sub',owner_id,'role','authenticated')::text,true);
  perform public.st_v6_set_presence_privacy(false);
  perform set_config('request.jwt.claims',json_build_object('sub',peer_id,'role','authenticated')::text,true);
  if exists(select 1 from public.st_v3_presence where user_id=owner_id)
    or exists(select 1 from public.st_v5_profile_details where user_id=owner_id)
    or public.st_v5_last_seen(chat_id) is not null
    or public.st_v6_effective_availability(owner_id) is not null
    or public.st_v6_profile_photo_revision(owner_id) is distinct from photo then
    raise exception 'Hidden availability exposed data or hid the photo';
  end if;

  perform set_config('request.jwt.claims',json_build_object('sub',owner_id,'role','authenticated')::text,true);
  perform public.st_v6_set_presence_privacy(true);
  perform public.st_v3_set_presence('invisible');
  select expires_at into strict expiry from public.st_v3_presence where user_id=owner_id and state='invisible';
  perform public.st_v3_ping();
  if expiry is distinct from (select expires_at from public.st_v3_presence where user_id=owner_id) then
    raise exception 'Invisible heartbeat extended presence';
  end if;
  perform public.st_v6_set_workspace_presence_policy(workspace_id,true);
  if public.st_v6_presence_settings() is distinct from '{"required":true,"sharing":true}'::jsonb then
    raise exception 'Did not apply stricter workspace policy';
  end if;
  begin
    perform public.st_v3_set_presence('invisible');
    raise exception 'Strict workspace accepted Invisible' using errcode='22023';
  exception when raise_exception then null;
  end;
  begin
    perform public.st_v6_set_presence_privacy(false);
    raise exception 'Strict workspace accepted a request to hide availability' using errcode='22023';
  exception when raise_exception then null;
  end;

  perform set_config('request.jwt.claims',json_build_object('sub',peer_id,'role','authenticated')::text,true);
  if exists(select 1 from public.st_v3_presence where user_id=owner_id)
    or public.st_v5_last_seen(chat_id) is not null
    or public.st_v6_effective_availability(owner_id) is not null then
    raise exception 'New policy disclosed a previously private member';
  end if;

  perform set_config('request.jwt.claims',json_build_object('sub',outsider_id,'role','authenticated')::text,true);
  if public.st_v6_profile_photo_revision(owner_id) is not null then raise exception 'Outsider read photo revision'; end if;
  begin
    perform public.st_v6_workspace_presence_policy(workspace_id);
    raise exception 'Outsider read workspace policy' using errcode='22023';
  exception when insufficient_privilege then null;
  end;
  begin
    perform public.st_v6_set_workspace_presence_policy(workspace_id,false);
    raise exception 'Outsider changed policy' using errcode='22023';
  exception when insufficient_privilege then null;
  end;

  perform set_config('request.jwt.claims',json_build_object('sub',owner_id,'role','authenticated')::text,true);
  perform public.st_v3_set_presence('away');
  perform public.st_v6_set_workspace_presence_policy(workspace_id,false);
  perform public.st_v3_set_presence('invisible');
end $$;
reset role;

delete from realtime.messages where topic='st:account:66000000-0020-4000-8000-000000000002';
set local role authenticated;
select set_config('request.jwt.claims','{"sub":"66000000-0020-4000-8000-000000000001","role":"authenticated"}',true);
select public.st_v3_ping();
select public.st_v5_profile_details_save('Private edit',false);
select public.st_v3_set_presence('invisible');
reset role;
do $$
begin
  if exists(select 1 from realtime.messages where topic='st:account:66000000-0020-4000-8000-000000000002'
    and event in ('presence','availability')) then
    raise exception 'Invisible activity sent a hint to a contact';
  end if;
end $$;

select 'passed: legacy defaults, private reads and hints, Invisible and workspace roles' as result;
rollback;
