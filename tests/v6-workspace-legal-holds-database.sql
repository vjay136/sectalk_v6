begin;
insert into auth.users(id,email) values
  ('6319aa0a-ad63-4538-9d6d-683b6da3e101','hold-owner@example.invalid'),
  ('6319aa0a-ad63-4538-9d6d-683b6da3e102','hold-member@example.invalid'),
  ('6319aa0a-ad63-4538-9d6d-683b6da3e103','hold-outsider@example.invalid');
insert into public.st_profiles(id,handle,name) values
  ('6319aa0a-ad63-4538-9d6d-683b6da3e101','hold_fixture_owner','Hold owner'),
  ('6319aa0a-ad63-4538-9d6d-683b6da3e102','hold_fixture_member','Hold member'),
  ('6319aa0a-ad63-4538-9d6d-683b6da3e103','hold_fixture_outsider','Hold outsider');
insert into auth.mfa_factors(id,user_id,factor_type,status,created_at,updated_at) values
  ('6319aa0a-ad63-4538-9d6d-683b6da3e111','6319aa0a-ad63-4538-9d6d-683b6da3e101','totp','verified',now(),now());
insert into auth.sessions(id,user_id,aal,factor_id) values
  ('6319aa0a-ad63-4538-9d6d-683b6da3e121','6319aa0a-ad63-4538-9d6d-683b6da3e101','aal2','6319aa0a-ad63-4538-9d6d-683b6da3e111');

do $$
declare
  owner_id constant uuid:='6319aa0a-ad63-4538-9d6d-683b6da3e101';
  member_id constant uuid:='6319aa0a-ad63-4538-9d6d-683b6da3e102';
  outside_id constant uuid:='6319aa0a-ad63-4538-9d6d-683b6da3e103';
  session_id constant uuid:='6319aa0a-ad63-4538-9d6d-683b6da3e121';
  hold_id uuid:=gen_random_uuid();
  person_hold uuid:=gen_random_uuid();
  room uuid:=gen_random_uuid();
  different_room uuid:=gen_random_uuid();
  post uuid:=gen_random_uuid();
  unscoped_post uuid:=gen_random_uuid();
  workspace uuid;
  channel uuid;
  invitation uuid;
  start_at timestamptz:=now()-interval '1 hour';
  valid_claims text:=json_build_object('sub',owner_id,'role','authenticated','aal','aal2','session_id',session_id)::text;
begin
  set local role authenticated;
  perform set_config('request.jwt.claims',json_build_object('sub',owner_id,'role','authenticated','aal','aal2',
    'session_id',gen_random_uuid())::text,true);
  workspace:=public.st_v2_create_workspace('Preservation fixture');
  perform public.st_v6_room_create(room,workspace,'Preserved project','public','blank');
  perform public.st_v6_room_create(different_room,workspace,'Ordinary project','public','blank');
  perform public.st_v2_invite(workspace,'hold_fixture_member');
  if public.st_v6_workspace_hold_state(workspace)->>'access'<>'mfa'
    then raise exception 'A fabricated assurance claim passed'; end if;
  begin
    perform public.st_v6_place_workspace_hold(workspace,hold_id,room,null,start_at,null,'Fictional preservation reason');
    raise exception 'A fabricated assurance claim placed a hold';
  exception when insufficient_privilege then null; end;

  perform set_config('request.jwt.claims',json_build_object('sub',member_id,'role','authenticated')::text,true);
  select id into invitation from public.st_v2_invites where workspace_id=workspace;
  perform public.st_v2_reply_invite(invitation,true);
  perform public.st_v6_room_membership(room,'join');
  perform public.st_v6_room_membership(different_room,'join');
  perform public.st_v6_room_post(room,post,'Fictional preserved original content');
  perform public.st_v6_room_post(different_room,unscoped_post,'Fictional unscoped content');
  begin
    perform public.st_v6_workspace_hold_state(workspace);
    raise exception 'An ordinary workspace member read hold data';
  exception when insufficient_privilege then null; end;
  select id into channel from public.st_v2_channels where workspace_id=workspace and name='general';
  perform public.st_v2_post(channel,gen_random_uuid(),'Fictional held channel content');

  perform set_config('request.jwt.claims',valid_claims,true);
  perform public.st_v6_place_workspace_hold(workspace,hold_id,room,null,start_at,null,'Fictional preservation reason');
  perform public.st_v6_place_workspace_hold(workspace,hold_id,room,null,start_at,null,'Fictional preservation reason');
  perform public.st_v6_place_workspace_hold(workspace,person_hold,null,member_id,start_at,null,'Fictional member-wide preservation');
  perform public.st_v6_room_post_action(room,post,'redact');
  if exists(select 1 from public.st_v6_room_posts where id=post and body='Fictional preserved original content')
    or exists(select 1 from public.st_v6_search('preserved original','room','{}'))
  then raise exception 'A preserved original was visible to normal readers or search'; end if;
  if jsonb_array_length(public.st_v6_workspace_hold_state(workspace)->'holds')<>2 then
    raise exception 'Hold creation was not idempotent'; end if;
  reset role;
  if (select count(*) from sectalk_private.st_v6_preserved_post_versions v where post_id=post)<>2
    or not exists(select 1 from sectalk_private.st_v6_preserved_post_versions v
      cross join vault.decrypted_secrets s where v.post_id=post and s.name='sectalk_v6_hold_archive_key'
      and extensions.pgp_sym_decrypt(v.encrypted_body,s.decrypted_secret)='Fictional preserved original content')
  then raise exception 'Original text was not preserved in both scoped archives'; end if;
  begin
    delete from public.st_v6_room_posts where id=post;
    raise exception 'Physical deletion bypassed a hold' using errcode='P0100';
  exception when raise_exception then
    if sqlerrm not like '%retention hold%' then raise; end if;
  end;
  begin
    delete from public.st_v2_channels where id=channel;
    raise exception 'Channel cascade bypassed the member hold' using errcode='P0100';
  exception when raise_exception then
    if sqlerrm not like '%retention hold%' then raise; end if;
  end;
  set local role authenticated;
  perform public.st_v6_release_workspace_hold(workspace,person_hold,'Fictional release reason');
  reset role;
  delete from public.st_v6_room_posts where id=unscoped_post;
  if found is false then raise exception 'Released scope remained locked'; end if;
  set local role authenticated;
  perform public.st_v6_release_workspace_hold(workspace,hold_id,'Fictional release reason');
  if (select count(*) from public.st_v2_workspace_audit where event='workspace.hold_released' and workspace_id=workspace)<>2
    then raise exception 'Release audit is missing'; end if;
  perform set_config('request.jwt.claims',json_build_object('sub',outside_id,'role','authenticated','aal','aal2',
    'session_id',session_id)::text,true);
  begin
    perform public.st_v6_workspace_hold_state(workspace);
    raise exception 'A cross-tenant user read hold data';
  exception when insufficient_privilege then null; end;
end $$;
select 'passed: MFA role and tenant scope, encrypted revisions, protected deletion and release audit' as result;
rollback;
