begin;
insert into auth.users(id,email,email_confirmed_at)
  select ('99900000-0000-4000-8000-'||lpad(n::text,12,'0'))::uuid,
    'invite-'||n||'@example.invalid',case when n<>4 then now() end
  from generate_series(1,8) n;
insert into public.st_profiles(id,handle,name)
  select ('99900000-0000-4000-8000-'||lpad(n::text,12,'0'))::uuid,'link_fixture_'||n,'Link Fixture '||n
  from generate_series(1,8) n;

do $$
declare
  owner_id constant uuid:='99900000-0000-4000-8000-000000000001';
  recipient constant uuid:='99900000-0000-4000-8000-000000000002';
  wrong constant uuid:='99900000-0000-4000-8000-000000000003';
  unconfirmed constant uuid:='99900000-0000-4000-8000-000000000004';
  expired constant uuid:='99900000-0000-4000-8000-000000000005';
  workspace uuid;
  token text;
  token_for_unconfirmed text;
  token_for_expired text;
  token_for_seat text;
begin
  set local role authenticated;
  perform set_config('request.jwt.claims',json_build_object('sub',owner_id,'role','authenticated')::text,true);
  workspace:=public.st_v2_create_workspace('Email Link Fixture');
  perform public.st_v6_workspace_link_policy_set(workspace,array['EXAMPLE.INVALID']);
  if public.st_v6_workspace_link_policy_get(workspace)<>array['example.invalid']
    then raise exception 'Domain was not normalized'; end if;
  begin
    perform public.st_v6_workspace_link_create(workspace,'wrong@unapproved.invalid',24);
    raise exception 'Invitation issued outside the domain policy' using errcode='P0100';
  exception when raise_exception then null; end;
  token:=public.st_v6_workspace_link_create(workspace,'invite-2@example.invalid',24)->>'token';
  token_for_unconfirmed:=public.st_v6_workspace_link_create(workspace,'invite-4@example.invalid',24)->>'token';
  token_for_expired:=public.st_v6_workspace_link_create(workspace,'invite-5@example.invalid',24)->>'token';
  token_for_seat:=public.st_v6_workspace_link_create(workspace,'invite-3@example.invalid',24)->>'token';

  perform set_config('request.jwt.claims',json_build_object('sub',wrong,'role','authenticated')::text,true);
  begin
    perform public.st_v6_workspace_link_accept(token);
    raise exception 'A different verified email redeemed the link' using errcode='P0100';
  exception when raise_exception then null; end;
  begin
    perform public.st_v6_workspace_link_policy_get(workspace);
    raise exception 'Outsider could read the policy';
  exception when insufficient_privilege then null; end;
  perform set_config('request.jwt.claims',json_build_object('sub',unconfirmed,'role','authenticated')::text,true);
  begin
    perform public.st_v6_workspace_link_accept(token_for_unconfirmed);
    raise exception 'An unconfirmed email redeemed the link' using errcode='P0100';
  exception when raise_exception then null; end;

  reset role;
  update sectalk_private.st_v6_workspace_link_invites set expires_at=clock_timestamp()-interval '1 second'
    where token_hash=sha256(convert_to(token_for_expired,'UTF8'));
  if has_table_privilege('authenticated','sectalk_private.st_v6_workspace_link_invites','SELECT')
    or not exists(select 1 from sectalk_private.st_v6_workspace_link_invites i
      where i.workspace_id=workspace and i.token_hash=sha256(convert_to(token,'UTF8')))
  then raise exception 'Invite hash or storage access was incorrect'; end if;
  set local role authenticated;
  perform set_config('request.jwt.claims',json_build_object('sub',expired,'role','authenticated')::text,true);
  begin
    perform public.st_v6_workspace_link_accept(token_for_expired);
    raise exception 'An expired email link was accepted' using errcode='P0100';
  exception when raise_exception then null; end;
  perform set_config('request.jwt.claims',json_build_object('sub',recipient,'role','authenticated')::text,true);
  if public.st_v6_workspace_link_accept(token)<>workspace
  then raise exception 'Verified recipient did not join'; end if;
  if not exists(select 1 from public.st_v2_members where workspace_id=workspace and user_id=recipient and role='member')
  then raise exception 'Verified recipient did not join'; end if;
  begin
    perform public.st_v6_workspace_link_accept(token);
    raise exception 'The invitation link was reusable' using errcode='P0100';
  exception when raise_exception then null; end;
  reset role;
  insert into public.st_v2_members(workspace_id,user_id) values
    (workspace,'99900000-0000-4000-8000-000000000006'),
    (workspace,'99900000-0000-4000-8000-000000000007'),
    (workspace,'99900000-0000-4000-8000-000000000008');
  set local role authenticated;
  perform set_config('request.jwt.claims',json_build_object('sub',wrong,'role','authenticated')::text,true);
  begin
    perform public.st_v6_workspace_link_accept(token_for_seat);
    raise exception 'An email link exceeded the seat limit' using errcode='P0100';
  exception when raise_exception then
    if sqlerrm<>'Workspace has no available seats' then raise; end if;
  end;
end $$;
select 'passed: hashed links, domain policy, verified email matching, expiry, replay and seats' as result;
rollback;
