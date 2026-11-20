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
  ('69000000-0000-4000-8000-000000000001','context-owner@example.invalid','authenticated','authenticated'),
  ('69000000-0000-4000-8000-000000000002','context-member@example.invalid','authenticated','authenticated');
insert into public.st_profiles(id,handle,name) values
  ('69000000-0000-4000-8000-000000000001','context_fixture_owner','Other workspace owner'),
  ('69000000-0000-4000-8000-000000000002','context_fixture_member','Multi-workspace account');

set local role authenticated;
do $$
declare
  alternate_owner constant uuid:='69000000-0000-4000-8000-000000000001';
  multi_member constant uuid:='69000000-0000-4000-8000-000000000002';
  first uuid;
  second uuid;
  invite_id uuid;
begin
  perform set_config('request.jwt.claims',json_build_object('sub',multi_member,'role','authenticated')::text,true);
  first:=public.st_v2_create_workspace('First fixture workspace');
  perform set_config('request.jwt.claims',json_build_object('sub',alternate_owner,'role','authenticated')::text,true);
  second:=public.st_v2_create_workspace('Second fixture workspace');
  perform public.st_v2_invite(second,'context_fixture_member');
  perform set_config('request.jwt.claims',json_build_object('sub',multi_member,'role','authenticated')::text,true);
  if exists(select 1 from public.st_v2_workspaces where id=second)
    then raise exception 'A pending invitation grants workspace access'; end if;
  select id into invite_id from public.st_v2_invites where workspace_id=second;
  perform public.st_v2_reply_invite(invite_id,true);
  if (select count(*) from public.st_v2_workspaces where id in (first,second))<>2
    or not exists(select 1 from public.st_v2_members where workspace_id=first and user_id=multi_member and role='owner')
    or not exists(select 1 from public.st_v2_members where workspace_id=second and user_id=multi_member and role='member')
    then raise exception 'Multi-workspace roles were not isolated'; end if;
  begin
    perform public.st_v2_set_member(second,alternate_owner,'remove');
    raise exception 'An owner crossed a workspace boundary' using errcode='P0004';
  exception when raise_exception then null; end;
  perform set_config('request.jwt.claims',json_build_object('sub',alternate_owner,'role','authenticated')::text,true);
  if exists(select 1 from public.st_v2_workspaces where id=first)
    then raise exception 'An owner discovered an unrelated workspace'; end if;
  perform pg_temp.set_verified_member(second,multi_member,'admin');
  perform pg_temp.set_verified_member(second,multi_member,'remove');
  perform set_config('request.jwt.claims',json_build_object('sub',multi_member,'role','authenticated')::text,true);
  if exists(select 1 from public.st_v2_workspaces where id=second)
    or not exists(select 1 from public.st_v2_workspaces where id=first)
    then raise exception 'Revoked membership affected the wrong tenant'; end if;
end $$;
reset role;

do $$
begin
  -- Realtime attaches its own generated event identifier to the empty app payload.
  if (select count(*) from realtime.messages where event='workspace_memberships'
      and topic='st:account:69000000-0000-4000-8000-000000000002' and private and payload-'id'='{}'::jsonb)<>4
    or (select count(*) from realtime.messages where event='workspace_memberships'
      and topic='st:account:69000000-0000-4000-8000-000000000001' and private and payload-'id'='{}'::jsonb)<>1
    then raise exception 'Membership changes did not send private content-free invalidations to the affected account'; end if;
end $$;

select 'passed: multi-workspace roles, membership removal, RLS, and private content-free membership invalidation' as result;
rollback;
