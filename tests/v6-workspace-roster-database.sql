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


insert into auth.users(id,email,aud,role)
select ('63000000-0000-4000-8000-00000000000'||i)::uuid,
  'roster-'||i||'@example.invalid','authenticated','authenticated'
from generate_series(1,5) i;
insert into public.st_profiles(id,handle,name)
select ('63000000-0000-4000-8000-00000000000'||i)::uuid,'roster_'||i,'Roster '||i
from generate_series(1,5) i;

set local role authenticated;
do $$
declare
  owner_id constant uuid:='63000000-0000-4000-8000-000000000001';
  admin_id constant uuid:='63000000-0000-4000-8000-000000000002';
  member_id constant uuid:='63000000-0000-4000-8000-000000000003';
  second_admin constant uuid:='63000000-0000-4000-8000-000000000004';
  invitee uuid;
  space_a uuid;
  space_b uuid;
  channel uuid;
  history uuid:=gen_random_uuid();
  invitation uuid;
  report jsonb;
begin
  perform set_config('request.jwt.claim.sub',owner_id::text,true);
  space_a:=public.st_v2_create_workspace('Roster tenant A');
  channel:=public.st_v2_create_channel(space_a,'roster-channel');
  perform public.st_v2_post(channel,history,'Workspace history');
  for invitation in select unnest(array[admin_id,member_id,second_admin]) loop
    if not public.st_v2_invite(space_a,(select 'roster_'||right(invitation::text,1))) then
      raise exception 'Single invitation failed';
    end if;
  end loop;
  foreach invitee in array array[admin_id,member_id,second_admin] loop
    perform set_config('request.jwt.claim.sub',invitee::text,true);
    select id into strict invitation from public.st_v2_invites where workspace_id=space_a and st_v2_invites.invitee=auth.uid();
    perform public.st_v2_reply_invite(invitation,true);
  end loop;

  perform set_config('request.jwt.claim.sub',member_id::text,true);
  space_b:=public.st_v2_create_workspace('Roster tenant B');

  perform set_config('request.jwt.claim.sub',owner_id::text,true);
  perform pg_temp.set_verified_member(space_a,admin_id,'admin');
  perform pg_temp.set_verified_member(space_a,second_admin,'admin');
  perform public.st_v6_manage_channel(channel,'transfer_owner',member_id,null);

  perform set_config('request.jwt.claim.sub',admin_id::text,true);
  begin
    perform public.st_v2_set_member(space_a,second_admin,'suspend');
    raise exception 'Administrator suspended peer';
  exception when raise_exception then
    if sqlerrm<>'Workspace member unavailable' then raise; end if;
  end;
  begin
    perform public.st_v2_set_member(space_a,owner_id,'suspend');
    raise exception 'Administrator suspended owner';
  exception when raise_exception then
    if sqlerrm<>'Workspace member unavailable' then raise; end if;
  end;
  begin
    perform public.st_v2_set_member(space_a,member_id,'admin');
    raise exception 'Administrator promoted member';
  exception when raise_exception then
    if sqlerrm<>'Workspace member unavailable' then raise; end if;
  end;
  perform pg_temp.set_verified_member(space_a,member_id,'suspend');
  perform pg_temp.set_verified_member(space_a,member_id,'suspend');
  if (select count(*) from public.st_v2_workspace_audit where workspace_id=space_a and event='member.suspend')<>1
    then raise exception 'Repeated suspension created duplicate audit entries'; end if;

  select jsonb_object_agg(r.handle,r.sent) into report from public.st_v6_bulk_workspace_invite(space_a,
    array[' roster_5 ','ROSTER_5','roster_3','missing_roster']) r;
  if report is distinct from '{"roster_5":true,"roster_3":false,"missing_roster":false}'::jsonb
    then raise exception 'Bulk invitation normalization, deduplication or skip handling failed: %',report; end if;
  if public.st_v2_invite(space_a,'roster_5') then raise exception 'Bulk invitation duplicated by single invitation'; end if;

  perform set_config('request.jwt.claim.sub',member_id::text,true);
  if exists(select 1 from public.st_v2_workspaces where id=space_a)
    or exists(select 1 from public.st_v2_members where workspace_id=space_a)
    or exists(select 1 from public.st_v2_posts where id=history)
    or exists(select 1 from public.st_v2_channels where id=channel)
    or not exists(select 1 from public.st_v2_workspaces where id=space_b)
    or (public.st_v6_channel_details(channel)->>'can_manage')::boolean
  then raise exception 'Suspension failed tenant or channel isolation'; end if;
  begin
    perform public.st_v2_post(channel,gen_random_uuid(),'Suspended member post');
    raise exception 'Suspended member posted';
  exception when raise_exception then
    if sqlerrm<>'Channel unavailable' then raise; end if;
  end;
  begin
    perform public.st_v6_bulk_workspace_invite(space_a,array['roster_5']);
    raise exception 'Suspended member imported a roster';
  exception when raise_exception then
    if sqlerrm<>'Workspace action unavailable' then raise; end if;
  end;

  perform set_config('request.jwt.claim.sub',owner_id::text,true);
  perform pg_temp.set_verified_member(space_a,admin_id,'suspend');
  perform set_config('request.jwt.claim.sub',admin_id::text,true);
  if exists(select 1 from public.st_v6_audit_workspaces() w where w.id=space_a)
    then raise exception 'Suspended administrator saw the audit workspace'; end if;

  perform set_config('request.jwt.claim.sub',owner_id::text,true);
  perform pg_temp.set_verified_member(space_a,admin_id,'restore');
  perform set_config('request.jwt.claim.sub',admin_id::text,true);
  if not exists(select 1 from public.st_v6_audit_workspaces() w where w.id=space_a)
    then raise exception 'Restored administrator lost their role'; end if;
  perform pg_temp.set_verified_member(space_a,member_id,'restore');

  perform set_config('request.jwt.claim.sub',member_id::text,true);
  if not exists(select 1 from public.st_v2_posts where id=history)
    or not (public.st_v6_channel_details(channel)->>'can_manage')::boolean
  then raise exception 'Restore lost messages or channel ownership'; end if;

  perform set_config('request.jwt.claim.sub','63000000-0000-4000-8000-000000000005',true);
  select id into strict invitation from public.st_v2_invites where workspace_id=space_a and st_v2_invites.invitee=auth.uid();
  if public.st_v2_reply_invite(invitation,true) is distinct from space_a
    then raise exception 'Could not accept invitation from bulk import'; end if;
end $$;
reset role;

select 'passed: tenant suspension, hierarchy, restore, history retention and bulk invitations' as result;
rollback;
