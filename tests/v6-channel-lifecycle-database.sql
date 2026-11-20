begin;

-- Use an authoritative native session for this ownership-transfer fixture.
create function pg_temp.refresh_owner_proof()
returns void language plpgsql security definer set search_path='' as $$
declare actor uuid:=auth.uid(); native_session uuid:=gen_random_uuid(); factor uuid;
begin
  select id into factor from auth.mfa_factors f where f.user_id=actor and f.status='verified'
    and f.factor_type='totp' limit 1;
  insert into auth.sessions(id,user_id,aal,factor_id,created_at)
    values(native_session,actor,case when factor is null then 'aal1'::auth.aal_level else 'aal2'::auth.aal_level end,factor,now());
  insert into auth.mfa_amr_claims(id,session_id,authentication_method,created_at,updated_at)
    values(gen_random_uuid(),native_session,case when factor is null then 'password' else 'totp' end,now(),now());
  perform set_config('request.jwt.claims',jsonb_build_object('sub',actor,'role','authenticated',
    'session_id',native_session,'aal',case when factor is null then 'aal1' else 'aal2' end)::text,true);
end $$;

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
 ('68000000-0000-4000-8000-000000000001','channel-owner@example.invalid','authenticated','authenticated'),
 ('68000000-0000-4000-8000-000000000002','channel-admin@example.invalid','authenticated','authenticated'),
 ('68000000-0000-4000-8000-000000000003','channel-member@example.invalid','authenticated','authenticated'),
 ('68000000-0000-4000-8000-000000000004','channel-outsider@example.invalid','authenticated','authenticated');
insert into public.st_profiles(id,handle,name) values
 ('68000000-0000-4000-8000-000000000001','channel_qa_owner','Channel owner'),
 ('68000000-0000-4000-8000-000000000002','channel_qa_admin','Channel admin'),
 ('68000000-0000-4000-8000-000000000003','channel_qa_member','Channel member'),
 ('68000000-0000-4000-8000-000000000004','channel_qa_outsider','Channel outsider');

set local role authenticated;
do $$
declare
  owner_id constant uuid:='68000000-0000-4000-8000-000000000001';
  admin_id constant uuid:='68000000-0000-4000-8000-000000000002';
  member_id constant uuid:='68000000-0000-4000-8000-000000000003';
  outsider_id constant uuid:='68000000-0000-4000-8000-000000000004';
  post_id constant uuid:=gen_random_uuid();
  workspace uuid;
  channel uuid;
  invite uuid;
  overview jsonb;
begin
  perform set_config('request.jwt.claim.sub',owner_id::text,true);
  workspace:=public.st_v2_create_workspace('Channel lifecycle acceptance');
  if not exists(select 1 from public.st_v2_channels where workspace_id=workspace and name='general'
    and owner=owner_id and visibility='workspace' and not archived) then raise exception 'General default changed'; end if;
  perform public.st_v2_invite(workspace,'channel_qa_admin');
  perform public.st_v2_invite(workspace,'channel_qa_member');
  channel:=public.st_v2_create_channel(workspace,'channel-lifecycle');
  perform public.st_v2_post(channel,post_id,'Lifecycle channel history');
  perform public.st_v2_post(channel,post_id,'Lifecycle channel history');

  perform set_config('request.jwt.claim.sub',admin_id::text,true);
  select id into invite from public.st_v2_invites where workspace_id=workspace and invitee=admin_id;
  perform public.st_v2_reply_invite(invite,true);
  perform set_config('request.jwt.claim.sub',member_id::text,true);
  select id into invite from public.st_v2_invites where workspace_id=workspace and invitee=member_id;
  perform public.st_v2_reply_invite(invite,true);
  if not exists(select 1 from public.st_v2_posts where id=post_id)
    or public.st_v6_channel_details(channel)<>'{"can_read":true,"can_manage":false}'::jsonb
    then raise exception 'Workspace-wide default access or audit boundaries failed'; end if;
  perform public.st_v2_post(channel,gen_random_uuid(),'Ordinary member reply');
  begin
    perform public.st_v6_manage_channel(channel,'visibility',p_visibility=>'private');
    raise exception 'Expected management action rejection';
  exception when raise_exception then
    if sqlerrm<>'Channel management unavailable' then raise; end if;
  end;

  perform set_config('request.jwt.claim.sub',owner_id::text,true);
  perform pg_temp.set_verified_member(workspace,admin_id,'admin');
  perform public.st_v6_manage_channel(channel,'visibility',p_visibility=>'private');
  perform set_config('request.jwt.claim.sub',member_id::text,true);
  if exists(select 1 from public.st_v2_channels where id=channel) or exists(select 1 from public.st_v2_posts where id=post_id)
    or public.st_v6_channel_details(channel)<>'{"can_read":false,"can_manage":false}'::jsonb
    then raise exception 'Private channel or history was disclosed'; end if;
  begin
    perform public.st_v2_post(channel,gen_random_uuid(),'Unavailable channel fixture');
    raise exception 'Expected private post rejection';
  exception when raise_exception then
    if sqlerrm<>'Channel unavailable' then raise; end if;
  end;

  perform set_config('request.jwt.claim.sub',admin_id::text,true);
  if not exists(select 1 from public.st_v2_channels where id=channel) or exists(select 1 from public.st_v2_posts where id=post_id)
    then raise exception 'Manager metadata or private content boundaries failed'; end if;
  overview:=public.st_v6_channel_details(channel);
  if overview->>'can_read'<>'false' or overview->>'can_manage'<>'true' then raise exception 'Manager permissions were misreported'; end if;
  begin
    perform public.st_v6_manage_channel(channel,'add_member',p_target=>outsider_id);
    raise exception 'Expected cross-workspace membership rejection';
  exception when raise_exception then
    if sqlerrm<>'Choose an active workspace member' then raise; end if;
  end;
  perform public.st_v6_manage_channel(channel,'add_member',p_target=>member_id);
  perform public.st_v6_manage_channel(channel,'add_member',p_target=>member_id);

  perform set_config('request.jwt.claim.sub',member_id::text,true);
  if not exists(select 1 from public.st_v2_posts where id=post_id) then raise exception 'Admitted reader could not access history'; end if;
  perform set_config('request.jwt.claim.sub',admin_id::text,true);
  if (select count(*) from jsonb_array_elements(public.st_v6_channel_details(channel)->'audit') a
    where a->>'action'='add_member' and a->>'actor'=admin_id::text and a->>'target'=member_id::text)<>1
    then raise exception 'Membership addition or stable retry audit failed'; end if;
  perform pg_temp.refresh_owner_proof();
  perform public.st_v6_manage_channel(channel,'transfer_owner',p_target=>member_id);
  perform set_config('request.jwt.claims','',true);

  perform set_config('request.jwt.claim.sub',member_id::text,true);
  if not exists(select 1 from public.st_v2_channels where id=channel and owner=member_id)
    or public.st_v6_channel_details(channel)->>'can_manage'<>'true' then raise exception 'Channel ownership failed'; end if;
  perform public.st_v6_manage_channel(channel,'archive');
  if not exists(select 1 from public.st_v2_posts where id=post_id) then raise exception 'Archive erased existing access'; end if;
  begin
    perform public.st_v2_post(channel,gen_random_uuid(),'Archive fixture');
    raise exception 'Expected archived post rejection';
  exception when raise_exception then
    if sqlerrm<>'Channel unavailable' then raise; end if;
  end;

  perform set_config('request.jwt.claim.sub',owner_id::text,true);
  perform public.st_v6_manage_channel(channel,'restore');
  perform public.st_v6_manage_channel(channel,'add_member',p_target=>admin_id);
  perform pg_temp.set_verified_member(workspace,admin_id,'remove');
  perform pg_temp.set_verified_member(workspace,member_id,'remove');
  overview:=public.st_v6_channel_details(channel);
  if overview->'members'<>'[]'::jsonb or not exists(select 1 from public.st_v2_channels where id=channel and owner=owner_id and not archived)
    or not exists(select 1 from jsonb_array_elements(overview->'audit') a where a->>'action'='workspace_departure' and a->>'target'=admin_id::text)
    or not exists(select 1 from jsonb_array_elements(overview->'audit') a where a->>'action'='restore')
    then raise exception 'Workspace departure or restore cleanup failed'; end if;
  perform public.st_v2_post(channel,gen_random_uuid(),'Restored channel post');

  perform set_config('request.jwt.claim.sub',outsider_id::text,true);
  if exists(select 1 from public.st_v2_channels where id=channel) or exists(select 1 from public.st_v2_posts where id=post_id)
    or public.st_v6_channel_details(channel)<>'{"can_read":false,"can_manage":false}'::jsonb
    then raise exception 'Channel lifecycle crossed the workspace boundary'; end if;
end $$;

rollback;
