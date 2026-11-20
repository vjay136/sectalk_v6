begin;

-- Materialize one entitlement snapshot per immutable catalog revision. Current
-- ownership and subscription state are still read on every policy decision.
create table sectalk_private.st_v7_plan_entitlements (
  plan text not null,
  version integer not null,
  workspace_limit integer not null check(workspace_limit between 1 and 10000),
  seat_limit integer not null check(seat_limit between 1 and 10000),
  group_limit integer not null check(group_limit between 2 and 32),
  file_bytes integer not null check(file_bytes between 0 and 4194304),
  storage_bytes bigint not null check(storage_bytes between file_bytes and 1099511627776),
  task_creation boolean not null,
  recurring_meetings boolean not null,
  integration_api boolean not null,
  primary key(plan,version),
  foreign key(plan,version) references sectalk_private.st_v6_plan_versions
);
alter table sectalk_private.st_v7_plan_entitlements enable row level security;
revoke all on sectalk_private.st_v7_plan_entitlements from public,anon,authenticated,service_role;

insert into sectalk_private.st_v7_plan_entitlements
select v.plan,v.version,p.workspaces,p.seats,p.groups,p.file_bytes,p.storage_bytes,true,true,p.api
from sectalk_private.st_v6_plan_versions v join (values
  ('free',1,5,4,1048576,33554432::bigint,false),
  ('basic',2,12,8,2097152,134217728::bigint,false),
  ('professional',5,30,16,3145728,536870912::bigint,false),
  ('business',20,100,24,4194304,2147483648::bigint,true),
  ('enterprise',100,500,32,4194304,8589934592::bigint,true)
) p(plan,workspaces,seats,groups,file_bytes,storage_bytes,api) on p.plan=v.plan;

create function sectalk_private.st_v7_inherit_plan_entitlements()
returns trigger language plpgsql security definer set search_path='' as $$
begin
  insert into sectalk_private.st_v7_plan_entitlements
    select new.plan,new.version,e.workspace_limit,e.seat_limit,e.group_limit,e.file_bytes,e.storage_bytes,
      e.task_creation,e.recurring_meetings,e.integration_api
    from sectalk_private.st_v7_plan_entitlements e where e.plan=new.plan and e.version<new.version
    order by e.version desc limit 1;
  if not found then raise exception 'Base plan entitlement snapshot unavailable'; end if;
  return new;
end $$;
create trigger st_v7_inherit_plan_entitlements after insert on sectalk_private.st_v6_plan_versions
  for each row execute function sectalk_private.st_v7_inherit_plan_entitlements();

create function public.st_v7_publish_plan_entitlements(p_plan text,p_title text,p_description text,p_visible boolean,
  p_active_from timestamptz,p_prices jsonb,p_workspace_limit integer,p_seat_limit integer,p_group_limit integer,
  p_file_bytes integer,p_storage_bytes bigint,p_task_creation boolean,p_recurring_meetings boolean,p_integration_api boolean
) returns integer language plpgsql security definer set search_path='' as $$
declare next_version integer;
begin
  next_version:=public.st_v6_publish_plan(p_plan,p_title,p_description,p_visible,p_active_from,p_prices);
  update sectalk_private.st_v7_plan_entitlements e set workspace_limit=p_workspace_limit,seat_limit=p_seat_limit,
    group_limit=p_group_limit,file_bytes=p_file_bytes,storage_bytes=p_storage_bytes,task_creation=p_task_creation,
    recurring_meetings=p_recurring_meetings,integration_api=p_integration_api
  where e.plan=p_plan and e.version=next_version;
  return next_version;
end $$;

create function sectalk_private.st_v7_account_entitlements(p_actor uuid)
returns sectalk_private.st_v7_plan_entitlements language sql stable security definer set search_path='' as $$
  select e.* from sectalk_private.st_v7_plan_entitlements e where (e.plan,e.version)=(
    select coalesce(s.plan,'free'),coalesce(s.catalog_version,f.version)
    from sectalk_private.st_v6_active_plans() f
    left join public.st_v2_subscriptions s on s.user_id=p_actor and (
      (s.status in ('active','trialing') and s.period_end>now()) or
      (s.status='past_due' and s.period_end+interval '3 days'>now()))
    where f.plan='free'
  );
$$;

create or replace function sectalk_private.st_v2_effective_plan(p_user uuid)
returns text language sql stable security definer set search_path='' as $$
  select coalesce((sectalk_private.st_v7_account_entitlements(p_user)).plan,'free');
$$;

create function sectalk_private.st_v7_workspace_entitlements(p_workspace uuid)
returns sectalk_private.st_v7_plan_entitlements language sql stable security definer set search_path='' as $$
  select e.* from public.st_v2_workspaces w
    cross join lateral sectalk_private.st_v7_account_entitlements(w.owner) e where w.id=p_workspace;
$$;
revoke all on function sectalk_private.st_v7_workspace_entitlements(uuid) from public,anon,authenticated,service_role;

create function public.st_v7_my_entitlements()
returns jsonb language sql stable security definer set search_path='' as $$
  select to_jsonb(e) from sectalk_private.st_v7_account_entitlements((select auth.uid())) e
    where (select auth.uid()) is not null;
$$;

create function public.st_v7_public_plan_entitlements()
returns table(plan text,version integer,title text,description text,prices jsonb,entitlements jsonb)
language sql stable security definer set search_path='' as $$
  select v.plan,v.version,v.title,v.description,v.prices,to_jsonb(e)
  from public.st_v6_plan_catalog() v join sectalk_private.st_v7_plan_entitlements e
    on (e.plan,e.version)=(v.plan,v.version)
  order by array_position(array['free','basic','professional','business','enterprise'],v.plan);
$$;

create or replace function sectalk_private.st_v6_attachment_entitlement(p_actor uuid)
returns table(plan text,max_file_bytes integer,max_storage_bytes bigint)
language sql stable set search_path='' as $$
  select e.plan,least(e.file_bytes,p.max_file_bytes),least(e.storage_bytes,p.max_storage_bytes)
  from sectalk_private.st_v7_account_entitlements(p_actor) e
  left join sectalk_private.st_v6_attachment_policy p on p.account_id=p_actor;
$$;

create or replace function sectalk_private.st_v6_workspace_feature_entitled(p_feature text,p_workspace uuid)
returns boolean language sql stable set search_path='' as $$
  select case when p_workspace is null then p_feature in ('task_creation','recurring_meetings')
    else exists(select 1 from public.st_v2_workspaces w
      cross join lateral sectalk_private.st_v7_workspace_entitlements(w.id) e
      where w.id=p_workspace and (case p_feature
        when 'integration_api' then coalesce(sectalk_private.st_v2_active(w.owner),false) and e.integration_api
        when 'task_creation' then e.task_creation when 'recurring_meetings' then e.recurring_meetings else false end)) end;
$$;

create or replace function public.st_v2_create_workspace(p_name text)
returns uuid language plpgsql security definer set search_path='' as $$
declare me uuid:=auth.uid(); w uuid; cap integer;
begin
  perform sectalk_private.limit_action('v2_workspace',4);
  if not sectalk_private.st_v2_active(me) then raise exception 'Workspace access is restricted'; end if;
  perform id from public.st_profiles where id=me for update;
  if not found then raise exception 'Create a profile first'; end if;
  cap:=coalesce((sectalk_private.st_v7_account_entitlements(me)).workspace_limit,0);
  if (select count(*) from public.st_v2_workspaces where owner=me)>=cap then
    raise exception 'Your plan’s workspace limit has been reached';
  end if;
  insert into public.st_v2_workspaces(name,owner) values(btrim(p_name),me) returning id into w;
  insert into public.st_v2_members(workspace_id,user_id,role) values(w,me,'owner');
  insert into public.st_v2_channels(workspace_id,name) values(w,'general');
  insert into public.st_v2_workspace_audit(workspace_id,actor,event) values(w,me,'workspace.created');
  return w;
end $$;

create or replace function public.st_v2_reply_invite(p_invite uuid,p_accept boolean)
returns uuid language plpgsql security definer set search_path='' as $$
declare me uuid:=auth.uid(); invitation public.st_v2_invites; workspace_owner uuid; cap integer;
begin
  perform sectalk_private.limit_action('v2_reply_invite',10);
  select * into invitation from public.st_v2_invites where id=p_invite and invitee=me and status='pending';
  if not found then raise exception 'Workspace invitation unavailable'; end if;
  select owner into workspace_owner from public.st_v2_workspaces where id=invitation.workspace_id for update;
  select * into invitation from public.st_v2_invites where id=p_invite and invitee=me and status='pending' for update;
  if not found then raise exception 'Workspace invitation unavailable'; end if;
  if exists(select 1 from public.st_v2_members
    where workspace_id=invitation.workspace_id and user_id=me and suspended_at is not null)
  then raise exception 'Workspace invitation unavailable'; end if;
  if not p_accept then
    update public.st_v2_invites set status='declined' where id=p_invite;
    return null;
  end if;
  if not coalesce(sectalk_private.st_v2_role(invitation.workspace_id,invitation.created_by) in ('owner','admin'),false)
    or not sectalk_private.open_pair(me,invitation.created_by) then raise exception 'Workspace invitation unavailable'; end if;
  cap:=coalesce((sectalk_private.st_v7_workspace_entitlements(invitation.workspace_id)).seat_limit,0);
  if (select count(*) from public.st_v2_members where workspace_id=invitation.workspace_id)>=cap then
    raise exception 'This workspace has reached its member limit';
  end if;
  insert into public.st_v2_members(workspace_id,user_id) values(invitation.workspace_id,me) on conflict do nothing;
  update public.st_v2_invites set status='accepted' where id=p_invite;
  insert into public.st_v2_workspace_audit(workspace_id,actor,event,target) values(invitation.workspace_id,me,'member.joined',me);
  return invitation.workspace_id;
end $$;

create or replace function sectalk_private.st_v6_workspace_link_accept(p_token text)
returns uuid language plpgsql security definer set search_path='' as $$
declare actor uuid:=auth.uid();
declare token_digest bytea;
declare invitation sectalk_private.st_v6_workspace_link_invites;
declare workspace uuid;
declare owner_id uuid;
declare verified_email text;
declare cap integer;
begin
  if not sectalk_private.st_v2_active(actor) or p_token is null or p_token!~'^[0-9a-f]{48}$'
  then raise exception 'Invitation unavailable'; end if;
  perform sectalk_private.limit_action('v6_invite_link_accept',15);
  token_digest:=sha256(convert_to(p_token,'UTF8'));
  select workspace_id into workspace from sectalk_private.st_v6_workspace_link_invites where token_hash=token_digest;
  select owner into owner_id from public.st_v2_workspaces where id=workspace for update;
  if not found then raise exception 'Invitation unavailable'; end if;
  select * into invitation from sectalk_private.st_v6_workspace_link_invites where token_hash=token_digest for update;
  select lower(u.email) into verified_email from auth.users u where u.id=actor and u.email_confirmed_at is not null;
  if not found or verified_email is distinct from invitation.email or invitation.consumed_at is not null
    or invitation.expires_at<=clock_timestamp()
    or not coalesce(sectalk_private.st_v2_role(workspace,invitation.issued_by) in ('owner','admin'),false)
    or not sectalk_private.st_v2_active(invitation.issued_by)
    or not sectalk_private.st_v6_link_domain_allowed(workspace,verified_email)
    or not sectalk_private.open_pair(actor,invitation.issued_by)
  then raise exception 'Invitation unavailable'; end if;
  if exists(select 1 from public.st_v2_members where workspace_id=workspace and user_id=actor)
    then raise exception 'Invitation unavailable'; end if;
  cap:=coalesce((sectalk_private.st_v7_workspace_entitlements(workspace)).seat_limit,0);
  if (select count(*) from public.st_v2_members where workspace_id=workspace)>=cap
    then raise exception 'Workspace has no available seats'; end if;
  insert into public.st_v2_members(workspace_id,user_id) values(workspace,actor);
  update sectalk_private.st_v6_workspace_link_invites set consumed_at=clock_timestamp() where token_hash=token_digest;
  insert into public.st_v2_workspace_audit(workspace_id,actor,event,target)
    values(workspace,actor,'workspace.link_joined',actor);
  return workspace;
end
$$;

create or replace function public.st_v6_workspace_admin_overview(p_workspace uuid)
returns jsonb language plpgsql stable security definer set search_path='' as $$
declare workspace_owner uuid;
declare plan text;
declare seat_limit integer;
declare occupied integer;
declare enabled integer;
declare pending_invites integer;
declare expiring_links integer;
declare access_requests integer;
declare contributors integer;
declare since timestamptz:=now()-interval '168 hours';
begin
  if not coalesce(sectalk_private.st_v2_role(p_workspace,auth.uid()) in ('owner','admin'),false)
    or sectalk_private.st_v2_active(auth.uid()) is not true
  then raise exception 'Workspace overview is unavailable' using errcode='42501'; end if;
  select w.owner into workspace_owner from public.st_v2_workspaces w where w.id=p_workspace;
  select e.plan,e.seat_limit into plan,seat_limit from sectalk_private.st_v7_workspace_entitlements(p_workspace) e;
  select count(*),count(*) filter(where m.suspended_at is null) into occupied,enabled
  from public.st_v2_members m where m.workspace_id=p_workspace;

  select (select count(*) from public.st_v2_invites i where i.workspace_id=p_workspace and i.status='pending')
      + count(*),
    count(*) filter(where i.expires_at<=now()+interval '24 hours')
  into pending_invites,expiring_links
  from sectalk_private.st_v6_workspace_link_invites i
  where i.workspace_id=p_workspace and i.consumed_at is null and i.expires_at>now();
  select count(*) into access_requests
  from public.st_v6_room_entries e join public.st_v6_rooms r on r.id=e.room_id
  where r.workspace_id=p_workspace and not r.archived and e.kind='request' and e.expires_at>now()
    and sectalk_private.st_v6_room_role(r.id) in ('owner','moderator');

  if enabled>=5 then
    select count(*) into contributors from public.st_v2_members m
    where m.workspace_id=p_workspace and m.suspended_at is null and (
      exists(select 1 from public.st_v6_room_posts p join public.st_v6_rooms r on r.id=p.room_id
        where r.workspace_id=p_workspace and r.kind in ('public','announcement','broadcast')
          and not r.archived and p.sender=m.user_id and p.removed_at is null and p.created_at>=since)
      or exists(select 1 from public.st_v2_posts p join public.st_v2_channels c on c.id=p.channel_id
        where c.workspace_id=p_workspace and c.visibility='workspace' and not c.archived
          and p.sender=m.user_id and p.created_at>=since)
    );
    if contributors<3 then contributors:=null; end if;
  end if;
  return jsonb_build_object('plan',plan,'seat_limit',seat_limit,'occupied',occupied,'active',enabled,
    'pending_invites',pending_invites,'expiring_links',expiring_links,'access_requests',access_requests,
    'contributors',contributors,'activity_window_hours',168);
end $$;

create or replace function public.st_group_chat(p_action text,p_group uuid default null,p_data jsonb default '{}')
returns jsonb language plpgsql security definer set search_path='' as $$
declare me uuid:=auth.uid(); local_device sectalk_private.st_v7_devices; target sectalk_private.st_group_chats;
  roster uuid[]; manifests jsonb; sealed_keys jsonb; next_epoch integer; plan_cap integer; cap integer;
  roster_size integer; result jsonb; current_members boolean;
begin
  select d.* into local_device from sectalk_private.st_v7_device_sessions s
    join sectalk_private.st_v7_devices d on (d.owner,d.id)=(s.owner,s.device_id)
    where s.owner=me and s.session_id::text=auth.jwt()->>'session_id' and d.state in ('trusted','managed');
  if local_device.id is null or not coalesce(sectalk_private.st_v7_manage_sessions(),false) then
    raise exception using errcode='42501',message='An approved browser device is required';
  end if;
  if p_action='list' then
    return coalesce((select jsonb_agg(to_jsonb(x) order by x.name,x.id) from (
      select g.* from sectalk_private.st_group_chats g join sectalk_private.st_group_members m on m.group_id=g.id
      where m.actor=me order by g.name,g.id limit 100) x),'[]');
  end if;
  if p_group is null then raise exception using errcode='22023',message='A group is required'; end if;
  select g.* into target from sectalk_private.st_group_chats g where g.id=p_group for update;
  if p_action in ('preview','rotate') then
    if target.id is not null and target.owner<>me then raise exception using errcode='42501',message='Group unavailable'; end if;
    if (p_data->>'previous_epoch')::integer is distinct from coalesce(target.epoch,0) then
      raise exception using errcode='40001',message='Group roster changed. Reopen the member editor.';
    end if;
    if target.id is null and (select count(*) from sectalk_private.st_group_chats g where g.owner=me)>=100 then
      raise exception using errcode='22023',message='This account has reached its group limit';
    end if;
    plan_cap:=coalesce((sectalk_private.st_v7_account_entitlements(me)).group_limit,0);
    cap:=(p_data->>'cap')::integer;
    if cap is null or cap<2 or cap>32 then raise exception using errcode='22023',message='Invalid member limit'; end if;
    if jsonb_typeof(p_data->'members') is distinct from 'array' or jsonb_array_length(p_data->'members')>32 then
      raise exception using errcode='22023',message='Invalid group roster';
    end if;
    select array_agg(distinct id order by id) into roster from (
      select me id union all select value::uuid from jsonb_array_elements_text(p_data->'members')) ids;
    roster_size:=cardinality(roster);
    if roster_size>least(plan_cap,cap) or (target.id is null and roster_size<2)
      or exists(select 1 from unnest(roster) peer where peer is null or (peer<>me
      and (not sectalk_private.open_pair(me,peer) or not exists(select 1 from public.st_chats c
        where (c.member_a,c.member_b)=(least(me,peer),greatest(me,peer)) and c.status='accepted')))) then
      raise exception using errcode='22023',message='Group roster exceeds the member limit or includes an unavailable contact';
    end if;
    select coalesce(jsonb_agg(jsonb_build_object('owner_id',d.owner,'device',d.id,'signing_key',d.signing_key,
      'agreement_key',d.agreement_key,'bundle_signature',d.bundle_signature) order by d.id),'[]')
      into manifests from sectalk_private.st_v7_devices d where d.owner=any(roster) and d.state in ('trusted','managed');
    if jsonb_array_length(manifests)>128 or (select count(distinct d->>'owner_id') from jsonb_array_elements(manifests) d)<>roster_size then
      raise exception using errcode='22023',message='Each member needs an approved device and the group supports up to 128 devices';
    end if;
    next_epoch:=coalesce(target.epoch,0)+1;
    if p_action='preview' then
      return jsonb_build_object('device',local_device.id,'epoch',next_epoch,'devices',manifests,'plan_cap',plan_cap);
    end if;
    perform sectalk_private.limit_action('group_chat_rotation',20);
    sealed_keys:=p_data->'envelopes';
    if (p_data->>'epoch')::integer is distinct from next_epoch or
      jsonb_typeof(sealed_keys) is distinct from 'object' or
      (select count(*) from jsonb_object_keys(sealed_keys))<>jsonb_array_length(manifests) or
      exists(select 1 from jsonb_array_elements(manifests) d where not (sealed_keys ? (d->>'device')))
      then raise exception using errcode='40001',message='Group roster or device list changed. Try again.'; end if;
    insert into sectalk_private.st_group_chats as g(id,owner,name,epoch,member_cap)
      values(p_group,me,btrim(p_data->>'name'),next_epoch,cap)
      on conflict(id) do update set name=excluded.name,epoch=excluded.epoch,member_cap=excluded.member_cap
      where g.owner=me and g.epoch=next_epoch-1;
    if not found then raise exception using errcode='40001',message='Group roster changed. Try again.'; end if;
    -- Removed accounts lose old envelopes too, including after readmission.
    delete from sectalk_private.st_group_envelopes e using sectalk_private.st_v7_devices d
      where e.group_id=p_group and e.device=d.id and not (d.owner=any(roster));
    delete from sectalk_private.st_group_members m where m.group_id=p_group and not (m.actor=any(roster));
    insert into sectalk_private.st_group_members(group_id,actor) select p_group,unnest(roster) on conflict do nothing;
    insert into sectalk_private.st_group_envelopes(group_id,epoch,device,sealed,ephemeral)
      select p_group,next_epoch,k.key::uuid,k.value->>'sealed',k.value->>'ephemeral' from jsonb_each(sealed_keys) k;
    return jsonb_build_object('epoch',next_epoch);
  end if;
  if target.id is null or not exists(select 1 from sectalk_private.st_group_members m where m.group_id=p_group and m.actor=me) then
    raise exception using errcode='42501',message='Group unavailable';
  end if;
  if p_action='send' then
    perform sectalk_private.limit_action('group_chat_message',60);
    -- Stop sends when a covered device is revoked. A fresh owner rotation drops it before more ciphertext is accepted.
    select not exists(select 1 from sectalk_private.st_group_envelopes e left join sectalk_private.st_v7_devices d on d.id=e.device
      where e.group_id=p_group and e.epoch=target.epoch and (d.id is null or d.state not in ('trusted','managed'))) into current_members;
    if (p_data->>'epoch')::integer is distinct from target.epoch or not current_members or not exists(
      select 1 from sectalk_private.st_group_envelopes e where e.group_id=p_group and e.epoch=target.epoch
        and e.device=local_device.id)
      then raise exception using errcode='40001',message='Group keys changed. Ask the owner to refresh encryption.'; end if;
    insert into sectalk_private.st_group_messages(group_id,id,epoch,actor,device,signing,payload,signature)
      values(p_group,(p_data->>'id')::uuid,target.epoch,me,local_device.id,local_device.signing_key,p_data->>'payload',p_data->>'signature');
    return '{}'::jsonb;
  end if;
  if p_action='read' then
    with newest as (
      select m.* from sectalk_private.st_group_messages m where m.group_id=p_group
        and exists(select 1 from sectalk_private.st_group_envelopes e where e.group_id=p_group and e.epoch=m.epoch and e.device=local_device.id)
      order by m.sent desc,m.id desc limit 50)
    select jsonb_build_object('group',to_jsonb(target),'device',local_device.id,
      'members',(select jsonb_agg(jsonb_build_object('id',m.actor,'name',p.name) order by m.actor)
        from sectalk_private.st_group_members m left join public.st_profiles p on p.id=m.actor where m.group_id=p_group),
      'envelopes',coalesce((select jsonb_agg(to_jsonb(e)-'group_id'-'device') from sectalk_private.st_group_envelopes e
        where e.group_id=p_group and e.device=local_device.id and (e.epoch=target.epoch or e.epoch in (select x.epoch from newest x))),'[]'),
      'messages',coalesce((select jsonb_agg(to_jsonb(x)-'group_id' order by x.sent,x.id) from newest x),'[]'))
      into result from (select 1) placeholder;
    return result;
  end if;
  raise exception using errcode='22023',message='Unknown group action';
end $$;

create or replace function public.st_v6_integration_access(p_workspace uuid)
returns text language sql stable security definer set search_path='' as $$
  select case
    when sectalk_private.st_v2_role(p_workspace,auth.uid()) is distinct from 'owner'
      or not coalesce(sectalk_private.st_v2_active(auth.uid()),false) then 'none'
    when not sectalk_private.st_v6_workspace_feature_entitled('integration_api',p_workspace) then 'upgrade'
    when sectalk_private.st_v6_holds_access(p_workspace)='verified'
      and public.st_v7_sensitive_action_status('integration_key')='verified' then 'verified'
    else 'mfa'
  end
$$;

create or replace function public.st_v6_integration_read(p_digest text,p_resource text,p_after uuid,p_limit integer)
returns jsonb language plpgsql security definer set search_path='' as $$
declare api_key sectalk_private.st_v6_integration_keys; tenant public.st_v2_workspaces; result jsonb; used integer;
begin
  if (p_digest ~ '^[a-f0-9]{64}$') is not true or (p_resource in ('workspace','rooms')) is not true
    or (p_limit between 1 and 100) is not true then
    raise exception using errcode='22023',message='Invalid API request';
  end if;
  select * into api_key from sectalk_private.st_v6_integration_keys k where k.digest=decode(p_digest,'hex')
    and k.revoked_at is null and k.expires_at>now() for share;
  if not found then raise exception using errcode='PT401',message='Invalid API key'; end if;
  select * into tenant from public.st_v2_workspaces w where w.id=api_key.workspace_id;
  if not found or tenant.owner is distinct from api_key.created_by or sectalk_private.st_v2_active(tenant.owner) is not true
    or not sectalk_private.st_v6_workspace_feature_entitled('integration_api',tenant.id)
    or not sectalk_private.st_v6_feature_allowed('integration_api',tenant.owner,tenant.id)
    or not (p_resource||':read'=any(api_key.scopes)) then
    raise exception using errcode='42501',message='API key scope is unavailable';
  end if;
  insert into sectalk_private.st_v6_api_rate as budget(key_id,minute,requests)
    values(api_key.id,date_trunc('minute',statement_timestamp()),1)
    on conflict(key_id,minute) do update set requests=budget.requests+1 where budget.requests<120
    returning requests into used;
  if used is null then raise exception using errcode='PT429',message='API request limit reached'; end if;
  if p_resource='workspace' then
    return jsonb_build_object('data',jsonb_build_object('id',tenant.id,'name',tenant.name,'created_at',tenant.created_at));
  end if;
  select jsonb_build_object('data',coalesce(jsonb_agg(jsonb_build_object('id',page.id,'name',page.name,'created_at',page.created_at)
    order by page.id) filter(where page.position<=p_limit),'[]'::jsonb),
    'next_cursor',case when count(*)>p_limit then (array_agg(page.id order by page.id))[p_limit] end)
  into result from (
    select r.id,r.name,r.created_at,row_number() over(order by r.id) position from public.st_v6_rooms r
    where r.workspace_id=tenant.id and r.kind='public' and r.classification in ('public','internal') and not r.archived
      and (p_after is null or r.id>p_after)
    order by r.id limit p_limit+1
  ) page;
  return result;
end $$;

create or replace function sectalk_private.st_v6_webhook_entitled(e sectalk_private.st_v6_webhooks)
returns boolean language sql stable set search_path='' as $$
  select e.revoked_at is null and not sectalk_private.st_v7_domain_blocked(sectalk_private.st_v7_webhook_host(e.destination))
    and exists(select 1 from public.st_v2_workspaces w
      where (w.id,w.owner)=(e.workspace_id,e.owner) and sectalk_private.st_v2_active(w.owner)
        and sectalk_private.st_v6_workspace_feature_entitled('integration_api',w.id));
$$;

revoke all on function sectalk_private.st_v7_inherit_plan_entitlements(),sectalk_private.st_v7_account_entitlements(uuid),
  public.st_v7_my_entitlements(),public.st_v7_public_plan_entitlements(),
  public.st_v7_publish_plan_entitlements(text,text,text,boolean,timestamptz,jsonb,integer,integer,integer,integer,bigint,boolean,boolean,boolean)
  from public,anon,authenticated,service_role;
grant execute on function public.st_v7_my_entitlements() to authenticated;
grant execute on function public.st_v7_public_plan_entitlements() to anon,authenticated;
grant execute on function public.st_v7_publish_plan_entitlements(text,text,text,boolean,timestamptz,jsonb,integer,integer,integer,integer,bigint,boolean,boolean,boolean)
  to service_role;

commit;
