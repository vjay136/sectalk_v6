begin;

create table sectalk_private.st_v8_workspace_room_structure_sso (
  workspace uuid primary key references public.st_v2_workspaces on delete cascade,
  protocol text not null check(protocol in ('saml','oidc')),
  provider text not null
);
alter table sectalk_private.st_v8_workspace_room_structure_sso enable row level security;
revoke all on table sectalk_private.st_v8_workspace_room_structure_sso from public,anon,authenticated,service_role;

create function sectalk_private.st_v8_room_structure_sso_allows(p_workspace uuid)
returns boolean language sql stable security definer set search_path='' as $$
  select not exists(select 1 from sectalk_private.st_v8_workspace_room_structure_sso p
    where p.workspace=p_workspace
      and sectalk_private.st_v8_workspace_session_receipt(p.workspace,p.protocol,p.provider) is not true);
$$;

create function sectalk_private.st_v8_room_structure_room_allows(p_room uuid)
returns boolean language sql stable security definer set search_path='' as $$
  select coalesce((select sectalk_private.st_v8_room_structure_sso_allows(r.workspace_id)
    from public.st_v6_rooms r where r.id=p_room),false);
$$;

-- Serialize normal directory changes with the policy and provider settings.
-- Preserve the existing failure path for callers outside the workspace.
create function sectalk_private.st_v8_room_structure_require(p_room uuid)
returns void language plpgsql set search_path='' as $$
declare space uuid;
begin
  select r.workspace_id into space from public.st_v6_rooms r where r.id=p_room;
  if space is not null and sectalk_private.st_v2_active(auth.uid())
    and sectalk_private.st_v2_role(space,auth.uid()) is not null then
    perform 1 from public.st_v2_workspaces w where w.id=space for key share;
    if not sectalk_private.st_v8_room_structure_sso_allows(space) then
      raise exception 'Sign in through your workspace provider to manage or join rooms' using errcode='42501';
    end if;
  end if;
end $$;

revoke all on function sectalk_private.st_v8_room_structure_sso_allows(uuid),
  sectalk_private.st_v8_room_structure_room_allows(uuid),sectalk_private.st_v8_room_structure_require(uuid)
  from public,anon,authenticated,service_role;
grant execute on function sectalk_private.st_v8_room_structure_sso_allows(uuid),
  sectalk_private.st_v8_room_structure_room_allows(uuid) to authenticated;

create function public.st_v8_workspace_room_structure_requires_sso(p_workspace uuid)
returns boolean language sql stable security definer set search_path='' as $$
  select sectalk_private.st_v2_active(auth.uid())
    and sectalk_private.st_v2_role(p_workspace,auth.uid()) is not null
    and not sectalk_private.st_v8_room_structure_sso_allows(p_workspace);
$$;

create function public.st_v8_workspace_room_structure_policy(p_workspace uuid,p_require boolean default null)
returns jsonb language plpgsql security definer set search_path='' as $$
declare access text:=sectalk_private.st_v7_file_egress_operator(p_workspace); setup sectalk_private.st_v7_workspace_sso;
begin
  if access is distinct from 'verified' then return jsonb_build_object('access',access); end if;
  if p_require is not null then
    perform sectalk_private.limit_action('v8_room_structure_sso_policy',5);
    perform 1 from public.st_v2_workspaces w where w.id=p_workspace for update;
    if not found or sectalk_private.st_v7_file_egress_operator(p_workspace) is distinct from 'verified' then
      raise insufficient_privilege;
    end if;
    if p_require then
      select * into setup from sectalk_private.st_v7_workspace_sso c where c.workspace=p_workspace;
      if not found or sectalk_private.st_v7_workspace_sso_provider(p_workspace,setup.domain,setup.protocol)
        is distinct from setup.provider or not exists(
          select 1 from sectalk_private.st_v7_workspace_sso_sessions r join auth.sessions s on (s.id,s.user_id)=(r.session,r.principal)
          where r.workspace=p_workspace and (r.protocol,r.provider)=(setup.protocol,setup.provider)
            and sectalk_private.st_v2_active(r.principal) and sectalk_private.st_v2_role(p_workspace,r.principal) is not null
            and sectalk_private.st_v7_session_deadline(s.created_at,s.refreshed_at,s.not_after)>statement_timestamp()
        ) then return '{"access":"verified","error":"verified_provider_session_required"}'; end if;
      insert into sectalk_private.st_v8_workspace_room_structure_sso(workspace,protocol,provider)
        values(p_workspace,setup.protocol,setup.provider)
        on conflict(workspace) do update set protocol=excluded.protocol,provider=excluded.provider;
    else
      delete from sectalk_private.st_v8_workspace_room_structure_sso p where p.workspace=p_workspace;
    end if;
    if found then
      insert into public.st_v2_workspace_audit(workspace_id,actor,event)
        values(p_workspace,auth.uid(),case when p_require then 'workspace.room_structure_sso_required'
          else 'workspace.room_structure_sso_recovered' end);
    end if;
  end if;
  return jsonb_build_object('access','verified',
    'required',exists(select 1 from sectalk_private.st_v8_workspace_room_structure_sso p where p.workspace=p_workspace));
end $$;

revoke all on function public.st_v8_workspace_room_structure_requires_sso(uuid),
  public.st_v8_workspace_room_structure_policy(uuid,boolean) from public,anon,authenticated,service_role;
grant execute on function public.st_v8_workspace_room_structure_requires_sso(uuid),
  public.st_v8_workspace_room_structure_policy(uuid,boolean) to authenticated;

create policy st_v8_room_structure_directory on public.st_v6_rooms as restrictive for select to authenticated
  using(sectalk_private.st_v8_room_structure_sso_allows(workspace_id));
create policy st_v8_room_structure_roster on public.st_v6_room_members as restrictive for select to authenticated
  using(sectalk_private.st_v8_room_structure_room_allows(room_id));
create policy st_v8_room_structure_entries on public.st_v6_room_entries as restrictive for select to authenticated
  using(sectalk_private.st_v8_room_structure_room_allows(room_id));
create policy st_v8_room_structure_bans on public.st_v6_room_bans as restrictive for select to authenticated
  using(sectalk_private.st_v8_room_structure_room_allows(room_id));
create policy st_v8_room_structure_timeouts on public.st_v6_room_timeouts as restrictive for select to authenticated
  using(sectalk_private.st_v8_room_structure_room_allows(room_id));
create policy st_v8_room_structure_audit on public.st_v6_room_audit as restrictive for select to authenticated
  using(sectalk_private.st_v8_room_structure_room_allows(room_id));

create or replace function public.st_v6_room_my_role(p_room uuid)
returns text language sql stable security definer set search_path='' as $$
  select case when sectalk_private.st_v8_room_structure_room_allows(p_room)
    then sectalk_private.st_v6_room_role(p_room) end;
$$;

create or replace function sectalk_private.st_v6_room_management_audit(p_room uuid)
returns setof public.st_v6_room_audit language sql stable security definer set search_path='' as $$
  select a.* from public.st_v6_room_audit a where a.room_id=p_room
    and sectalk_private.st_v6_room_workspace_manager(p_room)
    and sectalk_private.st_v8_room_structure_room_allows(p_room)
    and (a.action like 'membership.%' or a.action in ('room.created','room.visibility','room.archive','room.restore')
      or sectalk_private.st_v6_room_role(p_room) in ('owner','moderator'))
  order by a.id desc limit 50
$$;

create or replace function public.st_v6_room_create(p_id uuid,p_workspace uuid,p_name text,p_kind text,p_template text)
returns uuid language plpgsql security definer set search_path='' as $$
declare
  actor uuid:=auth.uid();
  allowed_kinds text[];
  starter text;
  starter_id uuid;
  initial_slow_seconds integer:=0;
begin
  perform sectalk_private.limit_action('v6_room_create',8);
  if not coalesce(sectalk_private.st_v2_role(p_workspace,actor) in ('owner','admin'),false)
    or not sectalk_private.st_v2_active(actor) then raise exception 'Room unavailable'; end if;
  perform id from public.st_v2_workspaces where id=p_workspace for update;
  if not sectalk_private.st_v8_room_structure_sso_allows(p_workspace) then
    raise exception 'Sign in through your workspace provider to create rooms' using errcode='42501';
  end if;
  if exists(select 1 from public.st_v6_rooms where id=p_id and workspace_id=p_workspace and creator=actor
      and name=btrim(p_name) and kind=p_kind and template=p_template) then return p_id; end if;

  case p_template
    when 'blank' then allowed_kinds:=array['public','private','admin','announcement','broadcast'];
    when 'class' then
      allowed_kinds:=array['private'];
      initial_slow_seconds:=15;
      starter:='Class starter'||chr(10)||'Post the syllabus or learning goals, keep each lesson in a separate thread, and share assignments in Tasks. Add learners only after confirming their workspace accounts.';
    when 'incident' then
      allowed_kinds:=array['admin'];
      starter:='Incident starter'||chr(10)||'Record the incident lead, status, scope, and next update time. Keep a timestamped timeline and assign authorized follow-up in Tasks. Keep credentials and personal data out of room messages.';
    when 'family' then
      allowed_kinds:=array['private'];
      starter:='Family starter'||chr(10)||'Agree on shared plans, use threads for individual topics, and invite only the workspace members you want here. Ask before posting someone else’s photo or personal details.';
    when 'project' then
      allowed_kinds:=array['public','private'];
      starter:='Project starter'||chr(10)||'Define the goal, owner, and next milestone. Use Tasks for assignments and due dates, and put decisions or blockers in their own threads.';
    else raise exception 'Room template unavailable';
  end case;
  if p_kind is null or not (p_kind=any(allowed_kinds))
    then raise exception 'Choose a room type allowed by this template'; end if;
  if (select count(*) from public.st_v6_rooms where workspace_id=p_workspace)>=100 then raise exception 'Workspace room limit reached'; end if;

  insert into public.st_v6_rooms(id,workspace_id,name,kind,template,creator,slow_seconds)
    values(p_id,p_workspace,btrim(p_name),p_kind,p_template,actor,initial_slow_seconds);
  if p_kind<>'admin' then
    insert into public.st_v6_room_members(room_id,user_id,role) values(p_id,actor,'owner');
  end if;
  insert into public.st_v6_room_audit(room_id,actor,action) values(p_id,actor,'room.created');
  if starter is not null then
    starter_id:=gen_random_uuid();
    insert into public.st_v6_room_posts(room_id,id,sender,body,kind)
      values(p_id,starter_id,actor,starter,'announcement');
    insert into public.st_v6_room_pins(room_id,post_id) values(p_id,starter_id);
    insert into public.st_v6_room_audit(room_id,actor,action,target)
      values(p_id,actor,'room.template_applied',starter_id);
  end if;
  return p_id;
end $$;

create or replace function public.st_v6_room_membership(p_room uuid,p_action text,p_target uuid default null,p_role text default 'member')
returns void language plpgsql security definer set search_path='' as $$
declare actor uuid:=auth.uid(); r public.st_v6_rooms; stage public.st_v6_room_entries; room_role text;
        target uuid:=coalesce(p_target,actor); target_role text;
begin
  perform sectalk_private.limit_action('v6_room_membership',30);
  perform sectalk_private.st_v8_room_structure_require(p_room);
  select * into r from public.st_v6_rooms where id=p_room for update;
  if not found or r.kind='admin' or r.archived or not sectalk_private.st_v2_active(actor)
    or sectalk_private.st_v2_role(r.workspace_id,actor) is null
    or exists(select 1 from public.st_v6_room_bans where room_id=p_room and user_id=actor)
    then raise exception 'Room unavailable'; end if;
  room_role:=sectalk_private.st_v6_room_role(p_room);
  select role into target_role from public.st_v6_room_members where room_id=p_room and user_id=target;
  select * into stage from public.st_v6_room_entries where room_id=p_room and user_id=target and expires_at>now();

  if p_action in ('join','request','accept','decline') and target=actor then
    if p_action='join' and r.kind in ('public','announcement','broadcast') then
      insert into public.st_v6_room_members(room_id,user_id,role)
        values(p_room,actor,case when r.kind='broadcast' then 'read_only' else 'member' end) on conflict do nothing;
    elsif p_action='request' and r.kind='private' and room_role is null then
      insert into public.st_v6_room_entries values(p_room,actor,'request','member',now()+interval '7 days')
        on conflict(room_id,user_id) do update set expires_at=excluded.expires_at
        where public.st_v6_room_entries.kind='request' or public.st_v6_room_entries.expires_at<=now();
    elsif p_action in ('accept','decline') and stage.kind='invite' then
      if p_action='accept' then
        insert into public.st_v6_room_members values(p_room,actor,stage.invited_role) on conflict do nothing;
      end if;
      delete from public.st_v6_room_entries where room_id=p_room and user_id=actor;
    else raise exception 'Room unavailable'; end if;
  elsif p_action in ('invite','approve','deny','role','remove','ban','unban','mute','timeout','unmute')
    and room_role in ('owner','moderator') and target<>actor and target_role is distinct from 'owner'
    and (target_role is distinct from 'moderator' or room_role='owner') then
    if p_action='role' and public.st_v7_sensitive_action_status('room_role')<>'verified' then
      raise exception 'Verify your current sign-in to change a room role' using errcode='42501';
    end if;
    if p_action in ('invite','approve','role') then
      if sectalk_private.st_v2_role(r.workspace_id,target) is null or not sectalk_private.st_v2_active(target)
        or exists(select 1 from public.st_v6_room_bans where room_id=p_room and user_id=target)
        or p_role is null or p_role not in ('member','guest','read_only','moderator')
        or (p_role='moderator' and (room_role<>'owner' or p_action<>'role')) then raise exception 'Room action unavailable'; end if;
      if p_action='invite' and target_role is null then
        insert into public.st_v6_room_entries values(p_room,target,'invite',p_role,now()+interval '7 days')
          on conflict(room_id,user_id) do update set kind='invite',invited_role=excluded.invited_role,expires_at=excluded.expires_at;
      elsif p_action='approve' and stage.kind='request' then
        insert into public.st_v6_room_members values(p_room,target,p_role) on conflict do nothing;
        delete from public.st_v6_room_entries where room_id=p_room and user_id=target;
      elsif p_action='role' and target_role is not null then
        update public.st_v6_room_members set role=p_role where room_id=p_room and user_id=target;
      else raise exception 'Room action unavailable'; end if;
    elsif p_action='deny' and stage.kind='request' then
      delete from public.st_v6_room_entries where room_id=p_room and user_id=target;
    elsif p_action in ('remove','ban') then
      if p_action='ban' then
        insert into public.st_v6_room_bans values(p_room,target) on conflict do nothing;
      end if;
      delete from public.st_v6_room_members where room_id=p_room and user_id=target;
      delete from public.st_v6_room_entries where room_id=p_room and user_id=target;
    elsif p_action='unban' then
      delete from public.st_v6_room_bans where room_id=p_room and user_id=target;
    elsif p_action in ('mute','timeout') and target_role is not null then
      insert into public.st_v6_room_timeouts values(p_room,target,case when p_action='mute' then 'infinity'::timestamptz else now()+interval '15 minutes' end)
        on conflict(room_id,user_id) do update set until_at=excluded.until_at;
    elsif p_action='unmute' then
      delete from public.st_v6_room_timeouts where room_id=p_room and user_id=target;
    else raise exception 'Room action unavailable'; end if;
  else raise exception 'Room action unavailable'; end if;
  insert into public.st_v6_room_audit(room_id,actor,action,target) values(p_room,actor,'membership.'||p_action,target);
end $$;

create or replace function sectalk_private.st_v6_manage_room(p_room uuid,p_action text,p_kind text,p_target uuid)
returns void language plpgsql security definer set search_path='' as $$
declare
  actor uuid:=auth.uid();
  room public.st_v6_rooms;
  audit_details jsonb:='{}'::jsonb;
  previous_owners jsonb;
begin
  if not sectalk_private.st_v6_room_workspace_manager(p_room) then
    raise exception 'Room management unavailable';
  end if;
  perform sectalk_private.limit_action('v6_manage_room',20);
  perform sectalk_private.st_v8_room_structure_require(p_room);
  select * into room from public.st_v6_rooms where id=p_room for update;
  if not found or not sectalk_private.st_v6_room_workspace_manager(p_room) then
    raise exception 'Room management unavailable';
  end if;

  case p_action
    when 'visibility' then
      if room.archived or room.kind not in ('public','private') or room.template not in ('blank','project')
        or p_kind is null or p_kind not in ('public','private') then
        raise exception 'Visibility is unavailable for this room';
      end if;
      if room.kind=p_kind then return; end if;
      update public.st_v6_rooms set kind=p_kind where id=p_room;
      audit_details:=jsonb_build_object('from',room.kind,'to',p_kind);
    when 'transfer_owner' then
      if public.st_v7_sensitive_action_status('room_role')<>'verified' then
        raise exception 'Verify your current sign-in to transfer ownership' using errcode='42501';
      end if;
      if room.archived or room.kind='admin' or not sectalk_private.st_v2_active(p_target)
        or sectalk_private.st_v2_role(room.workspace_id,p_target) is null
        or exists(select 1 from public.st_v6_room_bans where room_id=p_room and user_id=p_target)
        or not exists(select 1 from public.st_v6_room_members where room_id=p_room and user_id=p_target) then
        raise exception 'Choose an active room member as the new owner';
      end if;
      select coalesce(jsonb_agg(user_id order by user_id),'[]'::jsonb) into previous_owners
        from public.st_v6_room_members where room_id=p_room and role='owner';
      if previous_owners=jsonb_build_array(p_target) then return; end if;
      update public.st_v6_room_members set role='moderator'
        where room_id=p_room and role='owner' and user_id<>p_target;
      update public.st_v6_room_members set role='owner' where room_id=p_room and user_id=p_target;
      audit_details:=jsonb_build_object('previous_owners',previous_owners);
    when 'archive', 'restore' then
      if room.archived=(p_action='archive') then return; end if;
      update public.st_v6_rooms set archived=(p_action='archive') where id=p_room;
    else raise exception 'Room management unavailable';
  end case;

  insert into public.st_v6_room_audit(room_id,actor,action,target,details)
    values(p_room,actor,case when p_action='transfer_owner' then 'membership.transfer_owner' else 'room.'||p_action end,
      case when p_action='transfer_owner' then p_target end,audit_details);
end $$;

create or replace function public.st_v6_room_settings(p_room uuid,p_action text,p_post uuid default null,p_seconds integer default 0)
returns void language plpgsql security definer set search_path='' as $$
declare actor uuid:=auth.uid(); workspace_id_value uuid;
begin
  if p_action not in ('pin','unpin') then
    perform sectalk_private.st_v8_room_structure_require(p_room);
  end if;
  if coalesce(sectalk_private.st_v6_room_role(p_room,actor),'') in ('owner','moderator') then
    perform public.st_v7_builtin_room_settings(p_room,p_action,p_post,p_seconds);
    return;
  end if;
  select r.workspace_id into workspace_id_value from public.st_v6_rooms r where r.id=p_room;
  perform 1 from public.st_v2_workspaces where id=workspace_id_value for update;
  perform 1 from public.st_v6_rooms where id=p_room for update;
  if not found or not coalesce(('room.'||p_action)=any(public.st_v7_custom_room_access(p_room)),false)
    or sectalk_private.st_v7_workspace_payment_mode(workspace_id_value)->>'mode'='read_only' then
    raise exception using errcode='42501',message='Room settings unavailable';
  end if;
  perform sectalk_private.limit_action('v6_room_settings',20);
  if p_action in ('pin','unpin') then
    if p_action='pin' then
      if not exists(select 1 from public.st_v6_room_posts where room_id=p_room and id=p_post and parent_id is null and removed_at is null)
        then raise exception using errcode='42501',message='Message unavailable'; end if;
      insert into public.st_v6_room_pins(room_id,post_id) values(p_room,p_post) on conflict do nothing;
    else delete from public.st_v6_room_pins where room_id=p_room and post_id=p_post; end if;
  elsif p_action='slow' and p_seconds between 0 and 300 then
    update public.st_v6_rooms set slow_seconds=p_seconds where id=p_room;
  else raise exception using errcode='42501',message='Room settings unavailable'; end if;
  insert into public.st_v6_room_audit(room_id,actor,action,target) values(p_room,actor,'delegated.'||p_action,p_post);
end
$$;

create or replace function public.st_v6_set_room_role_overrides(p_room uuid,p_role text,p_rules jsonb)
returns void language plpgsql security definer set search_path='' as $$
declare actor uuid:=auth.uid();
declare member_role text;
begin
  perform sectalk_private.limit_action('v6_room_role_overrides',20);
  perform sectalk_private.st_v8_room_structure_require(p_room);
  perform 1 from public.st_v6_rooms r where r.id=p_room and not r.archived for no key update;
  if not found then raise exception 'Room permissions are unavailable.' using errcode='42501'; end if;
  member_role:=sectalk_private.st_v6_room_role(p_room,actor);
  if p_role is null or p_role not in ('owner','moderator','member') or member_role is null
    or not (member_role='owner' or (member_role='moderator' and p_role='member')) then
    raise exception 'You cannot change permissions for that room role.' using errcode='42501';
  end if;
  if public.st_v7_sensitive_action_status('room_role')<>'verified' then
    raise exception 'Verify your current sign-in to change role permissions' using errcode='42501';
  end if;
  if p_rules is null or jsonb_typeof(p_rules)<>'object' or exists(
    select 1 from jsonb_each(p_rules) rule where rule.key not in ('post','react','upload','mention_all','start_call')
      or rule.value not in ('"allow"'::jsonb,'"deny"'::jsonb)
  ) then raise exception 'Choose valid room permissions.' using errcode='22023'; end if;
  if p_rules='{}'::jsonb then
    delete from sectalk_private.st_v6_room_role_overrides r where r.room=p_room and r.role=p_role;
  else
    insert into sectalk_private.st_v6_room_role_overrides as current_rule(room,role,rules) values(p_room,p_role,p_rules)
      on conflict(room,role) do update set rules=excluded.rules where current_rule.rules is distinct from excluded.rules;
  end if;
  if found then
    insert into public.st_v6_room_audit(room_id,actor,action,details)
      values(p_room,actor,'room.role_permissions',jsonb_build_object('role',p_role,'rules',p_rules));
  end if;
end
$$;

create or replace function public.st_v6_set_room_classification(p_room uuid,p_classification text)
returns text language plpgsql security definer set search_path='' as $$
declare target public.st_v6_rooms;
declare resolved text;
begin
  perform sectalk_private.st_v8_room_structure_require(p_room);
  if p_classification is null or p_classification not in ('public','internal','confidential','restricted') then
    raise exception 'Choose a valid classification' using errcode='22023';
  end if;
  select * into target from public.st_v6_rooms where id=p_room;
  if not found or target.archived or not sectalk_private.st_v6_room_directory(p_room)
    or sectalk_private.st_v6_holds_access(target.workspace_id)<>'verified'
  then raise exception 'Verified workspace administration is required' using errcode='42501'; end if;
  perform sectalk_private.limit_action('v6_room_classification',20);
  select * into target from public.st_v6_rooms where id=p_room for update;
  if not found or target.archived or not sectalk_private.st_v6_room_directory(p_room)
    or sectalk_private.st_v6_holds_access(target.workspace_id)<>'verified'
  then raise exception 'Room classification is unavailable' using errcode='42501'; end if;
  if target.kind in ('admin','private') and p_classification in ('public','internal')
  then raise exception 'Private and admin rooms require Confidential or Restricted'; end if;
  if target.classification=p_classification then return target.classification; end if;
  update public.st_v6_rooms set classification=p_classification where id=p_room returning classification into resolved;
  insert into public.st_v6_room_audit(room_id,actor,action,details)
    values(p_room,auth.uid(),'room.classification_changed',jsonb_build_object(
      'from_classification',target.classification,'to_classification',resolved));
  return resolved;
end $$;

create or replace function public.st_v6_set_room_forwarding(p_room uuid,p_allowed boolean)
returns void language plpgsql security definer set search_path='' as $$
declare actor uuid:=auth.uid();
begin
  perform sectalk_private.st_v8_room_structure_require(p_room);
  perform sectalk_private.limit_action('v6_room_settings',20);
  if p_allowed is null or not coalesce(sectalk_private.st_v6_room_role(p_room) in ('owner','moderator'),false)
    then raise exception 'Room settings unavailable'; end if;
  update public.st_v6_rooms set forwarding_allowed=p_allowed where id=p_room and kind='public' and not archived
    and sectalk_private.st_v6_room_role(p_room) in ('owner','moderator');
  if not found then raise exception 'Room settings unavailable'; end if;
  insert into public.st_v6_room_audit(room_id,actor,action)
  values(p_room,actor,case when p_allowed then 'room.forwarding_enabled' else 'room.forwarding_disabled' end);
end $$;

create or replace function public.st_v6_set_room_typing_policy(p_room uuid,p_share boolean)
returns void language plpgsql security definer set search_path='' as $$
declare actor uuid:=auth.uid();
begin
  perform sectalk_private.st_v8_room_structure_require(p_room);
  perform sectalk_private.limit_action('v6_room_typing_policy',20);
  perform id from public.st_v6_rooms where id=p_room and not archived for update;
  if not found or p_share is null or sectalk_private.st_v6_room_role(p_room) is null
    then raise exception 'Room unavailable'; end if;

  insert into sectalk_private.room_typing(room_id,user_id,share_typing) values(p_room,actor,p_share)
  on conflict(room_id,user_id) do update set share_typing=p_share,
    expires_at=case when p_share then room_typing.expires_at end;
end $$;

commit;
