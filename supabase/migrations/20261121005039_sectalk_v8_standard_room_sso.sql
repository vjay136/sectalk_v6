begin;

create table sectalk_private.st_v8_workspace_standard_room_sso (
  workspace uuid primary key references public.st_v2_workspaces on delete cascade,
  protocol text not null check(protocol in ('saml','oidc')),
  provider text not null
);
alter table sectalk_private.st_v8_workspace_standard_room_sso enable row level security;
revoke all on sectalk_private.st_v8_workspace_standard_room_sso from public,anon,authenticated,service_role;

create function sectalk_private.st_v8_standard_room_session_allowed(p_room uuid)
returns boolean language sql stable set search_path='' as $$
  select coalesce((select sectalk_private.st_v8_workspace_session_receipt(p.workspace,p.protocol,p.provider) is true
    from public.st_v6_rooms r join sectalk_private.st_v8_workspace_standard_room_sso p on p.workspace=r.workspace_id
    where r.id=p_room and r.encryption_mode='standard'),true);
$$;

-- Resolve membership separately so a signed-in member can discover the room and
-- see how to regain access without learning anything about an inaccessible room.
create function sectalk_private.st_v8_room_membership_role(p_room uuid,p_user uuid)
returns text language sql stable set search_path='' as $$
  select case when c.id is not null then
      case when enrolled.role='teacher' and m.role in ('owner','moderator') then m.role
        when enrolled.role='student' and m.role='member' then 'member' end
    when r.kind='admin' and workspace_role.role in ('owner','admin')
      then case when workspace_role.role='owner' then 'owner' else 'moderator' end
    when r.kind<>'admin' and (m.role<>'guest' or not sectalk_private.st_v7_healthcare_workspace(r.workspace_id)) then m.role end
  from public.st_v6_rooms r
  cross join lateral (select sectalk_private.st_v2_role(r.workspace_id,p_user) as role) workspace_role
  left join public.st_v6_room_members m on m.room_id=r.id and m.user_id=p_user
  left join sectalk_private.st_v7_school_classes c on c.room=r.id
  left join sectalk_private.st_v7_school_class_people enrolled on enrolled.workspace=c.workspace
    and enrolled.class=c.id and enrolled.person=p_user
  where r.id=p_room and sectalk_private.st_v2_active(p_user) and workspace_role.role is not null
    and not exists(select 1 from public.st_v6_room_bans b where b.room_id=r.id and b.user_id=p_user)
$$;

create or replace function sectalk_private.st_v6_room_role(p_room uuid,p_user uuid)
returns text language sql stable security definer set search_path='' as $$
  select case when p_user=auth.uid() and not sectalk_private.st_v8_standard_room_session_allowed(p_room)
    then null else sectalk_private.st_v8_room_membership_role(p_room,p_user) end;
$$;

create or replace function sectalk_private.st_v6_room_directory(p_room uuid)
returns boolean language sql stable security definer set search_path='' as $$
  select exists(select 1 from public.st_v6_rooms r
    where r.id=p_room and sectalk_private.st_v2_active(auth.uid())
      and sectalk_private.st_v2_role(r.workspace_id,auth.uid()) is not null and (
        sectalk_private.st_v8_room_membership_role(r.id,auth.uid()) is not null
        or (not r.archived and (
          r.kind in ('public','announcement','broadcast')
          or (r.kind='private' and exists(select 1 from public.st_v6_room_entries e where e.room_id=r.id
            and e.user_id=auth.uid() and e.kind='invite' and e.expires_at>now()))
        ) and not exists(select 1 from public.st_v6_room_bans b where b.room_id=r.id and b.user_id=auth.uid()))
      ));
$$;

-- Includes starter posts created inside the room template RPC and serializes
-- ordinary publishing with activation of the workspace policy.
create function sectalk_private.st_v8_guard_standard_room_post_write()
returns trigger language plpgsql security definer set search_path='' as $$
begin
  if new.sender=auth.uid() then
    perform 1 from public.st_v2_workspaces workspace join public.st_v6_rooms room
      on room.workspace_id=workspace.id where room.id=new.room_id for key share of workspace;
    if not sectalk_private.st_v8_standard_room_session_allowed(new.room_id) then
      raise exception 'Workspace single sign-on is required for these room messages' using errcode='42501';
    end if;
  end if;
  return new;
end $$;
create trigger st_v8_standard_room_post_write before insert or update of body on public.st_v6_room_posts
  for each row execute function sectalk_private.st_v8_guard_standard_room_post_write();

create or replace function public.st_v6_task_source(p_id uuid)
returns jsonb language plpgsql stable security definer set search_path='' as $$
declare origin sectalk_private.st_v6_task_sources; task public.st_v6_tasks; live_body text;
begin
  if not sectalk_private.st_v6_task_can_read(p_id) then raise exception 'Task unavailable'; end if;
  select * into task from public.st_v6_tasks where id=p_id;
  select * into origin from sectalk_private.st_v6_task_sources where task_id=p_id;
  if not found then return null; end if;
  if task.room_id is not null then
    select m.body into live_body from public.st_v6_room_posts m where m.room_id=task.room_id and m.id=origin.message_id
      and m.created_at=origin.message_created_at and m.removed_at is null
      and sectalk_private.st_v8_standard_room_session_allowed(task.room_id);
  else
    select m.body into live_body from public.st_messages m where m.chat_id=task.chat_id and m.id=origin.message_id
      and m.created_at=origin.message_created_at
      and m.revoked_at is null and not exists(select 1 from public.st_v5_hidden_messages h
        where h.user_id=auth.uid() and h.message_id=m.id);
  end if;
  if live_body is null then return jsonb_build_object('available',false); end if;
  return jsonb_build_object('available',true,'messageId',origin.message_id,'snapshot',origin.snapshot,'currentText',live_body,'edited',live_body<>origin.snapshot);
end $$;

-- Guest capabilities cannot provide an alternate read path to protected posts.
create or replace function sectalk_private.st_v6_room_guest_policy(p_room public.st_v6_rooms)
returns boolean language sql stable set search_path='' as $$
  select p_room.kind='public' and p_room.classification='public' and p_room.forwarding_allowed
    and not p_room.locked and not p_room.archived
    and not exists(select 1 from sectalk_private.st_v8_workspace_standard_room_sso p where p.workspace=p_room.workspace_id);
$$;

create function sectalk_private.st_v8_guard_standard_room_guest_insert()
returns trigger language plpgsql security definer set search_path='' as $$
declare target public.st_v6_rooms;
begin
  select * into target from public.st_v6_rooms where id=new.room;
  perform 1 from public.st_v2_workspaces where id=target.workspace_id for key share;
  if not coalesce(sectalk_private.st_v6_room_guest_policy(target),false) then
    raise insufficient_privilege;
  end if;
  return new;
end $$;
create trigger st_v8_standard_room_guest_insert before insert on sectalk_private.st_v6_room_guest_link
  for each row execute function sectalk_private.st_v8_guard_standard_room_guest_insert();

create function public.st_v8_standard_room_requires_sso(p_room uuid)
returns boolean language sql stable security definer set search_path='' as $$
  select auth.uid() is not null and sectalk_private.st_v8_room_membership_role(p_room,auth.uid()) is not null
    and not sectalk_private.st_v8_standard_room_session_allowed(p_room);
$$;

create function public.st_v8_workspace_standard_room_policy(p_workspace uuid,p_require boolean default null)
returns jsonb language plpgsql security definer set search_path='' as $$
declare access text:=sectalk_private.st_v7_file_egress_operator(p_workspace); setup sectalk_private.st_v7_workspace_sso;
begin
  if access is distinct from 'verified' then return jsonb_build_object('access',access); end if;
  if p_require is not null then
    perform sectalk_private.limit_action('v8_standard_room_sso_policy',5);
    perform 1 from public.st_v2_workspaces w where w.id=p_workspace for update;
    if not found or sectalk_private.st_v7_file_egress_operator(p_workspace) is distinct from 'verified' then
      raise insufficient_privilege;
    end if;
    if p_require then
      select * into setup from sectalk_private.st_v7_workspace_sso c where c.workspace=p_workspace;
      if not found or sectalk_private.st_v7_workspace_sso_provider(setup.workspace,setup.domain,setup.protocol)
        is distinct from setup.provider or not exists(
          select 1 from sectalk_private.st_v7_workspace_sso_sessions r join auth.sessions s on s.id=r.session and s.user_id=r.principal
          where r.workspace=p_workspace and r.protocol=setup.protocol and r.provider=setup.provider
            and sectalk_private.st_v2_active(r.principal) and sectalk_private.st_v2_role(p_workspace,r.principal) is not null
            and sectalk_private.st_v7_session_deadline(s.created_at,s.refreshed_at,s.not_after)>statement_timestamp()
        ) then return '{"access":"verified","error":"verified_provider_session_required"}'; end if;
      insert into sectalk_private.st_v8_workspace_standard_room_sso(workspace,protocol,provider)
        values(p_workspace,setup.protocol,setup.provider)
        on conflict(workspace) do update set protocol=excluded.protocol,provider=excluded.provider;
      -- Disabling the policy later cannot reactivate a previously issued guest link.
      update sectalk_private.st_v6_room_guest_link l set revoked_at=clock_timestamp()
        from public.st_v6_rooms r where l.room=r.id and r.workspace_id=p_workspace and r.encryption_mode='standard'
          and l.revoked_at is null and l.expires_at>clock_timestamp();
    else
      delete from sectalk_private.st_v8_workspace_standard_room_sso p where p.workspace=p_workspace;
    end if;
    insert into public.st_v2_workspace_audit(workspace_id,actor,event)
      values(p_workspace,auth.uid(),case when p_require then 'workspace.standard_room_sso_required'
        else 'workspace.standard_room_sso_recovered' end);
  end if;
  return jsonb_build_object('access','verified',
    'required',exists(select 1 from sectalk_private.st_v8_workspace_standard_room_sso p where p.workspace=p_workspace));
end $$;

revoke all on function sectalk_private.st_v8_room_membership_role(uuid,uuid),
  sectalk_private.st_v8_standard_room_session_allowed(uuid),sectalk_private.st_v8_guard_standard_room_guest_insert(),
  sectalk_private.st_v8_guard_standard_room_post_write(),
  public.st_v8_standard_room_requires_sso(uuid),
  public.st_v8_workspace_standard_room_policy(uuid,boolean) from public,anon,authenticated,service_role;
grant execute on function public.st_v8_standard_room_requires_sso(uuid),
  public.st_v8_workspace_standard_room_policy(uuid,boolean) to authenticated;

commit;
