begin;

alter table public.st_v2_members
  add column suspended_at timestamptz,
  add constraint st_v6_workspace_owner_active check (role <> 'owner' or suspended_at is null);

create or replace function sectalk_private.st_v2_role(w uuid,u uuid)
returns text language sql stable security definer set search_path='' as $$
  select role from public.st_v2_members where workspace_id=w and user_id=u and suspended_at is null
$$;

create or replace function sectalk_private.st_v2_shared_profile(p uuid,u uuid)
returns boolean language sql stable security definer set search_path='' as $$
  select exists(select 1 from public.st_v2_members a join public.st_v2_members b using(workspace_id)
    where a.user_id=u and a.suspended_at is null and b.user_id=p)
$$;

create or replace function sectalk_private.st_v6_channel_can_manage(p_channel uuid,p_actor uuid)
returns boolean language sql stable security definer set search_path='' as $$
  select exists(select 1 from public.st_v2_channels c
    join public.st_v2_members m on m.workspace_id=c.workspace_id and m.user_id=p_actor
    where c.id=p_channel and m.suspended_at is null and sectalk_private.st_v2_active(p_actor)
      and (c.owner=p_actor or m.role in ('owner','admin')))
$$;

create or replace function public.st_v6_audit_workspaces()
returns table(id uuid,name text) language sql stable security definer set search_path='' as $$
  select w.id,w.name
  from public.st_v2_members m join public.st_v2_workspaces w on w.id=m.workspace_id
  where m.user_id=auth.uid() and m.role in ('owner','admin') and m.suspended_at is null
    and sectalk_private.st_v2_active(auth.uid())
  order by w.name,w.id
$$;

drop trigger st_v6_workspace_membership_hint on public.st_v2_members;
create trigger st_v6_workspace_membership_hint
after insert or update of role,suspended_at or delete on public.st_v2_members
for each row execute function sectalk_private.st_v6_workspace_membership_hint();

create or replace function sectalk_private.st_v6_manage_channel(p_channel uuid,p_action text,p_target uuid,p_visibility text)
returns void language plpgsql security definer set search_path='' as $$
declare actor uuid:=auth.uid(); channel public.st_v2_channels; workspace uuid; audit_detail text;
begin
  if not sectalk_private.st_v6_channel_can_manage(p_channel,actor) then raise exception 'Channel management unavailable'; end if;
  perform sectalk_private.limit_action('v6_manage_channel',30);
  if p_action in ('add_member','transfer_owner') then
    select workspace_id into workspace from public.st_v2_channels where id=p_channel;
    perform 1 from public.st_v2_members where workspace_id=workspace and user_id=p_target and suspended_at is null for share;
    if not found or not sectalk_private.st_v2_active(p_target) then raise exception 'Choose an active workspace member'; end if;
  end if;
  select * into channel from public.st_v2_channels where id=p_channel for update;
  if not found or not sectalk_private.st_v6_channel_can_manage(p_channel,actor)
    or (channel.archived and p_action is distinct from 'restore' and p_action is distinct from 'archive') then
    raise exception 'Channel management unavailable';
  end if;

  if p_action in ('add_member','transfer_owner') and p_target=channel.owner then return; end if;

  case p_action
    when 'visibility' then
      if p_visibility is null or p_visibility not in ('workspace','private') then raise exception 'Choose a channel visibility'; end if;
      if channel.visibility=p_visibility then return; end if;
      update public.st_v2_channels set visibility=p_visibility where id=p_channel;
      audit_detail:=channel.visibility||' → '||p_visibility;
    when 'add_member' then
      insert into sectalk_private.st_v6_channel_members values(p_channel,p_target) on conflict do nothing;
      if not found then return; end if;
    when 'remove_member' then
      if p_target=channel.owner then raise exception 'Transfer ownership before removing the owner'; end if;
      delete from sectalk_private.st_v6_channel_members where channel_id=p_channel and user_id=p_target;
      if not found then return; end if;
    when 'transfer_owner' then
      update public.st_v2_channels set owner=p_target where id=p_channel;
      delete from sectalk_private.st_v6_channel_members where channel_id=p_channel and user_id=p_target;
      audit_detail:=channel.owner::text;
    when 'archive','restore' then
      if channel.archived=(p_action='archive') then return; end if;
      update public.st_v2_channels set archived=(p_action='archive') where id=p_channel;
    else raise exception 'Channel management unavailable';
  end case;

  insert into sectalk_private.st_v6_channel_audit(channel_id,actor,action,target,detail)
    values(p_channel,actor,p_action,case when p_action in ('add_member','remove_member','transfer_owner') then p_target end,audit_detail);
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
  cap:=case sectalk_private.st_v2_effective_plan(workspace_owner)
    when 'basic' then 12 when 'professional' then 30 when 'business' then 100 when 'enterprise' then 500 else 5 end;
  if (select count(*) from public.st_v2_members where workspace_id=invitation.workspace_id)>=cap then
    raise exception 'This workspace has reached its member limit';
  end if;
  insert into public.st_v2_members(workspace_id,user_id) values(invitation.workspace_id,me) on conflict do nothing;
  update public.st_v2_invites set status='accepted' where id=p_invite;
  insert into public.st_v2_workspace_audit(workspace_id,actor,event,target) values(invitation.workspace_id,me,'member.joined',me);
  return invitation.workspace_id;
end $$;

create or replace function public.st_v2_set_member(p_workspace uuid,p_member uuid,p_role text)
returns void language plpgsql security definer set search_path='' as $$
declare
  actor uuid:=auth.uid();
  actor_role text;
  target_role text;
begin
  perform sectalk_private.limit_action('v2_role',12);
  perform id from public.st_v2_workspaces where id=p_workspace for update;
  actor_role:=sectalk_private.st_v2_role(p_workspace,actor);
  if not coalesce(actor_role in ('owner','admin'),false) or not sectalk_private.st_v2_active(actor)
    or p_member=actor or p_role is null or p_role not in ('admin','member','remove','suspend','restore')
  then raise exception 'Workspace action unavailable'; end if;

  select role into target_role from public.st_v2_members
    where workspace_id=p_workspace and user_id=p_member;
  if target_role is null or target_role='owner'
    or (actor_role='admin' and (target_role<>'member' or p_role not in ('suspend','restore')))
  then raise exception 'Workspace member unavailable'; end if;

  case p_role
    when 'remove' then
      delete from public.st_v2_members where workspace_id=p_workspace and user_id=p_member;
    when 'suspend' then
      update public.st_v2_members set suspended_at=clock_timestamp()
        where workspace_id=p_workspace and user_id=p_member and suspended_at is null;
    when 'restore' then
      update public.st_v2_members set suspended_at=null
        where workspace_id=p_workspace and user_id=p_member and suspended_at is not null;
    else
      update public.st_v2_members set role=p_role where workspace_id=p_workspace and user_id=p_member;
  end case;
  if found then
    insert into public.st_v2_workspace_audit(workspace_id,actor,event,target)
      values(p_workspace,actor,'member.'||p_role,p_member);
  end if;
end $$;

create function sectalk_private.st_v6_invite_workspace_handles(p_workspace uuid,p_handles text[])
returns table(handle text, sent boolean)
language plpgsql security definer set search_path='' as $$
declare
  actor uuid:=auth.uid();
  title text;
  peer uuid;
  normalized_handle text;
begin
  select name into title from public.st_v2_workspaces where id=p_workspace for update;
  if title is null or not coalesce(sectalk_private.st_v2_role(p_workspace,actor) in ('owner','admin'),false)
    or not sectalk_private.st_v2_active(actor)
  then raise exception 'Workspace action unavailable'; end if;

  if coalesce(cardinality(p_handles),0) not between 1 and 100 or array_ndims(p_handles)<>1
    or exists(select 1 from unnest(p_handles) h where h is null or char_length(h)>64)
  then raise exception 'Provide between 1 and 100 SecTalk handles'; end if;

  for normalized_handle in
    select lower(btrim(h)) from unnest(p_handles) with ordinality as input(h,position)
    group by lower(btrim(h)) order by min(position)
  loop
    handle:=normalized_handle;
    sent:=false;
    select p.id into peer from public.st_profiles p where p.handle=normalized_handle;
    if peer is not null and peer<>actor and sectalk_private.open_pair(actor,peer)
      and not exists(select 1 from public.st_v2_members where workspace_id=p_workspace and user_id=peer)
    then
      insert into public.st_v2_invites(workspace_id,invitee,created_by,workspace_name)
        values(p_workspace,peer,actor,title) on conflict(workspace_id,invitee) do nothing;
      sent:=found;
      if sent then
        insert into public.st_v2_workspace_audit(workspace_id,actor,event,target)
          values(p_workspace,actor,'member.invited',peer);
      end if;
    end if;
    return next;
  end loop;
end $$;

create or replace function public.st_v2_invite(p_workspace uuid,p_handle text)
returns boolean language plpgsql security definer set search_path='' as $$
begin
  perform sectalk_private.limit_action('v2_invite',10);
  return coalesce((select result.sent from sectalk_private.st_v6_invite_workspace_handles(p_workspace,
    array[coalesce(left(btrim(p_handle),25),'')]) result),false);
end $$;

create function public.st_v6_bulk_workspace_invite(p_workspace uuid,p_handles text[])
returns table(handle text, sent boolean) language plpgsql security definer set search_path='' as $$
begin
  perform sectalk_private.limit_action('v6_bulk_workspace_invite',3);
  return query select * from sectalk_private.st_v6_invite_workspace_handles(p_workspace,p_handles);
end $$;

revoke all on function sectalk_private.st_v6_invite_workspace_handles(uuid,text[]),
  public.st_v6_bulk_workspace_invite(uuid,text[])
  from public,anon,authenticated;
grant execute on function public.st_v6_bulk_workspace_invite(uuid,text[]) to authenticated;

commit;
