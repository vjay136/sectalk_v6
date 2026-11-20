begin;

alter table public.st_v2_channels
  add column owner uuid references public.st_profiles,
  add column visibility text not null default 'workspace' check(visibility in ('workspace','private')),
  add column archived boolean not null default false;
update public.st_v2_channels c set owner=w.owner from public.st_v2_workspaces w where w.id=c.workspace_id;
alter table public.st_v2_channels alter column owner set not null;

create table sectalk_private.st_v6_channel_members (
  channel_id uuid not null references public.st_v2_channels on delete cascade,
  user_id uuid not null references public.st_profiles on delete cascade,
  primary key(channel_id,user_id)
);
create table sectalk_private.st_v6_channel_audit (
  id bigint generated always as identity primary key,
  channel_id uuid not null references public.st_v2_channels on delete cascade,
  actor uuid not null references public.st_profiles,
  action text not null,
  target uuid,
  detail text,
  occurred_at timestamptz not null default clock_timestamp()
);
create index st_v6_channel_audit_feed on sectalk_private.st_v6_channel_audit(channel_id,id desc);
alter table sectalk_private.st_v6_channel_members enable row level security;
alter table sectalk_private.st_v6_channel_audit enable row level security;
revoke all on sectalk_private.st_v6_channel_members,sectalk_private.st_v6_channel_audit from public,anon,authenticated;

create function sectalk_private.st_v6_channel_set_initial_owner()
returns trigger language plpgsql security definer set search_path='' as $$
begin
  if new.owner is null then
    select case when sectalk_private.st_v2_role(new.workspace_id,auth.uid()) in ('owner','admin')
      then auth.uid() else w.owner end into new.owner
    from public.st_v2_workspaces w where w.id=new.workspace_id;
  end if;
  return new;
end $$;
create trigger st_v6_channel_set_initial_owner before insert on public.st_v2_channels
  for each row execute function sectalk_private.st_v6_channel_set_initial_owner();
revoke all on function sectalk_private.st_v6_channel_set_initial_owner() from public,anon,authenticated;

create function sectalk_private.st_v6_channel_content_access(p_channel uuid,p_actor uuid)
returns boolean language sql stable security definer set search_path='' as $$
  select exists(select 1 from public.st_v2_channels c where c.id=p_channel
    and sectalk_private.st_v2_active(p_actor) and sectalk_private.st_v2_role(c.workspace_id,p_actor) is not null
    and (c.visibility='workspace' or c.owner=p_actor or exists(
      select 1 from sectalk_private.st_v6_channel_members m where m.channel_id=c.id and m.user_id=p_actor)))
$$;

create function sectalk_private.st_v6_channel_can_manage(p_channel uuid,p_actor uuid)
returns boolean language sql stable security definer set search_path='' as $$
  select exists(select 1 from public.st_v2_channels c
    join public.st_v2_members m on m.workspace_id=c.workspace_id and m.user_id=p_actor
    where c.id=p_channel and sectalk_private.st_v2_active(p_actor) and (c.owner=p_actor or m.role in ('owner','admin')))
$$;

revoke all on function sectalk_private.st_v6_channel_content_access(uuid,uuid),
  sectalk_private.st_v6_channel_can_manage(uuid,uuid) from public,anon,authenticated;
grant execute on function sectalk_private.st_v6_channel_content_access(uuid,uuid),
  sectalk_private.st_v6_channel_can_manage(uuid,uuid) to authenticated;

alter policy st_v2_channel_read on public.st_v2_channels using(
  sectalk_private.st_v6_channel_content_access(id,(select auth.uid()))
  or sectalk_private.st_v6_channel_can_manage(id,(select auth.uid())));

create or replace function sectalk_private.st_v2_post_read(c uuid,s uuid,u uuid)
returns boolean language sql stable security definer set search_path='' as $$
  select sectalk_private.st_v6_channel_content_access(c,u)
    and not exists(select 1 from public.st_blocks where (actor,target) in ((u,s),(s,u)))
$$;

create or replace function public.st_v2_post(p_channel uuid,p_id uuid,p_body text)
returns void language plpgsql security definer set search_path='' as $$
declare me uuid:=auth.uid(); is_archived boolean;
begin
  perform sectalk_private.limit_action('v2_post',60);
  select archived into is_archived from public.st_v2_channels where id=p_channel for update;
  if not found or is_archived or not sectalk_private.st_v6_channel_content_access(p_channel,me)
    then raise exception 'Channel unavailable'; end if;
  insert into public.st_v2_posts(id,channel_id,sender,body) values(p_id,p_channel,me,btrim(p_body)) on conflict(id) do nothing;
  if not found and not exists(select 1 from public.st_v2_posts where id=p_id and channel_id=p_channel and sender=me and body=btrim(p_body))
    then raise exception 'Message ID already in use'; end if;
end $$;

create function sectalk_private.st_v6_channel_details(p_channel uuid)
returns jsonb language plpgsql stable security definer set search_path='' as $$
declare can_read boolean:=sectalk_private.st_v6_channel_content_access(p_channel,auth.uid());
        can_manage boolean:=sectalk_private.st_v6_channel_can_manage(p_channel,auth.uid());
begin
  if not can_manage then return jsonb_build_object('can_read',can_read,'can_manage',false); end if;
  return jsonb_build_object('can_read',can_read,'can_manage',true,
    'members',coalesce((select jsonb_agg(m.user_id order by m.user_id) from sectalk_private.st_v6_channel_members m
      where m.channel_id=p_channel),'[]'::jsonb),
    'audit',coalesce((select jsonb_agg(to_jsonb(a)-'channel_id' order by a.id desc) from (
      select * from sectalk_private.st_v6_channel_audit where channel_id=p_channel order by id desc limit 50) a),'[]'::jsonb));
end $$;

create function sectalk_private.st_v6_manage_channel(p_channel uuid,p_action text,p_target uuid,p_visibility text)
returns void language plpgsql security definer set search_path='' as $$
declare actor uuid:=auth.uid(); channel public.st_v2_channels; workspace uuid; audit_detail text;
begin
  if not sectalk_private.st_v6_channel_can_manage(p_channel,actor) then raise exception 'Channel management unavailable'; end if;
  perform sectalk_private.limit_action('v6_manage_channel',30);
  if p_action in ('add_member','transfer_owner') then
    select workspace_id into workspace from public.st_v2_channels where id=p_channel;
    perform 1 from public.st_v2_members where workspace_id=workspace and user_id=p_target for key share;
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

create function sectalk_private.st_v6_channel_workspace_departure()
returns trigger language plpgsql security definer set search_path='' as $$
begin
  with removed as (
    delete from sectalk_private.st_v6_channel_members m using public.st_v2_channels c
    where m.channel_id=c.id and c.workspace_id=old.workspace_id and m.user_id=old.user_id
    returning m.channel_id
  ) insert into sectalk_private.st_v6_channel_audit(channel_id,actor,action,target)
    select channel_id,coalesce(auth.uid(),old.user_id),'workspace_departure',old.user_id from removed;

  with restored as (
    update public.st_v2_channels c set owner=w.owner from public.st_v2_workspaces w
    where c.workspace_id=w.id and w.id=old.workspace_id and c.owner=old.user_id and c.owner<>w.owner
    returning c.id,c.owner
  ) insert into sectalk_private.st_v6_channel_audit(channel_id,actor,action,target,detail)
    select id,coalesce(auth.uid(),old.user_id),'transfer_owner',owner,old.user_id::text from restored;
  return old;
end $$;
create trigger st_v6_channel_workspace_departure after delete on public.st_v2_members
  for each row execute function sectalk_private.st_v6_channel_workspace_departure();
revoke all on function sectalk_private.st_v6_channel_workspace_departure() from public,anon,authenticated;

create function public.st_v6_channel_details(p_channel uuid)
returns jsonb language sql stable security invoker set search_path=''
return sectalk_private.st_v6_channel_details(p_channel);

create function public.st_v6_manage_channel(p_channel uuid,p_action text,p_target uuid default null,p_visibility text default null)
returns void language sql security invoker set search_path=''
return sectalk_private.st_v6_manage_channel(p_channel,p_action,p_target,p_visibility);

revoke all on function public.st_v6_channel_details(uuid),public.st_v6_manage_channel(uuid,text,uuid,text),
  sectalk_private.st_v6_channel_details(uuid),sectalk_private.st_v6_manage_channel(uuid,text,uuid,text) from public,anon,authenticated;
grant execute on function public.st_v6_channel_details(uuid),public.st_v6_manage_channel(uuid,text,uuid,text),
  sectalk_private.st_v6_channel_details(uuid),sectalk_private.st_v6_manage_channel(uuid,text,uuid,text) to authenticated;

commit;
