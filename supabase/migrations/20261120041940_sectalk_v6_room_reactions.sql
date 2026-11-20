begin;

create table public.st_v6_workspace_reaction_policy (
  workspace_id uuid primary key references public.st_v2_workspaces on delete cascade,
  emoji_set text not null check(emoji_set in ('all','native','essential','off')),
  per_person smallint not null check(per_person between 1 and 8)
);
alter table public.st_v6_workspace_reaction_policy enable row level security;
revoke all on public.st_v6_workspace_reaction_policy from public,anon,authenticated;
grant select on public.st_v6_workspace_reaction_policy to authenticated;
create policy st_v6_workspace_reaction_policy_read on public.st_v6_workspace_reaction_policy
for select to authenticated using(sectalk_private.st_v2_role(workspace_id,(select auth.uid())) is not null);

create table sectalk_private.st_v6_room_reactions (
  room_id uuid not null,
  post_id uuid not null,
  actor_id uuid not null references public.st_profiles on delete cascade,
  emoji text not null check(char_length(emoji) between 1 and 80),
  primary key(room_id,post_id,actor_id,emoji),
  foreign key(room_id,post_id) references public.st_v6_room_posts(room_id,id) on delete cascade
);
alter table sectalk_private.st_v6_room_reactions enable row level security;
revoke all on sectalk_private.st_v6_room_reactions from public,anon,authenticated;

create table public.st_v6_room_reaction_changes (
  room_id uuid primary key references public.st_v6_rooms on delete cascade,
  revision bigint not null
);
alter table public.st_v6_room_reaction_changes enable row level security;
revoke all on public.st_v6_room_reaction_changes from public,anon,authenticated;
grant select on public.st_v6_room_reaction_changes to authenticated;
create policy st_v6_room_reaction_changes_read on public.st_v6_room_reaction_changes
for select to authenticated using(sectalk_private.st_v6_room_role(room_id) is not null);

create function public.st_v6_set_workspace_reactions(p_workspace uuid,p_set text,p_limit integer)
returns void language plpgsql security definer set search_path='' as $$
declare actor uuid:=auth.uid();
begin
  perform sectalk_private.limit_action('v6_workspace_reactions',12);
  perform id from public.st_v2_workspaces where id=p_workspace for no key update;
  if not found or not sectalk_private.st_v2_active(actor)
    or not coalesce(sectalk_private.st_v2_role(p_workspace,actor) in ('owner','admin'),false)
    then raise exception 'Reaction settings unavailable'; end if;
  if p_set is null or p_set not in ('all','native','essential','off') or p_limit is null or p_limit not between 1 and 8
    then raise exception 'Choose a supported emoji set and reaction limit'; end if;
  insert into public.st_v6_workspace_reaction_policy as current_policy(workspace_id,emoji_set,per_person)
    values(p_workspace,p_set,p_limit) on conflict(workspace_id) do update
    set emoji_set=excluded.emoji_set,per_person=excluded.per_person
    where (current_policy.emoji_set,current_policy.per_person) is distinct from (excluded.emoji_set,excluded.per_person);
  if found then
    insert into public.st_v2_workspace_audit(workspace_id,actor,event)
      values(p_workspace,actor,'workspace.reaction_policy');
  end if;
end $$;

create function public.st_v6_react_room_post(p_room uuid,p_post uuid,p_emoji text,p_enabled boolean)
returns void language plpgsql security definer set search_path='' as $$
declare actor uuid:=auth.uid(); target_workspace uuid; room public.st_v6_rooms;
  room_role text; policy public.st_v6_workspace_reaction_policy; parts text[];
begin
  perform sectalk_private.limit_action('v6_room_reaction',40);
  select workspace_id into target_workspace from public.st_v6_rooms where id=p_room;
  perform id from public.st_v2_workspaces where id=target_workspace for share;
  select * into room from public.st_v6_rooms where id=p_room and workspace_id=target_workspace for no key update;
  room_role:=sectalk_private.st_v6_room_role(p_room);
  if room.id is null or room_role is null or room_role='read_only' or room.archived
    then raise exception 'Reaction unavailable'; end if;
  perform id from public.st_v6_room_posts where room_id=p_room and id=p_post and removed_at is null for update;
  if not found then raise exception 'Reaction unavailable'; end if;
  if p_enabled is null or p_emoji is null or char_length(p_emoji) not between 1 and 80
    then raise exception 'Choose an emoji reaction'; end if;
  if not p_enabled then
    delete from sectalk_private.st_v6_room_reactions where room_id=p_room and post_id=p_post and actor_id=actor and emoji=p_emoji;
  else
    if exists(select 1 from sectalk_private.st_v6_room_reactions
      where room_id=p_room and post_id=p_post and actor_id=actor and emoji=p_emoji) then return; end if;
    if (room_role not in ('owner','moderator') and (room.locked or room.kind in ('announcement','broadcast'))) or
      exists(select 1 from public.st_v6_room_timeouts where room_id=p_room and user_id=actor and until_at>now())
      then raise exception 'Reactions are unavailable in this room'; end if;

    select * into policy from public.st_v6_workspace_reaction_policy where workspace_id=target_workspace;
    if policy.emoji_set='off' or
      (policy.emoji_set='essential' and p_emoji not in ('👍','❤️','✅','👀'))
      then raise exception 'That reaction is unavailable under workspace policy'; end if;
    if not exists(select 1 from sectalk_private.st_v5_reaction_catalog where collection='native' and value=p_emoji) then
      parts:=regexp_match(p_emoji,'^\[\[st:([^|]+)\|([^|]+)\]\]$');
      if coalesce(policy.emoji_set,'all')<>'all' or parts is null or
        not exists(select 1 from sectalk_private.st_v5_reaction_catalog where collection='base' and value=parts[1]) or
        not exists(select 1 from sectalk_private.st_v5_reaction_catalog where collection='badge' and value=parts[2])
        then raise exception 'Choose an emoji allowed by this workspace'; end if;
    end if;
    if (select count(*) from sectalk_private.st_v6_room_reactions where room_id=p_room and post_id=p_post and actor_id=actor)
      >=coalesce(policy.per_person,8) then raise exception 'Remove a reaction before adding more'; end if;
    if not exists(select 1 from sectalk_private.st_v6_room_reactions where room_id=p_room and post_id=p_post and emoji=p_emoji)
      and (select count(distinct emoji) from sectalk_private.st_v6_room_reactions where room_id=p_room and post_id=p_post)>=24
      then raise exception 'This message already has 24 different reactions'; end if;
    insert into sectalk_private.st_v6_room_reactions values(p_room,p_post,actor,p_emoji);
  end if;
  if found then
    insert into public.st_v6_room_reaction_changes as changes values(p_room,1)
      on conflict(room_id) do update set revision=changes.revision+1;
  end if;
end $$;

create function public.st_v6_room_reaction_counts(p_room uuid,p_posts uuid[])
returns table(post_id uuid,emoji text,amount bigint,mine boolean)
language sql stable security definer set search_path='' as $$
  select r.post_id,r.emoji,count(*),bool_or(r.actor_id=auth.uid())
  from sectalk_private.st_v6_room_reactions r
  join public.st_v6_room_posts p on p.room_id=r.room_id and p.id=r.post_id
  where cardinality(p_posts) between 1 and 151 and r.room_id=p_room and r.post_id=any(p_posts) and p.removed_at is null
    and sectalk_private.st_v6_room_role(p_room) is not null
  group by r.post_id,r.emoji
  order by r.post_id,r.emoji
$$;

revoke all on function public.st_v6_set_workspace_reactions(uuid,text,integer),
  public.st_v6_react_room_post(uuid,uuid,text,boolean),public.st_v6_room_reaction_counts(uuid,uuid[]) from public,anon,authenticated;
grant execute on function public.st_v6_set_workspace_reactions(uuid,text,integer),
  public.st_v6_react_room_post(uuid,uuid,text,boolean),public.st_v6_room_reaction_counts(uuid,uuid[]) to authenticated;
alter publication supabase_realtime add table public.st_v6_workspace_reaction_policy,public.st_v6_room_reaction_changes;

commit;
