begin;

create table sectalk_private.st_v6_thread_summary_policy (
  workspace uuid primary key references public.st_v2_workspaces on delete cascade,
  enabled boolean not null,
  epoch uuid not null default gen_random_uuid()
);
create table sectalk_private.st_v6_thread_summary_consent (
  room uuid not null,
  root uuid not null,
  actor uuid not null references public.st_profiles on delete cascade,
  policy_epoch uuid not null,
  epoch uuid not null default gen_random_uuid(),
  primary key(room,root,actor),
  foreign key(room,root) references public.st_v6_room_posts(room_id,id) on delete cascade
);
alter table sectalk_private.st_v6_thread_summary_policy enable row level security;
alter table sectalk_private.st_v6_thread_summary_consent enable row level security;
revoke all on sectalk_private.st_v6_thread_summary_policy,sectalk_private.st_v6_thread_summary_consent
  from public,anon,authenticated,service_role;

create function public.st_v6_room_thread_summary_command(p_room uuid,p_root uuid,p_actor uuid,p_action text,p_enabled boolean)
returns jsonb language plpgsql security definer set search_path='' as $$
declare room_row public.st_v6_rooms;
declare policy sectalk_private.st_v6_thread_summary_policy;
declare owner boolean;
declare consent_epoch uuid;
declare source_rows jsonb;
declare revision text;
begin
  if p_action is null or p_action not in ('view','source','policy','opt-in','withdraw') then return null; end if;
  select * into room_row from public.st_v6_rooms r where r.id=p_room
    and r.kind='public' and r.classification in ('public','internal') and not r.archived;
  if not found or coalesce(sectalk_private.st_v6_room_role(p_room,p_actor),'') not in ('owner','moderator','member')
    or not exists(select 1 from public.st_v6_room_posts p where p.room_id=p_room and p.id=p_root
      and p.parent_id is null and p.removed_at is null and not p.forwarded and p.kind='message'
      and sectalk_private.open_pair(p_actor,p.sender)) then return null; end if;
  owner:=sectalk_private.st_v2_role(room_row.workspace_id,p_actor)='owner';
  select * into policy from sectalk_private.st_v6_thread_summary_policy where workspace=room_row.workspace_id;

  if p_action='policy' then
    if not owner or p_enabled is null then return null; end if;
    perform 1 from public.st_v2_workspaces where id=room_row.workspace_id for update;
    select * into policy from sectalk_private.st_v6_thread_summary_policy where workspace=room_row.workspace_id;
    if coalesce(policy.enabled,false) is distinct from p_enabled then
      insert into sectalk_private.st_v6_thread_summary_policy(workspace,enabled) values(room_row.workspace_id,p_enabled)
        on conflict(workspace) do update set enabled=excluded.enabled,epoch=gen_random_uuid() returning * into policy;
      insert into public.st_v2_workspace_audit(workspace_id,actor,event,target)
        values(room_row.workspace_id,p_actor,'workspace.thread_summary_policy',room_row.workspace_id);
    end if;
  elsif p_action='opt-in' then
    select * into policy from sectalk_private.st_v6_thread_summary_policy where workspace=room_row.workspace_id and enabled for share;
    if not found then return null; end if;
    insert into sectalk_private.st_v6_thread_summary_consent(room,root,actor,policy_epoch)
      values(p_room,p_root,p_actor,policy.epoch)
      on conflict(room,root,actor) do update set policy_epoch=excluded.policy_epoch,epoch=gen_random_uuid()
      where st_v6_thread_summary_consent.policy_epoch is distinct from excluded.policy_epoch;
  elsif p_action='withdraw' then
    delete from sectalk_private.st_v6_thread_summary_consent where room=p_room and root=p_root and actor=p_actor;
  end if;

  if coalesce(policy.enabled,false) then
    select c.epoch into consent_epoch from sectalk_private.st_v6_thread_summary_consent c
      where c.room=p_room and c.root=p_root and c.actor=p_actor and c.policy_epoch=policy.epoch;
  end if;
  if p_action='source' and consent_epoch is null then return null; end if;
  if consent_epoch is not null and p_action in ('view','source') then
    select coalesce(jsonb_agg(jsonb_build_object('id',source.id,'line',source.body,'speaker',source.name,'epoch',source.epoch)
      order by source.is_root desc,source.created_at,source.id),'[]'::jsonb) into source_rows
    from (
      select p.id,p.body,pr.name,c.epoch,p.created_at,p.id=p_root as is_root
      from public.st_v6_room_posts p
      join sectalk_private.st_v6_thread_summary_consent c on c.room=p.room_id and c.root=p_root and c.actor=p.sender
        and c.policy_epoch=policy.epoch
      join public.st_profiles pr on pr.id=p.sender
      where p.room_id=p_room and (p.id=p_root or p.parent_id=p_root)
        and p.removed_at is null and not p.forwarded and p.kind='message'
        and char_length(p.body) between 1 and 500 and btrim(p.body)<>''
        and sectalk_private.open_pair(p_actor,p.sender)
        and sectalk_private.st_v6_room_role(p_room,p.sender) in ('owner','moderator','member')
      order by is_root desc,p.created_at desc,p.id desc limit 60
    ) source;
    revision:=encode(sha256(convert_to(policy.epoch::text||':'||consent_epoch::text||':'||source_rows::text,'UTF8')),'hex');
  end if;
  return jsonb_build_object('owner',owner,'policy',coalesce(policy.enabled,false),
    'consented',consent_epoch is not null,'revision',revision,
    'source',case when p_action='source' then source_rows end);
end
$$;

revoke all on function public.st_v6_room_thread_summary_command(uuid,uuid,uuid,text,boolean)
  from public,anon,authenticated,service_role;
grant execute on function public.st_v6_room_thread_summary_command(uuid,uuid,uuid,text,boolean) to service_role;

commit;
