begin;

create function public.st_v6_audit_workspaces()
returns table(id uuid,name text) language sql stable security definer set search_path='' as $$
  select w.id,w.name
  from public.st_v2_members m join public.st_v2_workspaces w on w.id=m.workspace_id
  where m.user_id=auth.uid() and m.role in ('owner','admin') and sectalk_private.st_v2_active(auth.uid())
  order by w.name,w.id
$$;

create index st_v6_room_audit_times on public.st_v6_room_audit(room_id,occurred_at desc,id desc);

create function public.st_v6_audit_search(
  p_workspace uuid,p_query text default '',p_source text default null,p_from timestamptz default null,p_before timestamptz default null
)
returns table(source text,id bigint,event text,actor uuid,target uuid,room_name text,at timestamptz)
language plpgsql stable security invoker set search_path='' as $$
declare needle text:=lower(btrim(coalesce(p_query,'')));
begin
  if not exists(select 1 from public.st_v6_audit_workspaces() w where w.id=p_workspace)
    then raise exception 'Audit search is unavailable for this workspace' using errcode='42501'; end if;
  if char_length(needle)>120 or (p_source is not null and p_source not in ('workspace','room'))
    or (p_from is not null and p_before is not null and p_before<=p_from)
    then raise exception 'Choose valid audit search filters' using errcode='22023'; end if;
  return query
  select r.log_source,r.log_id,r.action,r.who,r.subject,r.room,r.event_time
  from (
    (select 'workspace'::text as log_source,a.id as log_id,a.event as action,a.actor as who,a.target as subject,
      null::text as room,a.created_at as event_time
      from public.st_v2_workspace_audit a
      where a.workspace_id=p_workspace and (p_source is null or p_source='workspace')
        and (p_from is null or a.created_at>=p_from) and (p_before is null or a.created_at<p_before)
        and (needle='' or strpos(lower(concat_ws(' ',a.event,replace(a.event,'.',' '),a.actor,a.target)),needle)>0)
      order by a.created_at desc,a.id desc limit 100)
    union all
    (select 'room',a.id,a.action,a.actor,a.target,room.name,a.occurred_at
      from public.st_v6_rooms room join public.st_v6_room_audit a on a.room_id=room.id
      where room.workspace_id=p_workspace and (p_source is null or p_source='room')
        and (p_from is null or a.occurred_at>=p_from) and (p_before is null or a.occurred_at<p_before)
        and (needle='' or strpos(lower(concat_ws(' ',a.action,replace(a.action,'.',' '),a.actor,a.target,room.name)),needle)>0)
      order by a.occurred_at desc,a.id desc limit 100)
  ) r order by r.event_time desc,r.log_source,r.log_id desc limit 100;
end $$;

revoke all on function public.st_v6_audit_workspaces(),
  public.st_v6_audit_search(uuid,text,text,timestamptz,timestamptz) from public,anon,authenticated;
grant execute on function public.st_v6_audit_workspaces(),
  public.st_v6_audit_search(uuid,text,text,timestamptz,timestamptz) to authenticated;

commit;
