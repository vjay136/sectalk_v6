begin;

create table sectalk_private.st_v8_workspace_audit_sso (
  workspace uuid primary key references public.st_v2_workspaces on delete cascade,
  protocol text not null check(protocol in ('saml','oidc')),
  provider text not null
);
alter table sectalk_private.st_v8_workspace_audit_sso enable row level security;
revoke all on table sectalk_private.st_v8_workspace_audit_sso from public,anon,authenticated,service_role;

-- This policy applies to current-caller audit requests. Role lookups are kept separate
-- for normal workspace selection, automation and owner recovery.
create function sectalk_private.st_v8_audit_sso_allows(p_workspace uuid)
returns boolean language sql stable security definer set search_path='' as $$
  select not exists(select 1 from sectalk_private.st_v8_workspace_audit_sso p
    where p.workspace=p_workspace
      and sectalk_private.st_v8_workspace_session_receipt(p.workspace,p.protocol,p.provider) is not true);
$$;
revoke all on function sectalk_private.st_v8_audit_sso_allows(uuid) from public,anon,authenticated,service_role;
grant execute on function sectalk_private.st_v8_audit_sso_allows(uuid) to authenticated;

create function public.st_v8_workspace_audit_requires_sso(p_workspace uuid)
returns boolean language sql stable security definer set search_path='' as $$
  select sectalk_private.st_v2_active(auth.uid())
    and coalesce(sectalk_private.st_v2_role(p_workspace,auth.uid()) in ('owner','admin'),false)
    and not sectalk_private.st_v8_audit_sso_allows(p_workspace);
$$;

create function public.st_v8_workspace_audit_policy(p_workspace uuid,p_require boolean default null)
returns jsonb language plpgsql security definer set search_path='' as $$
declare access text:=sectalk_private.st_v7_file_egress_operator(p_workspace); setup sectalk_private.st_v7_workspace_sso;
begin
  if access is distinct from 'verified' then return jsonb_build_object('access',access); end if;
  if p_require is not null then
    perform sectalk_private.limit_action('v8_audit_sso_policy',5);
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
      insert into sectalk_private.st_v8_workspace_audit_sso(workspace,protocol,provider)
        values(p_workspace,setup.protocol,setup.provider)
        on conflict(workspace) do update set protocol=excluded.protocol,provider=excluded.provider;
    else
      delete from sectalk_private.st_v8_workspace_audit_sso p where p.workspace=p_workspace;
    end if;
    if found then
      insert into public.st_v2_workspace_audit(workspace_id,actor,event)
        values(p_workspace,auth.uid(),case when p_require then 'workspace.audit_sso_required'
          else 'workspace.audit_sso_recovered' end);
    end if;
  end if;
  return jsonb_build_object('access','verified',
    'required',exists(select 1 from sectalk_private.st_v8_workspace_audit_sso p where p.workspace=p_workspace));
end $$;

revoke all on function public.st_v8_workspace_audit_policy(uuid,boolean),
  public.st_v8_workspace_audit_requires_sso(uuid) from public,anon,authenticated,service_role;
grant execute on function public.st_v8_workspace_audit_policy(uuid,boolean),
  public.st_v8_workspace_audit_requires_sso(uuid) to authenticated;

-- Ordinary workspace audit browsing and signed-export authorization use the
-- current caller. Independent journal writers and compliance workers keep
-- their targeted capabilities.
create policy st_v8_audit_sso on public.st_v2_workspace_audit as restrictive for select to authenticated
  using(sectalk_private.st_v8_audit_sso_allows(workspace_id));

create or replace function public.st_v6_audit_search(
  p_workspace uuid,p_query text default '',p_source text default null,p_from timestamptz default null,p_before timestamptz default null
)
returns table(source text,id bigint,event text,actor uuid,target uuid,room_name text,at timestamptz)
language plpgsql stable security invoker set search_path='' as $$
declare needle text:=lower(btrim(coalesce(p_query,'')));
begin
  if not exists(select 1 from public.st_v6_audit_workspaces() w where w.id=p_workspace)
    then raise exception 'Audit search is unavailable for this workspace' using errcode='42501'; end if;
  if public.st_v8_workspace_audit_requires_sso(p_workspace) then
    raise exception 'Sign in through your workspace provider to access audit logs' using errcode='42501';
  end if;
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

create or replace function public.st_v6_audit_integrity_status(p_workspace uuid,p_rows jsonb)
returns jsonb language plpgsql stable security definer set search_path=''
set timezone='UTC' set datestyle='ISO, YMD' as $$
declare requested jsonb;
declare source_table text;
declare source_ref bigint;
declare current_hash bytea;
declare matched boolean:=true;
declare anchored timestamptz;
begin
  if not coalesce(sectalk_private.st_v2_role(p_workspace,auth.uid()) in ('owner','admin'),false)
    or sectalk_private.st_v2_active(auth.uid()) is not true
  then raise exception 'Workspace audit verification is unavailable' using errcode='42501'; end if;
  if not sectalk_private.st_v8_audit_sso_allows(p_workspace) then
    raise exception 'Sign in through your workspace provider to access audit logs' using errcode='42501';
  end if;
  if p_rows is null or jsonb_typeof(p_rows)<>'array' or jsonb_array_length(p_rows)>100
  then raise exception 'Choose a valid audit result set' using errcode='22023'; end if;
  for requested in select value from jsonb_array_elements(p_rows)
  loop
    if requested->>'source' not in ('workspace','room') or requested->>'source' is null
      or coalesce(requested->>'id','')!~'^[0-9]{1,18}$' then
      raise exception 'Choose valid audit references' using errcode='22023';
    end if;
    source_ref:=(requested->>'id')::bigint;
    if requested->>'source'='workspace' then
      source_table:='public.st_v2_workspace_audit';
      select sectalk_private.st_v6_audit_row_hash(to_jsonb(a)) into current_hash
      from public.st_v2_workspace_audit a where a.workspace_id=p_workspace and a.id=source_ref;
    else
      source_table:='public.st_v6_room_audit';
      select sectalk_private.st_v6_audit_row_hash(to_jsonb(a)) into current_hash
      from public.st_v6_room_audit a join public.st_v6_rooms r on r.id=a.room_id
      where r.workspace_id=p_workspace and a.id=source_ref
        and sectalk_private.st_v6_room_role(a.room_id) in ('owner','moderator');
    end if;
    if current_hash is null or not exists(
      select 1 from (
        select c.row_hash,c.operation from sectalk_private.st_v6_audit_chain c
        where c.source=source_table and c.source_id=source_ref order by c.entry_no desc limit 1
      ) proof where proof.row_hash=current_hash and proof.operation<>'DELETE'
    ) then matched:=false; exit; end if;
  end loop;
  select max(a.anchored_at) into anchored from sectalk_private.st_v6_audit_anchors a;
  return jsonb_build_object('state',case
    when jsonb_array_length(p_rows)=0 then 'empty' when matched then 'matched' else 'unavailable' end,
    'last_local_checkpoint',anchored,'can_export',sectalk_private.st_v6_holds_access(p_workspace)='verified');
end $$;

create or replace function public.st_v6_record_audit_export(p_workspace uuid)
returns void language plpgsql security definer set search_path='' as $$
begin
  if public.st_v7_sensitive_action_status('export')<>'verified' then
    raise exception 'Fresh authenticator proof is required for this export' using errcode='42501';
  end if;
  if sectalk_private.st_v6_holds_access(p_workspace)<>'verified' then
    raise exception 'Verified workspace audit export access is required' using errcode='42501';
  end if;
  if not sectalk_private.st_v8_audit_sso_allows(p_workspace) then
    raise exception 'Sign in through your workspace provider to access audit logs' using errcode='42501';
  end if;
  perform sectalk_private.limit_action('v6_audit_export',10);
  insert into public.st_v2_workspace_audit(workspace_id,actor,event)
    values(p_workspace,auth.uid(),'workspace.audit_export_requested');
end $$;

commit;
