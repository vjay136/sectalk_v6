begin;
create table sectalk_private.st_v7_custom_role_heads (
  workspace uuid not null references public.st_v2_workspaces(id) on delete cascade,
  id uuid not null,
  revision integer not null check(revision between 1 and 100),
  primary key(workspace,id)
);
create table sectalk_private.st_v7_custom_role_versions (
  workspace uuid not null,
  role_id uuid not null,
  revision integer not null,
  name text not null check(char_length(name) between 1 and 64),
  target uuid not null,
  permissions text[] not null,
  device text not null check(device in ('any','trusted','managed')),
  risk_max integer check(risk_max between 0 and 100),
  utc_start integer check(utc_start between 0 and 23),
  utc_end integer check(utc_end between 0 and 24),
  enabled boolean not null,
  recorded_at timestamptz not null default clock_timestamp(),
  primary key(workspace,role_id,revision),
  foreign key(workspace,role_id) references sectalk_private.st_v7_custom_role_heads on delete cascade,
  foreign key(workspace,target) references public.st_v6_workspace_groups(workspace_id,id) on delete cascade
);
create table sectalk_private.st_v7_custom_role_assignments (
  workspace uuid not null,
  role_id uuid not null,
  account uuid not null,
  primary key(workspace,role_id,account),
  foreign key(workspace,role_id) references sectalk_private.st_v7_custom_role_heads on delete cascade,
  foreign key(workspace,account) references public.st_v2_members(workspace_id,user_id) on delete cascade
);
create index st_v7_custom_roles_for_account on sectalk_private.st_v7_custom_role_assignments(workspace,account);
alter table sectalk_private.st_v7_custom_role_heads enable row level security;
alter table sectalk_private.st_v7_custom_role_versions enable row level security;
alter table sectalk_private.st_v7_custom_role_assignments enable row level security;
revoke all on sectalk_private.st_v7_custom_role_heads,sectalk_private.st_v7_custom_role_versions,
  sectalk_private.st_v7_custom_role_assignments from public,anon,authenticated,service_role;

create function sectalk_private.st_v7_custom_role_conditions(rule sectalk_private.st_v7_custom_role_versions,
  actual_device text,actual_risk integer,hour_utc integer)
returns text[] language sql stable set search_path='' as $$
  select array_remove(array[
    case when not rule.enabled then 'disabled' end,
    case when rule.device='trusted' and coalesce(actual_device,'') not in ('trusted','managed')
      or rule.device='managed' and actual_device is distinct from 'managed' then 'device' end,
    case when rule.risk_max is not null and (actual_risk is null or actual_risk>rule.risk_max) then 'risk' end,
    case when rule.utc_start is not null and not coalesce(case when rule.utc_start<rule.utc_end
      then hour_utc>=rule.utc_start and hour_utc<rule.utc_end
      else hour_utc>=rule.utc_start or hour_utc<rule.utc_end end,false) then 'time' end
  ],null);
$$;

create function public.st_v7_custom_group_access(p_workspace uuid,p_group uuid)
returns text[] language plpgsql stable security definer set search_path='' as $$
declare actor uuid:=auth.uid(); device_state text; risk_score integer; allowed text[];
begin
  if sectalk_private.st_v2_role(p_workspace,actor) is distinct from 'member'
    or public.st_v7_current_session_valid() is not true or public.st_v7_account_under_lockdown()
    or public.st_v7_login_risk_status() is distinct from 'clear' or not sectalk_private.st_v2_active(actor)
    or not exists(select 1 from public.st_v6_workspace_groups g where g.workspace_id=p_workspace and g.id=p_group
      and g.kind in ('group','team','department')) then return '{}'; end if;
  select d.state,r.score into device_state,risk_score from auth.sessions s
    left join sectalk_private.st_v7_device_sessions b on b.session_id=s.id and b.owner=s.user_id
    left join sectalk_private.st_v7_devices d on (d.owner,d.id)=(b.owner,b.device_id)
    left join sectalk_private.st_v7_session_scores r on r.session_id=s.id and r.user_id=s.user_id
    where s.user_id=actor and s.id=(auth.jwt()->>'session_id')::uuid;
  select array_agg(distinct perm) into allowed
    from sectalk_private.st_v7_custom_role_assignments a
    join sectalk_private.st_v7_custom_role_heads h on (h.workspace,h.id)=(a.workspace,a.role_id)
    join sectalk_private.st_v7_custom_role_versions v on (v.workspace,v.role_id,v.revision)=(h.workspace,h.id,h.revision)
    cross join lateral unnest(v.permissions) perm
    where a.workspace=p_workspace and a.account=actor and v.target=p_group
      and cardinality(sectalk_private.st_v7_custom_role_conditions(v,device_state,risk_score,
        extract(hour from statement_timestamp() at time zone 'UTC')::integer))=0;
  return coalesce(allowed,'{}');
end
$$;

create function public.st_v7_workspace_custom_roles(p_workspace uuid,p_action text default 'read',
  p_role uuid default null,p_revision integer default null,p_definition jsonb default null,p_account uuid default null)
returns jsonb language plpgsql security definer set search_path='' as $$
declare access text:=sectalk_private.st_v7_file_egress_operator(p_workspace);
  current_revision integer; def sectalk_private.st_v7_custom_role_versions; simulation text[]; stamp integer;
begin
  if access is distinct from 'verified' then return jsonb_build_object('access',access); end if;
  if p_action is distinct from 'read' then
    perform sectalk_private.limit_action('v7_custom_roles',20);
    perform 1 from public.st_v2_workspaces where id=p_workspace for update;
    if not found or sectalk_private.st_v7_file_egress_operator(p_workspace) is distinct from 'verified' then
      raise exception using errcode='42501',message='Fresh workspace owner verification required';
    end if;
    select h.revision into current_revision from sectalk_private.st_v7_custom_role_heads h where h.workspace=p_workspace and h.id=p_role;
    if p_role is null or p_revision is distinct from coalesce(current_revision,0) then
      raise exception using errcode='PT409',message='Role revision changed. Refresh before trying again';
    end if;
    if p_action='save' then
      if jsonb_typeof(p_definition) is distinct from 'object' or octet_length(p_definition::text)>1024
        or (p_definition->>'target') !~* '^[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}$'
        or jsonb_typeof(p_definition->'permissions') is distinct from 'array'
        or jsonb_typeof(p_definition->'enabled') is distinct from 'boolean' then
        raise exception using errcode='22023',message='Enter a valid group-scoped role';
      end if;
      def.name:=btrim(p_definition->>'name'); def.target:=(p_definition->>'target')::uuid;
      def.device:=p_definition->>'device'; def.enabled:=(p_definition->>'enabled')::boolean;
      def.risk_max:=(p_definition->>'risk_max')::integer;
      def.utc_start:=(p_definition->>'utc_start')::integer; def.utc_end:=(p_definition->>'utc_end')::integer;
      select array_agg(distinct p) into def.permissions from jsonb_array_elements_text(p_definition->'permissions') p;
      if def.name is null or char_length(def.name) not between 1 and 64 or def.name~'[[:cntrl:]]'
        or not exists(select 1 from public.st_v6_workspace_groups g where (g.workspace_id,g.id)=(p_workspace,def.target)
          and g.kind in ('group','team','department'))
        or coalesce(cardinality(def.permissions),0) not between 1 and 3
        or not def.permissions<@array['rename','archive','restore']::text[]
        or coalesce(def.device,'') not in ('any','trusted','managed')
        or (def.risk_max is not null and def.risk_max not between 0 and 100)
        or (def.utc_start is null)<>(def.utc_end is null)
        or (def.utc_start is not null and (def.utc_start not between 0 and 23 or def.utc_end not between 0 and 24 or def.utc_start=def.utc_end))
        or coalesce(current_revision,0)>=100
        or (current_revision is null and (select count(*) from sectalk_private.st_v7_custom_role_heads where workspace=p_workspace)>=25)
        then raise exception using errcode='22023',message='Enter supported permissions, a group and valid ABAC conditions';
      end if;
      stamp:=coalesce(current_revision,0)+1;
      insert into sectalk_private.st_v7_custom_role_heads values(p_workspace,p_role,stamp)
        on conflict(workspace,id) do update set revision=excluded.revision;
      insert into sectalk_private.st_v7_custom_role_versions(workspace,role_id,revision,name,target,permissions,device,risk_max,utc_start,utc_end,enabled)
        values(p_workspace,p_role,stamp,def.name,def.target,def.permissions,def.device,def.risk_max,def.utc_start,def.utc_end,def.enabled);
    elsif p_action in ('assign','revoke') and current_revision is not null and p_account is not null then
      if p_action='assign' then
        perform 1 from public.st_v2_members where workspace_id=p_workspace and user_id=p_account for no key update;
        if sectalk_private.st_v2_role(p_workspace,p_account) is distinct from 'member' or not sectalk_private.st_v2_active(p_account)
          then raise exception using errcode='42501',message='Assign only to an active ordinary workspace member'; end if;
        insert into sectalk_private.st_v7_custom_role_assignments values(p_workspace,p_role,p_account) on conflict do nothing;
      else delete from sectalk_private.st_v7_custom_role_assignments
          where workspace=p_workspace and role_id=p_role and account=p_account; end if;
    elsif p_action='simulate' and current_revision is not null then
      select * into def from sectalk_private.st_v7_custom_role_versions v
        where (v.workspace,v.role_id,v.revision)=(p_workspace,p_role,current_revision);
      simulation:=sectalk_private.st_v7_custom_role_conditions(def,p_definition->>'device',(p_definition->>'risk')::integer,
        (p_definition->>'hour')::integer);
      if not coalesce(p_definition->>'permission'=any(def.permissions),false) then simulation:=simulation||'permission'::text; end if;
      return jsonb_build_object('access','verified','allowed',cardinality(simulation)=0,'conditions',simulation);
    else raise exception using errcode='22023',message='Choose a supported role operation'; end if;
    insert into public.st_v2_workspace_audit(workspace_id,actor,event,target)
      values(p_workspace,auth.uid(),'workspace.custom_role_'||p_action,p_role);
  end if;
  return jsonb_build_object('access','verified','roles',coalesce((select jsonb_agg(jsonb_build_object(
    'id',h.id,'revision',h.revision,'name',v.name,'target',v.target,'permissions',v.permissions,
    'device',v.device,'risk_max',v.risk_max,'utc_start',v.utc_start,'utc_end',v.utc_end,'enabled',v.enabled,
    'assignments',coalesce((select jsonb_agg(a.account order by a.account) from sectalk_private.st_v7_custom_role_assignments a
      where (a.workspace,a.role_id)=(h.workspace,h.id)),'[]'),
    'history',coalesce((select jsonb_agg(jsonb_build_object('revision',older.revision,'recordedAt',older.recorded_at) order by older.revision desc)
      from sectalk_private.st_v7_custom_role_versions older where (older.workspace,older.role_id)=(h.workspace,h.id)),'[]')
  ) order by v.name,h.id) from sectalk_private.st_v7_custom_role_heads h
    join sectalk_private.st_v7_custom_role_versions v on (v.workspace,v.role_id,v.revision)=(h.workspace,h.id,h.revision)
    where h.workspace=p_workspace),'[]'));
end
$$;

alter function public.st_v6_workspace_group_change(uuid,uuid,text,text,text,uuid) rename to st_v7_builtin_group_change;
revoke all on function public.st_v7_builtin_group_change(uuid,uuid,text,text,text,uuid) from public,anon,authenticated,service_role;
create function public.st_v6_workspace_group_change(p_workspace uuid,p_id uuid,p_action text,p_name text default null,
  p_description text default null,p_user uuid default null)
returns void language plpgsql security definer set search_path='' as $$
declare item public.st_v6_workspace_groups; actor uuid:=auth.uid(); name_value text:=btrim(p_name);
  summary text:=btrim(coalesce(p_description,''));
begin
  if sectalk_private.st_v2_role(p_workspace,actor) in ('owner','admin') then
    perform public.st_v7_builtin_group_change(p_workspace,p_id,p_action,p_name,p_description,p_user);
    return;
  end if;
  perform sectalk_private.limit_action('v6_group_change',30);
  perform 1 from public.st_v2_workspaces where id=p_workspace for update;
  if not found or not coalesce(p_action=any(public.st_v7_custom_group_access(p_workspace,p_id)),false) then
    raise exception using errcode='42501',message='Workspace group action unavailable';
  end if;
  select * into item from public.st_v6_workspace_groups where workspace_id=p_workspace and id=p_id;
  if p_action='rename' and item.archived_at is null then
    if name_value is null or char_length(name_value) not between 1 and 80 or char_length(summary)>500 then
      raise exception using errcode='22023',message='Choose a valid name and description'; end if;
    update public.st_v6_workspace_groups set name=name_value,description=summary
      where workspace_id=p_workspace and id=p_id and (name,description) is distinct from (name_value,summary);
  elsif p_action='archive' then
    update public.st_v6_workspace_groups set archived_at=clock_timestamp()
      where workspace_id=p_workspace and id=p_id and archived_at is null;
  elsif p_action='restore' then
    update public.st_v6_workspace_groups set archived_at=null where workspace_id=p_workspace and id=p_id and archived_at is not null;
  else raise exception using errcode='42501',message='Workspace group action unavailable'; end if;
  if found then insert into public.st_v2_workspace_audit(workspace_id,actor,event,target)
    values(p_workspace,actor,'group.'||p_action,p_id); end if;
end
$$;

create function sectalk_private.st_v7_revoke_role_on_roster_change()
returns trigger language plpgsql security definer set search_path='' as $$
begin
  if new.suspended_at is not null or new.role<>'member' then
    delete from sectalk_private.st_v7_custom_role_assignments where workspace=new.workspace_id and account=new.user_id;
  end if;
  return null;
end
$$;
create trigger st_v7_custom_role_roster after update of role,suspended_at on public.st_v2_members
  for each row execute function sectalk_private.st_v7_revoke_role_on_roster_change();

revoke all on function sectalk_private.st_v7_custom_role_conditions(sectalk_private.st_v7_custom_role_versions,text,integer,integer),
  sectalk_private.st_v7_revoke_role_on_roster_change(),public.st_v7_custom_group_access(uuid,uuid),
  public.st_v7_workspace_custom_roles(uuid,text,uuid,integer,jsonb,uuid),
  public.st_v6_workspace_group_change(uuid,uuid,text,text,text,uuid)
  from public,anon,authenticated,service_role;
grant execute on function public.st_v7_custom_group_access(uuid,uuid),public.st_v7_workspace_custom_roles(uuid,text,uuid,integer,jsonb,uuid),
  public.st_v6_workspace_group_change(uuid,uuid,text,text,text,uuid) to authenticated;
commit;
