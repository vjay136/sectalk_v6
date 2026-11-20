begin;
alter table sectalk_private.st_v7_custom_role_versions
  drop constraint st_v7_custom_role_versions_workspace_target_fkey,
  add column scope_type text not null default 'group' check(scope_type in ('group','room','file'));

create table sectalk_private.st_v7_file_custom_role_required (
  workspace uuid not null,
  file uuid not null,
  primary key(workspace,file),
  foreign key(workspace,file) references sectalk_private.st_v6_workspace_files(workspace,id) on delete cascade
);
alter table sectalk_private.st_v7_file_custom_role_required enable row level security;
revoke all on sectalk_private.st_v7_file_custom_role_required from public,anon,authenticated,service_role;

create function sectalk_private.st_v7_custom_role_target(p_workspace uuid,p_scope text,p_target uuid)
returns boolean language sql stable set search_path='' as $$
  select case p_scope
    when 'group' then exists(select 1 from public.st_v6_workspace_groups g
      where (g.workspace_id,g.id)=(p_workspace,p_target) and g.kind in ('group','team','department'))
    when 'room' then exists(select 1 from public.st_v6_rooms r where (r.workspace_id,r.id)=(p_workspace,p_target)
      and r.kind in ('public','private') and r.template<>'class' and not r.archived and r.classification<>'restricted')
    when 'file' then exists(select 1 from sectalk_private.st_v6_workspace_files f
      where (f.workspace,f.id)=(p_workspace,p_target) and f.published_at is not null and f.deleted_at is null)
    else false end;
$$;

create function sectalk_private.st_v7_custom_scope_access(p_workspace uuid,p_scope text,p_target uuid)
returns text[] language plpgsql stable security definer set search_path='' as $$
declare actor uuid:=auth.uid(); device_state text; risk_score integer; allowed text[];
begin
  if sectalk_private.st_v2_role(p_workspace,actor) is distinct from 'member'
    or public.st_v7_current_session_valid() is not true or public.st_v7_account_under_lockdown()
    or public.st_v7_login_risk_status() is distinct from 'clear' or not sectalk_private.st_v2_active(actor)
    or not sectalk_private.st_v7_custom_role_target(p_workspace,p_scope,p_target)
    or (p_scope='room' and sectalk_private.st_v6_room_role(p_target,actor) is distinct from 'member')
    then return '{}'; end if;
  select d.state,r.score into device_state,risk_score from auth.sessions s
    left join sectalk_private.st_v7_device_sessions b on b.session_id=s.id and b.owner=s.user_id
    left join sectalk_private.st_v7_devices d on (d.owner,d.id)=(b.owner,b.device_id)
    left join sectalk_private.st_v7_session_scores r on r.session_id=s.id and r.user_id=s.user_id
    where s.user_id=actor and s.id=(auth.jwt()->>'session_id')::uuid;
  if device_state='blocked' then return '{}'; end if;
  select array_agg(distinct perm) into allowed
    from sectalk_private.st_v7_custom_role_assignments a
    join sectalk_private.st_v7_custom_role_heads h on (h.workspace,h.id)=(a.workspace,a.role_id)
    join sectalk_private.st_v7_custom_role_versions v on (v.workspace,v.role_id,v.revision)=(h.workspace,h.id,h.revision)
    cross join lateral unnest(v.permissions) perm
    where a.workspace=p_workspace and a.account=actor and v.target=p_target and v.scope_type=p_scope
      and cardinality(sectalk_private.st_v7_custom_role_conditions(v,device_state,risk_score,
        extract(hour from statement_timestamp() at time zone 'UTC')::integer))=0;
  return coalesce(allowed,'{}');
end
$$;

create or replace function public.st_v7_custom_group_access(p_workspace uuid,p_group uuid)
returns text[] language sql stable security definer set search_path='' as $$
  select sectalk_private.st_v7_custom_scope_access(p_workspace,'group',p_group);
$$;
create function public.st_v7_custom_room_access(p_room uuid)
returns text[] language sql stable security definer set search_path='' as $$
  select coalesce((select sectalk_private.st_v7_custom_scope_access(r.workspace_id,'room',r.id)
    from public.st_v6_rooms r where r.id=p_room),'{}');
$$;

create function public.st_v7_custom_role_targets(p_workspace uuid)
returns jsonb language sql stable security definer set search_path='' as $$
  select case when sectalk_private.st_v7_file_egress_operator(p_workspace)='verified' then coalesce((
    select jsonb_agg(to_jsonb(t) order by scope,name) from (
      (select 'group' as scope,g.id,g.name from public.st_v6_workspace_groups g
        where g.workspace_id=p_workspace and g.kind in ('group','team','department') order by g.name limit 250)
      union all
      (select 'room',r.id,r.name from public.st_v6_rooms r
        where r.workspace_id=p_workspace and sectalk_private.st_v7_custom_role_target(p_workspace,'room',r.id)
        and sectalk_private.st_v6_room_role(r.id,auth.uid()) in ('owner','moderator') order by r.name limit 100)
      union all
      (select 'file',f.id,f.filename from sectalk_private.st_v6_workspace_files f
        where f.workspace=p_workspace and f.published_at is not null and f.deleted_at is null order by f.filename limit 250)
    ) t),'[]') else '[]' end;
$$;

create or replace function public.st_v7_workspace_custom_roles(p_workspace uuid,p_action text default 'read',
  p_role uuid default null,p_revision integer default null,p_definition jsonb default null,p_account uuid default null)
returns jsonb language plpgsql security definer set search_path='' as $$
declare access text:=sectalk_private.st_v7_file_egress_operator(p_workspace);
  current_revision integer; def sectalk_private.st_v7_custom_role_versions; simulation text[]; stamp integer; previous_scope text; previous_target uuid;
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
      def.scope_type:=coalesce(p_definition->>'scope_type','group');
      if current_revision is not null then
        select v.scope_type,v.target into previous_scope,previous_target from sectalk_private.st_v7_custom_role_versions v
          where (v.workspace,v.role_id,v.revision)=(p_workspace,p_role,current_revision);
      end if;
      def.name:=btrim(p_definition->>'name'); def.target:=(p_definition->>'target')::uuid;
      def.device:=p_definition->>'device'; def.enabled:=(p_definition->>'enabled')::boolean;
      def.risk_max:=(p_definition->>'risk_max')::integer;
      def.utc_start:=(p_definition->>'utc_start')::integer; def.utc_end:=(p_definition->>'utc_end')::integer;
      select array_agg(distinct p) into def.permissions from jsonb_array_elements_text(p_definition->'permissions') p;
      if def.name is null or char_length(def.name) not between 1 and 64 or def.name~'[[:cntrl:]]'
        or not sectalk_private.st_v7_custom_role_target(p_workspace,def.scope_type,def.target)
        or (current_revision is not null and (def.scope_type,def.target) is distinct from (previous_scope,previous_target))
        or (def.scope_type='room' and sectalk_private.st_v6_room_role(def.target,auth.uid()) not in ('owner','moderator'))
        or (def.scope_type='room' and sectalk_private.st_v6_room_role(def.target,auth.uid()) is null)
        or coalesce(cardinality(def.permissions),0) not between 1 and 3
        or not (def.permissions<@(case def.scope_type when 'group' then array['rename','archive','restore']::text[]
          when 'room' then array['room.pin','room.unpin','room.slow']::text[]
          when 'file' then array['file.download','file.share']::text[] else '{}'::text[] end))
        or coalesce(def.device,'') not in ('any','trusted','managed')
        or (def.risk_max is not null and def.risk_max not between 0 and 100)
        or (def.utc_start is null)<>(def.utc_end is null)
        or (def.utc_start is not null and (def.utc_start not between 0 and 23 or def.utc_end not between 0 and 24 or def.utc_start=def.utc_end))
        or coalesce(current_revision,0)>=100
        or (current_revision is null and (select count(*) from sectalk_private.st_v7_custom_role_heads where workspace=p_workspace)>=25)
        then raise exception using errcode='22023',message='Enter supported permissions, an eligible resource and valid ABAC conditions';
      end if;
      stamp:=coalesce(current_revision,0)+1;
      insert into sectalk_private.st_v7_custom_role_heads values(p_workspace,p_role,stamp)
        on conflict(workspace,id) do update set revision=excluded.revision;
      insert into sectalk_private.st_v7_custom_role_versions(workspace,role_id,revision,name,target,permissions,device,risk_max,utc_start,utc_end,enabled,scope_type)
        values(p_workspace,p_role,stamp,def.name,def.target,def.permissions,def.device,def.risk_max,def.utc_start,def.utc_end,def.enabled,def.scope_type);
    elsif p_action in ('assign','revoke') and current_revision is not null and p_account is not null then
      if p_action='assign' then
        perform 1 from public.st_v2_members where workspace_id=p_workspace and user_id=p_account for no key update;
        if sectalk_private.st_v2_role(p_workspace,p_account) is distinct from 'member' or not sectalk_private.st_v2_active(p_account)
          then raise exception using errcode='42501',message='Assign only to an active ordinary workspace member'; end if;
        insert into sectalk_private.st_v7_custom_role_assignments values(p_workspace,p_role,p_account) on conflict do nothing;
      else delete from sectalk_private.st_v7_custom_role_assignments
          where workspace=p_workspace and role_id=p_role and account=p_account; end if;
    elsif p_action='gate' and current_revision is not null and jsonb_typeof(p_definition->'required')='boolean' then
      select * into def from sectalk_private.st_v7_custom_role_versions v
        where (v.workspace,v.role_id,v.revision)=(p_workspace,p_role,current_revision);
      if def.scope_type<>'file' or not sectalk_private.st_v7_custom_role_target(p_workspace,'file',def.target) then
        raise exception using errcode='42501',message='Select an eligible workspace file';
      end if;
      if (p_definition->>'required')::boolean then
        insert into sectalk_private.st_v7_file_custom_role_required values(p_workspace,def.target) on conflict do nothing;
      else
        delete from sectalk_private.st_v7_file_custom_role_required where workspace=p_workspace and file=def.target;
      end if;
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
    'id',h.id,'revision',h.revision,'name',v.name,'target',v.target,'scope_type',v.scope_type,'permissions',v.permissions,
    'file_gate',v.scope_type='file' and exists(select 1 from sectalk_private.st_v7_file_custom_role_required f
      where (f.workspace,f.file)=(v.workspace,v.target)),
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


alter function public.st_v6_room_settings(uuid,text,uuid,integer) rename to st_v7_builtin_room_settings;
revoke all on function public.st_v7_builtin_room_settings(uuid,text,uuid,integer) from public,anon,authenticated,service_role;
create function public.st_v6_room_settings(p_room uuid,p_action text,p_post uuid default null,p_seconds integer default 0)
returns void language plpgsql security definer set search_path='' as $$
declare actor uuid:=auth.uid(); workspace_id_value uuid;
begin
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

alter function public.st_v7_explain_file_egress(text,uuid,uuid,text) rename to st_v7_builtin_file_egress;
revoke all on function public.st_v7_builtin_file_egress(text,uuid,uuid,text) from public,anon,authenticated,service_role;
create function public.st_v7_explain_file_egress(p_scope_type text,p_scope uuid,p_file uuid,p_operation text)
returns jsonb language plpgsql stable security definer set search_path='' as $$
declare baseline jsonb;
begin
  baseline:=public.st_v7_builtin_file_egress(p_scope_type,p_scope,p_file,p_operation);
  if baseline->>'allowed'='true' and p_scope_type='workspace'
    and sectalk_private.st_v2_role(p_scope,auth.uid())='member'
    and exists(select 1 from sectalk_private.st_v7_file_custom_role_required f where (f.workspace,f.file)=(p_scope,p_file))
    and not coalesce(('file.'||p_operation)=any(sectalk_private.st_v7_custom_scope_access(p_scope,'file',p_file)),false) then
    return jsonb_build_object('allowed',false,'reasons',jsonb_build_array('custom_role_required'));
  end if;
  return baseline;
end
$$;
revoke all on function sectalk_private.st_v7_custom_role_target(uuid,text,uuid),
  sectalk_private.st_v7_custom_scope_access(uuid,text,uuid),public.st_v7_custom_role_targets(uuid),public.st_v7_custom_room_access(uuid),
  public.st_v6_room_settings(uuid,text,uuid,integer),public.st_v7_explain_file_egress(text,uuid,uuid,text)
  from public,anon,authenticated,service_role;
grant execute on function public.st_v7_custom_role_targets(uuid),public.st_v7_custom_room_access(uuid),
  public.st_v6_room_settings(uuid,text,uuid,integer),public.st_v7_explain_file_egress(text,uuid,uuid,text) to authenticated;
commit;
