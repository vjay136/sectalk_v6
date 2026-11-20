begin;

create table sectalk_private.st_v7_file_egress_policies (
  workspace uuid primary key references public.st_v2_workspaces on delete cascade,
  revision integer not null check (revision>0),
  policy jsonb not null check (jsonb_typeof(policy)='object' and octet_length(policy::text)<=1024)
);
alter table sectalk_private.st_v7_file_egress_policies enable row level security;
revoke all on sectalk_private.st_v7_file_egress_policies from public,anon,authenticated,service_role;

create function sectalk_private.st_v7_file_egress_operator(p_workspace uuid)
returns text language sql stable security definer set search_path='' as $$
  select case when sectalk_private.st_v2_role(p_workspace,auth.uid()) is distinct from 'owner'
    or public.st_v7_current_session_valid() is not true
    or sectalk_private.st_v2_active(auth.uid()) is not true
    or public.st_v7_account_under_lockdown() then 'none'
    when sectalk_private.st_v7_admin_fresh() is not true then 'mfa' else 'verified' end;
$$;

create function public.st_v7_file_egress_policy(p_workspace uuid)
returns jsonb language sql stable security definer set search_path='' as $$
  select case o.access when 'none' then jsonb_build_object('access','none')
    when 'mfa' then jsonb_build_object('access','mfa')
    else jsonb_build_object('access','verified','revision',coalesce(p.revision,0),
      'policy',coalesce(p.policy,'{"mode":"inherit"}'::jsonb)) end
  from (select sectalk_private.st_v7_file_egress_operator(p_workspace) access) o
  left join sectalk_private.st_v7_file_egress_policies p on p.workspace=p_workspace;
$$;

create function public.st_v7_save_file_egress_policy(p_workspace uuid,p_revision integer,p_policy jsonb)
returns integer language plpgsql security definer set search_path='' as $$
declare mode text:=p_policy->>'mode';
  next_revision integer;
begin
  if sectalk_private.st_v7_file_egress_operator(p_workspace)<>'verified' then
    raise exception 'Fresh workspace owner verification required' using errcode='42501';
  end if;
  if p_revision is null or p_revision<0 or jsonb_typeof(p_policy) is distinct from 'object'
    or octet_length(p_policy::text)>1024 or mode is null or mode not in ('inherit','require','block') then
    raise exception 'Choose a supported file egress policy' using errcode='22023';
  end if;
  if exists(select 1 from jsonb_each(p_policy) j
    where (case j.key
      when 'mode' then jsonb_typeof(j.value)='string'
      when 'device' then jsonb_typeof(j.value)='string' and j.value#>>'{}' in ('trusted','managed')
      when 'risk_max' then jsonb_typeof(j.value)='number' and j.value#>>'{}' ~ '^([0-9]|[1-9][0-9]|100)$'
      when 'network' then jsonb_typeof(j.value)='string' and j.value#>>'{}' like '%/%'
      when 'utc_start' then jsonb_typeof(j.value)='number' and j.value#>>'{}' ~ '^([0-9]|1[0-9]|2[0-3])$'
      when 'utc_end' then jsonb_typeof(j.value)='number' and j.value#>>'{}' ~ '^([0-9]|1[0-9]|2[0-3])$'
      when 'classification_max' then jsonb_typeof(j.value)='string' and j.value#>>'{}' in ('public','internal','confidential','restricted')
      when 'tenant_type' then jsonb_typeof(j.value)='string' and exists(
        select 1 from public.st_v6_workspace_templates t where t.id=j.value#>>'{}')
      else false end) is not true)
    or (mode='require' and p_policy-'mode'='{}'::jsonb)
    or (mode<>'require' and p_policy-'mode'<>'{}'::jsonb)
    or (p_policy?'utc_start')<>(p_policy?'utc_end')
    or (p_policy->>'utc_start')=(p_policy->>'utc_end') then
    raise exception 'Choose recognized attributes and valid policy values' using errcode='22023';
  end if;
  if p_policy?'network' then
    p_policy:=jsonb_set(p_policy,'{network}',to_jsonb((p_policy->>'network')::cidr::text));
  end if;
  perform sectalk_private.limit_action('v7_file_egress_policy',12);
  if p_revision=0 then
    insert into sectalk_private.st_v7_file_egress_policies(workspace,revision,policy)
      values(p_workspace,1,p_policy) on conflict(workspace) do nothing returning revision into next_revision;
  else
    update sectalk_private.st_v7_file_egress_policies set policy=p_policy,revision=p_revision+1
      where workspace=p_workspace and revision=p_revision returning revision into next_revision;
  end if;
  if next_revision is null then raise exception 'Policy changed. Reload to review its current settings.' using errcode='PT409'; end if;
  insert into public.st_v2_workspace_audit(workspace_id,actor,event,target)
    values(p_workspace,auth.uid(),'workspace.file_egress_'||mode,p_workspace);
  return next_revision;
end $$;

create function public.st_v7_explain_file_egress(p_scope_type text,p_scope uuid,p_file uuid,p_operation text)
returns jsonb language plpgsql stable security definer set search_path='' as $$
declare
  actor uuid:=auth.uid();
  workspace_key uuid;
  classification text;
  tenant_type text;
  device_state text;
  risk_score integer;
  session_ip inet;
  rules jsonb;
  ver integer;
  hour_utc integer;
  start_hour integer;
  end_hour integer;
  failures text[]:='{}';
  unavailable constant jsonb:='{"allowed":false,"reasons":["access_unavailable"]}';
begin
  if p_operation is null or p_scope_type is null or p_file is null
    or p_operation not in ('download','share') or p_scope_type not in ('workspace','room')
    or (p_scope_type='room' and p_operation<>'download')
    or public.st_v7_current_session_valid() is not true or public.st_v7_account_under_lockdown()
    or sectalk_private.st_v2_active(actor) is not true then return unavailable; end if;
  if p_scope_type='workspace' then
    if sectalk_private.st_v2_role(p_scope,actor) is null then return unavailable; end if;
    select f.workspace,'internal' into workspace_key,classification
      from sectalk_private.st_v6_workspace_files f where f.workspace=p_scope and f.id=p_file
        and f.published_at is not null and f.deleted_at is null;
  else
    if sectalk_private.st_v6_room_role(p_scope,actor) is null then return unavailable; end if;
    select r.workspace_id,r.classification into workspace_key,classification
      from public.st_v6_rooms r join sectalk_private.st_v6_room_files f on f.room=r.id and f.workspace=r.workspace_id
      where r.id=p_scope and f.id=p_file and f.published_at is not null and f.deleted_at is null;
  end if;
  if workspace_key is null then return unavailable; end if;

  select p.policy,p.revision into rules,ver from sectalk_private.st_v7_file_egress_policies p where p.workspace=workspace_key;
  if rules is null or rules->>'mode'='inherit' then
    return jsonb_build_object('allowed',true,'revision',coalesce(ver,0),'reasons',jsonb_build_array('inherited_access'));
  end if;
  if rules->>'mode'='block' then
    return jsonb_build_object('allowed',false,'revision',ver,'reasons',jsonb_build_array('tenant_block'));
  end if;

  select sectalk_private.st_v7_normalize_network_address(s.ip),score.score,d.state
    into session_ip,risk_score,device_state
    from auth.sessions s
    left join sectalk_private.st_v7_session_scores score on score.session_id=s.id and score.user_id=s.user_id
    left join sectalk_private.st_v7_device_sessions b on b.session_id=s.id and b.owner=s.user_id
    left join sectalk_private.st_v7_devices d on d.id=b.device_id and d.owner=s.user_id
    where s.id=(auth.jwt()->>'session_id')::uuid and s.user_id=actor;
  select p.workspace_type into tenant_type from public.st_v6_workspace_policy p where p.workspace_id=workspace_key;

  if rules?'device' and not coalesce(device_state='managed' or (device_state='trusted' and rules->>'device'='trusted'),false) then
    failures:=array_append(failures,'device_trust');
  end if;
  if rules?'risk_max' and (risk_score is null or risk_score>(rules->>'risk_max')::integer) then
    failures:=array_append(failures,'session_risk');
  end if;
  if rules?'network' and not coalesce(session_ip <<= (rules->>'network')::cidr,false) then
    failures:=array_append(failures,'session_network');
  end if;
  if rules?'utc_start' then
    hour_utc:=extract(hour from statement_timestamp() at time zone 'UTC');
    start_hour:=(rules->>'utc_start')::integer;
    end_hour:=(rules->>'utc_end')::integer;
    if not (case when start_hour<end_hour then hour_utc>=start_hour and hour_utc<end_hour
      else hour_utc>=start_hour or hour_utc<end_hour end) then
      failures:=array_append(failures,'utc_window');
    end if;
  end if;
  if rules?'classification_max' and array_position(array['public','internal','confidential','restricted'],classification)
      >array_position(array['public','internal','confidential','restricted'],rules->>'classification_max') is not false then
    failures:=array_append(failures,'classification');
  end if;
  if rules?'tenant_type' and tenant_type is distinct from rules->>'tenant_type' then
    failures:=array_append(failures,'tenant_type');
  end if;
  return jsonb_build_object('allowed',cardinality(failures)=0,'revision',ver,'reasons',
    case when cardinality(failures)=0 then array['requirements_met'] else failures end);
end $$;

revoke all on function sectalk_private.st_v7_file_egress_operator(uuid),public.st_v7_file_egress_policy(uuid),
  public.st_v7_save_file_egress_policy(uuid,integer,jsonb),public.st_v7_explain_file_egress(text,uuid,uuid,text)
  from public,anon,authenticated,service_role;
grant execute on function public.st_v7_file_egress_policy(uuid),public.st_v7_save_file_egress_policy(uuid,integer,jsonb),
  public.st_v7_explain_file_egress(text,uuid,uuid,text) to authenticated;
notify pgrst,'reload schema';
commit;
