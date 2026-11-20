begin;
create table sectalk_private.st_v7_policy_snapshots (
  workspace uuid not null references public.st_v2_workspaces(id) on delete cascade,
  domain text not null check(domain in ('messaging','files','calls','ai','retention','sharing','dlp','external')),
  revision integer not null check(revision>=0),
  settings jsonb not null,
  recorded_at timestamptz not null default clock_timestamp(),
  primary key(workspace,domain,revision)
);
alter table sectalk_private.st_v7_policy_snapshots enable row level security;
revoke all on sectalk_private.st_v7_policy_snapshots from public,anon,authenticated,service_role;

create function sectalk_private.st_v7_policy_shape(domain text,row_data jsonb)
returns jsonb language sql immutable set search_path='' as $$
  select case domain
    when 'messaging' then jsonb_build_object('set',coalesce(row_data->>'emoji_set','all'),'limit',coalesce((row_data->>'per_person')::integer,8))
    when 'files' then jsonb_build_object('history',coalesce((row_data->>'enabled')::boolean,false))
    when 'calls' then jsonb_build_object('paused',(row_data->>'feature'='recurring_meetings') is true)
    when 'ai' then jsonb_build_object('enabled',coalesce((row_data->>'enabled')::boolean,true),
      'consent',coalesce((row_data->>'processing_consent')::boolean,true),
      'threshold',coalesce((row_data->>'advisory_threshold')::integer,1),'days',coalesce((row_data->>'retention_days')::integer,30))
    when 'retention' then jsonb_build_object('days',coalesce((row_data->>'retention_days')::integer,30))
    when 'sharing' then coalesce(row_data->'policy','{"mode":"inherit"}')
    when 'dlp' then coalesce(row_data->'rules','{"pii":"allow","phi":"allow","payment_card":"allow","credential":"allow"}')
    when 'external' then jsonb_build_object('domains',coalesce(row_data->'domains','[]'))
    end;
$$;

create function sectalk_private.st_v7_live_policy(p_workspace uuid,p_domain text)
returns jsonb language sql stable set search_path='' as $$
  select sectalk_private.st_v7_policy_shape(p_domain,case p_domain
    when 'messaging' then (select to_jsonb(p) from public.st_v6_workspace_reaction_policy p where p.workspace_id=p_workspace)
    when 'files' then (select to_jsonb(p) from sectalk_private.st_v6_workspace_file_history_policy p where p.workspace=p_workspace)
    when 'calls' then (select to_jsonb(p) from sectalk_private.st_v6_tenant_feature_pauses p where p.workspace=p_workspace and p.feature='recurring_meetings')
    when 'ai' then (select to_jsonb(p) from sectalk_private.st_v7_workspace_ai_policy p where p.workspace=p_workspace)
    when 'retention' then (select to_jsonb(p) from sectalk_private.st_v6_room_retention_policy p where p.workspace_id=p_workspace)
    when 'sharing' then (select to_jsonb(p) from sectalk_private.st_v7_file_egress_policies p where p.workspace=p_workspace)
    when 'dlp' then (select to_jsonb(p) from sectalk_private.st_v7_workspace_dlp p where p.workspace_id=p_workspace)
    when 'external' then (select to_jsonb(p) from sectalk_private.st_v6_workspace_link_policy p where p.workspace_id=p_workspace)
    end);
$$;

create function sectalk_private.st_v7_capture_policy_snapshot()
returns trigger language plpgsql security definer set search_path='' as $$
declare p_domain text:=tg_argv[0]; previous jsonb; next jsonb; target uuid; latest integer; expectation text;
  prev_row jsonb:=case when tg_op<>'INSERT' then to_jsonb(old) end;
  next_row jsonb:=case when tg_op<>'DELETE' then to_jsonb(new) end;
begin
  if p_domain='calls' and coalesce(next_row,prev_row)->>'feature' is distinct from 'recurring_meetings' then return null; end if;
  target:=(coalesce(next_row,prev_row)->>tg_argv[1])::uuid;
  if not exists(select 1 from public.st_v2_workspaces where id=target) then return null; end if;
  previous:=sectalk_private.st_v7_policy_shape(p_domain,prev_row);
  next:=sectalk_private.st_v7_policy_shape(p_domain,next_row);
  if previous is not distinct from next then return null; end if;
  perform pg_advisory_xact_lock(hashtextextended('workspace-policy:'||target::text||':'||p_domain,0));
  select coalesce(max(v.revision),0) into latest from sectalk_private.st_v7_policy_snapshots v
    where v.workspace=target and v.domain=p_domain;
  expectation:=nullif(current_setting('sectalk.adm06_expected',true),'');
  if expectation is not null and split_part(expectation,'|',1)=target::text and split_part(expectation,'|',2)=p_domain
    and split_part(expectation,'|',3)<>latest::text then
    raise exception using errcode='PT409',message='Policy changed. Refresh before updating.';
  end if;
  if latest=0 then
    insert into sectalk_private.st_v7_policy_snapshots values(target,p_domain,0,previous) on conflict do nothing;
  end if;
  insert into sectalk_private.st_v7_policy_snapshots values(target,p_domain,latest+1,next);
  return null;
end
$$;

create trigger st_v7_unified_policy_snapshot after insert or update or delete on public.st_v6_workspace_reaction_policy
  for each row execute function sectalk_private.st_v7_capture_policy_snapshot('messaging','workspace_id');
create trigger st_v7_unified_policy_snapshot after insert or update or delete on sectalk_private.st_v6_workspace_file_history_policy
  for each row execute function sectalk_private.st_v7_capture_policy_snapshot('files','workspace');
create trigger st_v7_unified_policy_snapshot after insert or update or delete on sectalk_private.st_v6_tenant_feature_pauses
  for each row execute function sectalk_private.st_v7_capture_policy_snapshot('calls','workspace');
create trigger st_v7_unified_policy_snapshot after insert or update or delete on sectalk_private.st_v7_workspace_ai_policy
  for each row execute function sectalk_private.st_v7_capture_policy_snapshot('ai','workspace');
create trigger st_v7_unified_policy_snapshot after insert or update or delete on sectalk_private.st_v6_room_retention_policy
  for each row execute function sectalk_private.st_v7_capture_policy_snapshot('retention','workspace_id');
create trigger st_v7_unified_policy_snapshot after insert or update or delete on sectalk_private.st_v7_file_egress_policies
  for each row execute function sectalk_private.st_v7_capture_policy_snapshot('sharing','workspace');
create trigger st_v7_unified_policy_snapshot after insert or update or delete on sectalk_private.st_v7_workspace_dlp
  for each row execute function sectalk_private.st_v7_capture_policy_snapshot('dlp','workspace_id');
create trigger st_v7_unified_policy_snapshot after insert or update or delete on sectalk_private.st_v6_workspace_link_policy
  for each row execute function sectalk_private.st_v7_capture_policy_snapshot('external','workspace_id');

create function sectalk_private.st_v7_apply_live_policy(p_workspace uuid,p_domain text,p_settings jsonb)
returns void language plpgsql set search_path='' as $$
declare native_revision integer; domains text[];
begin
  if jsonb_typeof(p_settings) is distinct from 'object' or octet_length(p_settings::text)>4000 then
    raise exception using errcode='22023',message='Provide valid policy settings';
  end if;
  case p_domain
    when 'messaging' then perform public.st_v6_set_workspace_reactions(p_workspace,p_settings->>'set',(p_settings->>'limit')::integer);
    when 'files' then perform public.st_v6_set_workspace_file_history_policy(p_workspace,(p_settings->>'history')::boolean);
    when 'calls' then perform public.st_v6_set_tenant_feature_pause(p_workspace,'recurring_meetings',(p_settings->>'paused')::boolean);
    when 'ai' then perform public.st_v7_workspace_ai_settings(p_workspace,(p_settings->>'enabled')::boolean,
      (p_settings->>'consent')::boolean,(p_settings->>'threshold')::integer,(p_settings->>'days')::integer);
    when 'retention' then
      if p_settings->>'days' is null then raise exception using errcode='22023',message='Choose a retention period'; end if;
      perform public.st_v6_room_retention_policy(p_workspace,(p_settings->>'days')::integer);
    when 'sharing' then
      select p.revision into native_revision from sectalk_private.st_v7_file_egress_policies p where p.workspace=p_workspace;
      perform public.st_v7_save_file_egress_policy(p_workspace,coalesce(native_revision,0),p_settings);
    when 'dlp' then
      select p.revision into native_revision from sectalk_private.st_v7_workspace_dlp p where p.workspace_id=p_workspace;
      perform public.st_v7_set_workspace_dlp(p_workspace,coalesce(native_revision,0),p_settings);
    when 'external' then
      if jsonb_typeof(p_settings->'domains') is distinct from 'array' then raise exception using errcode='22023',message='Enter an array of domains'; end if;
      select array(select jsonb_array_elements_text(p_settings->'domains')) into domains;
      perform public.st_v6_workspace_link_policy_set(p_workspace,domains);
  end case;
end
$$;

create function public.st_v7_workspace_policies(p_workspace uuid,p_domain text,p_action text default 'read',
  p_revision integer default null,p_settings jsonb default null,p_target integer default null)
returns jsonb language plpgsql security definer set search_path='' as $$
declare assurance text:=sectalk_private.st_v7_file_egress_operator(p_workspace);
  latest integer; before_settings jsonb; after_settings jsonb; history jsonb; prior_setting text;
  query_result jsonb;
begin
  if assurance is distinct from 'verified' then return jsonb_build_object('access',assurance); end if;
  if p_domain is null or p_domain not in ('messaging','files','calls','ai','retention','sharing','dlp','external')
    or p_action is null or p_action not in ('read','preview','apply','rollback') then
    raise exception using errcode='22023',message='Choose a supported workspace policy operation';
  end if;
  if p_action<>'read' then
    perform sectalk_private.limit_action('v7_unified_workspace_policies',40);
    if p_domain='retention' then
      perform pg_advisory_xact_lock(hashtextextended('sectalk-workspace-hold:'||p_workspace::text,0));
    end if;
    perform 1 from public.st_v2_workspaces where id=p_workspace for update;
    if not found or sectalk_private.st_v7_file_egress_operator(p_workspace) is distinct from 'verified' then
      raise exception using errcode='42501',message='Fresh workspace owner verification required';
    end if;
  end if;
  select coalesce(max(v.revision),0) into latest from sectalk_private.st_v7_policy_snapshots v
    where v.workspace=p_workspace and v.domain=p_domain;
  before_settings:=sectalk_private.st_v7_live_policy(p_workspace,p_domain);
  if p_action<>'read' then
    if p_revision is distinct from latest then raise exception using errcode='PT409',message='Policy changed. Refresh before updating.'; end if;
    prior_setting:=current_setting('sectalk.adm06_expected',true);
    perform set_config('sectalk.adm06_expected',p_workspace::text||'|'||p_domain||'|'||latest::text,true);
    if p_action='rollback' or (p_action='preview' and p_target is not null) then
      select v.settings into p_settings from sectalk_private.st_v7_policy_snapshots v
        where v.workspace=p_workspace and v.domain=p_domain and v.revision=p_target;
      if not found then raise exception using errcode='22023',message='Choose an available revision'; end if;
    end if;
    if p_action='preview' then
      -- Calling the enforcing writer inside a subtransaction exercises the same
      -- native checks. The sentinel rolls back revisions, audit and policy writes.
      begin
        perform sectalk_private.st_v7_apply_live_policy(p_workspace,p_domain,p_settings);
        after_settings:=sectalk_private.st_v7_live_policy(p_workspace,p_domain);
        select case p_domain
          when 'calls' then jsonb_build_object('available_to_requester',sectalk_private.st_v6_feature_allowed('recurring_meetings',auth.uid(),p_workspace))
          when 'external' then jsonb_build_object('allowlist_required',exists(select 1 from public.st_v6_workspace_policy w
            join public.st_v6_compliance_profiles pr on pr.id=w.compliance_profile where w.workspace_id=p_workspace and pr.require_domains))
          when 'retention' then jsonb_build_object('preservation_holds_still_apply',true)
          when 'sharing' then jsonb_build_object('document_rules_still_apply',true)
          else '{}'::jsonb end into query_result;
        raise exception using errcode='PZ006',message='Policy preview complete';
      exception when sqlstate 'PZ006' then null;
      end;
      perform set_config('sectalk.adm06_expected',coalesce(prior_setting,''),true);
      return jsonb_build_object('access','verified','revision',latest,'current',before_settings,'proposed',after_settings,'effect',query_result);
    end if;
    perform sectalk_private.st_v7_apply_live_policy(p_workspace,p_domain,p_settings);
    perform set_config('sectalk.adm06_expected',coalesce(prior_setting,''),true);
    if before_settings is distinct from sectalk_private.st_v7_live_policy(p_workspace,p_domain) then
      insert into public.st_v2_workspace_audit(workspace_id,actor,event,target)
        values(p_workspace,auth.uid(),'workspace.policy.'||p_domain||'.'||p_action,p_workspace);
    end if;
  end if;
  select coalesce(max(v.revision),0) into latest from sectalk_private.st_v7_policy_snapshots v
    where v.workspace=p_workspace and v.domain=p_domain;
  select coalesce(jsonb_agg(to_jsonb(h) order by h.revision desc),'[]') into history from (
    select v.revision,v.settings,v.recorded_at from sectalk_private.st_v7_policy_snapshots v
    where v.workspace=p_workspace and v.domain=p_domain order by revision desc limit 25) h;
  return jsonb_build_object('access','verified','revision',latest,'current',sectalk_private.st_v7_live_policy(p_workspace,p_domain),'history',history);
end
$$;

revoke all on function sectalk_private.st_v7_policy_shape(text,jsonb),sectalk_private.st_v7_live_policy(uuid,text),
  sectalk_private.st_v7_capture_policy_snapshot(),sectalk_private.st_v7_apply_live_policy(uuid,text,jsonb),
  public.st_v7_workspace_policies(uuid,text,text,integer,jsonb,integer) from public,anon,authenticated,service_role;
grant execute on function public.st_v7_workspace_policies(uuid,text,text,integer,jsonb,integer) to authenticated;
commit;
