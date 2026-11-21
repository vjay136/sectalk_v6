begin;

alter table sectalk_private.st_v8_offboarding_requests add column integration_shutdown jsonb
  check(integration_shutdown is null or jsonb_typeof(integration_shutdown)='object');

create function sectalk_private.st_v8_offboarding_shutdown_integrations()
returns trigger language plpgsql security definer set search_path='' as $$
declare
  closed_at timestamptz:=clock_timestamp();
  api_keys integer;
  webhooks integer;
  jobs integer;
  scim_tokens integer;
begin
  if old.integration_shutdown is not null then
    if new.integration_shutdown is distinct from old.integration_shutdown then raise insufficient_privilege; end if;
    return new;
  end if;
  if new.state<>'read_only' then return new; end if;

  perform 1 from public.st_v2_workspaces where id=new.workspace for no key update;
  update sectalk_private.st_v6_integration_keys
    set revoked_at=closed_at where workspace_id=new.workspace and revoked_at is null;
  get diagnostics api_keys=row_count;

  update sectalk_private.st_v6_webhooks
    set revoked_at=closed_at where workspace_id=new.workspace and revoked_at is null;
  get diagnostics webhooks=row_count;

  update sectalk_private.st_v6_webhook_jobs as job
    set state='cancelled',lease=null,lease_expires=null
    from sectalk_private.st_v6_webhooks as endpoint
    where (endpoint.id,endpoint.workspace_id)=(job.endpoint_id,new.workspace) and job.state='queued';
  get diagnostics jobs=row_count;

  delete from sectalk_private.st_v8_scim_keys where workspace=new.workspace;
  get diagnostics scim_tokens=row_count;

  new.integration_shutdown:=jsonb_build_object('at',closed_at,'apiKeys',api_keys,'webhooks',webhooks,
    'webhookJobs',jobs,'scimTokens',scim_tokens);
  return new;
end $$;

create trigger st_v8_offboarding_shutdown_integrations before update on sectalk_private.st_v8_offboarding_requests
  for each row when (new.state='read_only' or old.integration_shutdown is not null)
  execute function sectalk_private.st_v8_offboarding_shutdown_integrations();

create function sectalk_private.st_v8_offboarding_integration_write()
returns trigger language plpgsql security definer set search_path='' as $$
declare target_workspace uuid;
begin
  if tg_table_name='st_v8_scim_keys' then target_workspace:=new.workspace;
  else
    if new.revoked_at is not null then return new; end if;
    target_workspace:=new.workspace_id;
  end if;
  perform 1 from public.st_v2_workspaces where id=target_workspace for share;
  if exists(select 1 from sectalk_private.st_v8_offboarding_requests r
      where r.workspace=target_workspace and r.state='read_only') then
    raise exception 'This workspace is read-only for offboarding.' using errcode='PT423';
  end if;
  return new;
end $$;

create trigger st_v8_offboarding_api_key_write before insert on sectalk_private.st_v6_integration_keys
  for each row execute function sectalk_private.st_v8_offboarding_integration_write();
create trigger st_v8_offboarding_webhook_write before insert on sectalk_private.st_v6_webhooks
  for each row execute function sectalk_private.st_v8_offboarding_integration_write();
create trigger st_v8_offboarding_scim_key_write before insert on sectalk_private.st_v8_scim_keys
  for each row execute function sectalk_private.st_v8_offboarding_integration_write();

create function sectalk_private.st_v8_ignore_revoked_webhook_job()
returns trigger language plpgsql security definer set search_path='' as $$
begin
  perform 1 from sectalk_private.st_v6_webhooks e where e.id=new.endpoint_id and e.revoked_at is null for share;
  if not found then return null; end if;
  return new;
end $$;

create trigger st_v8_ignore_revoked_webhook_job before insert on sectalk_private.st_v6_webhook_jobs
  for each row when (new.state='queued') execute function sectalk_private.st_v8_ignore_revoked_webhook_job();

-- Apply the same integration boundary to workspaces that completed staging before this migration.
update sectalk_private.st_v8_offboarding_requests set state='read_only' where state='read_only';

create or replace function public.st_v8_workspace_offboarding(p_workspace uuid)
returns jsonb language plpgsql stable security definer set search_path='' as $$
declare actor_id uuid:=auth.uid(); role text:=sectalk_private.st_v8_offboarding_role(p_workspace,actor_id);
begin
  if not coalesce(sectalk_private.st_v7_billing_admin_session(),false) or role='none' then
    raise exception 'Workspace offboarding unavailable' using errcode='42501'; end if;
  if not sectalk_private.st_v7_admin_fresh() then return jsonb_build_object('access','mfa','role',role); end if;
  return jsonb_build_object('access','verified','role',role,'held',sectalk_private.st_v8_offboarding_holds(p_workspace),
    'request',(select jsonb_build_object('id',r.id,'state',r.state,'sha256',r.snapshot_sha256,'case',r.case_id,
      'artifact',c.artifact is not null and c.expires_at>statement_timestamp(),
      'expired',c.expires_at<=statement_timestamp(),
      'downloaded',exists(select 1 from sectalk_private.st_v7_compliance_audit a where a.case_id=r.case_id and a.action='downloaded'),
      'snapshot',r.snapshot,'manifestSha256',c.manifest_sha256,'reason',r.reason,
      'integrationShutdown',r.integration_shutdown)
      from sectalk_private.st_v8_offboarding_requests r left join sectalk_private.st_v7_compliance_cases c on c.id=r.case_id
      where r.workspace=p_workspace and r.state<>'withdrawn'));
end $$;

revoke all on function sectalk_private.st_v8_offboarding_shutdown_integrations(),
  sectalk_private.st_v8_offboarding_integration_write(),sectalk_private.st_v8_ignore_revoked_webhook_job()
  from public,anon,authenticated,service_role;

commit;
