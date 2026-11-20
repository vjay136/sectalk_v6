begin;
create table sectalk_private.st_v7_siem_batches (
  id uuid primary key default gen_random_uuid(),
  workspace uuid not null references public.st_v2_workspaces on delete cascade,
  period timestamptz not null,
  created_at timestamptz not null default clock_timestamp(),
  counts jsonb not null,
  unique(workspace,period)
);
create table sectalk_private.st_v7_siem_deliveries (
  batch uuid not null references sectalk_private.st_v7_siem_batches on delete cascade,
  channel text not null check(channel in ('webhook','syslog','s3')),
  requested_by uuid not null references auth.users on delete cascade,
  state text not null default 'queued' check(state in ('queued','sending','sent','failed')),
  attempts smallint not null default 0 check(attempts between 0 and 4),
  ready_at timestamptz not null default clock_timestamp(),
  lease uuid,
  lease_until timestamptz,
  primary key(batch,channel)
);
create index on sectalk_private.st_v7_siem_deliveries(channel,ready_at) where state in ('queued','sending');
create index on sectalk_private.st_v7_siem_batches(created_at);
alter table sectalk_private.st_v7_siem_batches enable row level security;
alter table sectalk_private.st_v7_siem_deliveries enable row level security;
revoke all on sectalk_private.st_v7_siem_batches,sectalk_private.st_v7_siem_deliveries
  from public,anon,authenticated,service_role;

create function sectalk_private.st_v7_siem_entitled(p_workspace uuid,p_actor uuid)
returns boolean language sql stable set search_path='' as $$
  select exists(select 1 from public.st_v2_workspaces w where w.id=p_workspace and w.owner=p_actor
    and sectalk_private.st_v2_role(w.id,p_actor)='owner' and sectalk_private.st_v2_active(p_actor)
    and sectalk_private.st_v2_effective_plan(p_actor)='enterprise')
$$;

create function public.st_v7_siem_batch(p_workspace uuid,p_period timestamptz,p_channel text)
returns uuid language plpgsql security definer set search_path='' as $$
declare
  actor uuid:=auth.uid();
  batch_key uuid;
  grouped jsonb;
begin
  if not sectalk_private.st_v7_admin_fresh() or not sectalk_private.st_v7_siem_entitled(p_workspace,actor) then
    raise exception 'Fresh enterprise workspace ownership required' using errcode='42501'; end if;
  if p_channel is null or p_channel not in ('download','webhook','syslog','s3') or p_period is null
    or not isfinite(p_period) or p_period<>date_trunc('hour',p_period,'UTC')
    or p_period>=date_trunc('hour',statement_timestamp(),'UTC')-interval '0 hours'
    or p_period<date_trunc('hour',statement_timestamp(),'UTC')-interval '7 days' then
    raise exception 'Select a completed UTC hour from the last seven days' using errcode='22023'; end if;
  perform sectalk_private.limit_action('v7_siem_batch',20);
  select b.id into batch_key from sectalk_private.st_v7_siem_batches b where b.workspace=p_workspace and b.period=p_period;
  if not found then
    select coalesce(jsonb_object_agg(category,n),'{}') into grouped
      from (select case a.event
        when 'member.suspend' then 'member_suspended'
        when 'member.remove' then 'member_removed'
        when 'member.admin' then 'administrator_granted'
        when 'workspace.data_loss_policy_changed' then 'data_loss_policy_updated'
        when 'workspace.audit_export_requested' then 'audit_export_requested'
        when 'integration.key_created' then 'integration_key_created'
        when 'integration.key_revoked' then 'integration_key_revoked'
        end category,count(*) n from public.st_v2_workspace_audit a
        where a.workspace_id=p_workspace and a.created_at>=p_period and a.created_at<p_period+interval '1 hour'
          and a.event in ('member.suspend','member.remove','member.admin','workspace.data_loss_policy_changed',
            'workspace.audit_export_requested','integration.key_created','integration.key_revoked')
        group by category) counts;
    insert into sectalk_private.st_v7_siem_batches as b(workspace,period,counts) values(p_workspace,p_period,grouped)
      on conflict(workspace,period) do update set period=excluded.period returning b.id into batch_key;
  end if;
  if p_channel<>'download' then
    insert into sectalk_private.st_v7_siem_deliveries(batch,channel,requested_by) values(batch_key,p_channel,actor)
      on conflict do nothing;
    if found then insert into public.st_v2_workspace_audit(workspace_id,actor,event,target)
      values(p_workspace,actor,'workspace.siem_delivery_queued',batch_key); end if;
  end if;
  return batch_key;
end $$;

create function public.st_v7_siem_batch_read(p_workspace uuid,p_batch uuid default null)
returns jsonb language plpgsql stable security definer set search_path='' as $$
begin
  if not sectalk_private.st_v7_admin_fresh() or not sectalk_private.st_v7_siem_entitled(p_workspace,auth.uid()) then
    raise exception 'Fresh enterprise workspace ownership required' using errcode='42501'; end if;
  if p_batch is null then
    return coalesce((select jsonb_agg(to_jsonb(item) order by item.period desc) from (
      select b.id,b.period,coalesce((select jsonb_object_agg(d.channel,d.state)
        from sectalk_private.st_v7_siem_deliveries d where d.batch=b.id),'{}') deliveries
      from sectalk_private.st_v7_siem_batches b where b.workspace=p_workspace order by b.period desc limit 24
    ) item),'[]');
  end if;
  return (select jsonb_build_object('id',b.id,'workspace',b.workspace,'period',b.period,'counts',b.counts)
    from sectalk_private.st_v7_siem_batches b where b.workspace=p_workspace and b.id=p_batch);
end $$;

create function public.st_v7_siem_claim(p_workspace uuid,p_channel text)
returns jsonb language plpgsql security definer set search_path='' as $$
declare
  item sectalk_private.st_v7_siem_deliveries;
begin
  select d.* into item from sectalk_private.st_v7_siem_deliveries d
    join sectalk_private.st_v7_siem_batches b on b.id=d.batch
    where b.workspace=p_workspace and d.channel=p_channel and d.attempts<4
      and b.created_at>clock_timestamp()-interval '24 hours'
      and ((d.state='queued' and d.ready_at<=clock_timestamp())
        or (d.state='sending' and d.lease_until<=clock_timestamp()))
      and sectalk_private.st_v7_siem_entitled(b.workspace,d.requested_by)
    order by d.ready_at,b.id limit 1 for update of d skip locked;
  if not found then return null; end if;
  update sectalk_private.st_v7_siem_deliveries d set state='sending',attempts=attempts+1,
    lease=gen_random_uuid(),lease_until=clock_timestamp()+interval '30 seconds'
    where d.batch=item.batch and d.channel=item.channel returning d.* into item;
  return (select jsonb_build_object('id',b.id,'workspace',b.workspace,'period',b.period,'counts',b.counts,'lease',item.lease)
    from sectalk_private.st_v7_siem_batches b where b.id=item.batch);
end $$;

create function public.st_v7_siem_finish(p_batch uuid,p_channel text,p_lease uuid,p_result text)
returns boolean language plpgsql security definer set search_path='' as $$
begin
  if p_result is null or p_result not in ('sent','retry','failed') then return false; end if;
  update sectalk_private.st_v7_siem_deliveries d
    set state=case when p_result='sent' then 'sent' when p_result='failed' or d.attempts>=4 then 'failed' else 'queued' end,
      ready_at=clock_timestamp()+make_interval(secs=>power(4,d.attempts)::integer*5),lease=null,lease_until=null
    where d.batch=p_batch and d.channel=p_channel and d.state='sending' and d.lease=p_lease
      and d.lease_until>clock_timestamp();
  return found;
end $$;

revoke all on function sectalk_private.st_v7_siem_entitled(uuid,uuid),public.st_v7_siem_batch(uuid,timestamptz,text),
  public.st_v7_siem_batch_read(uuid,uuid),public.st_v7_siem_claim(uuid,text),public.st_v7_siem_finish(uuid,text,uuid,text)
  from public,anon,authenticated,service_role;
grant execute on function public.st_v7_siem_batch(uuid,timestamptz,text),public.st_v7_siem_batch_read(uuid,uuid) to authenticated;
grant execute on function public.st_v7_siem_claim(uuid,text),public.st_v7_siem_finish(uuid,text,uuid,text) to service_role;

select cron.schedule('sectalk-v7-siem-cleanup','*/10 * * * *',
  $job$update sectalk_private.st_v7_siem_deliveries d set state='failed',lease=null,lease_until=null
    from sectalk_private.st_v7_siem_batches b where b.id=d.batch and
      ((d.state in ('queued','sending') and b.created_at<clock_timestamp()-interval '24 hours')
      or (d.state='sending' and d.attempts>=4 and d.lease_until<=clock_timestamp()));
    delete from sectalk_private.st_v7_siem_batches where created_at<clock_timestamp()-interval '8 days';$job$);
commit;
