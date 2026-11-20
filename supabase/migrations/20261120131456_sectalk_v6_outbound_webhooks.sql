begin;

create table sectalk_private.st_v6_webhooks (
  id uuid primary key,
  workspace_id uuid not null references public.st_v2_workspaces on delete cascade,
  owner uuid not null,
  label text not null check(char_length(label) between 1 and 48),
  destination text not null check(char_length(destination) between 10 and 480),
  wrapped_key text not null check(wrapped_key~'^[A-Za-z0-9_-]{80}$'),
  topics text[] not null check(cardinality(topics) between 1 and 2
    and topics <@ array['room.created','membership.changed']::text[]),
  created_at timestamptz not null default clock_timestamp(),
  revoked_at timestamptz
);
create index st_v6_webhooks_workspace on sectalk_private.st_v6_webhooks(workspace_id) where revoked_at is null;
create table sectalk_private.st_v6_webhook_jobs (
  id uuid primary key default gen_random_uuid(),
  endpoint_id uuid not null references sectalk_private.st_v6_webhooks on delete cascade,
  event_id uuid not null,
  payload jsonb not null check(octet_length(payload::text)<=1000),
  created_at timestamptz not null default clock_timestamp(),
  next_attempt timestamptz not null default clock_timestamp(),
  attempts integer not null default 0 check(attempts between 0 and 5),
  state text not null default 'queued' check(state in ('queued','sent','failed','cancelled')),
  lease uuid,
  lease_expires timestamptz,
  last_status integer check(last_status between 100 and 599),
  unique(endpoint_id,event_id)
);
create index st_v6_webhook_due on sectalk_private.st_v6_webhook_jobs(next_attempt,id) where state='queued';
create index st_v6_webhook_history on sectalk_private.st_v6_webhook_jobs(endpoint_id,created_at desc);
alter table sectalk_private.st_v6_webhooks enable row level security;
alter table sectalk_private.st_v6_webhook_jobs enable row level security;
revoke all on sectalk_private.st_v6_webhooks,sectalk_private.st_v6_webhook_jobs from public,anon,authenticated,service_role;

create function sectalk_private.st_v6_webhook_entitled(e sectalk_private.st_v6_webhooks)
returns boolean language sql stable set search_path='' as $$
  select e.revoked_at is null and exists(select 1 from public.st_v2_workspaces w
    where (w.id,w.owner)=(e.workspace_id,e.owner) and sectalk_private.st_v2_active(w.owner)
      and sectalk_private.st_v2_effective_plan(w.owner) in ('business','enterprise'))
$$;

create function public.st_v6_register_webhook(p_workspace uuid,p_endpoint uuid,p_label text,p_destination text,p_wrapped text,p_topics text[])
returns void language plpgsql security definer set search_path='' as $$
begin
  if public.st_v6_integration_access(p_workspace)<>'verified' then
    raise exception using errcode='42501',message='Fresh integration administrator verification required';
  end if;
  if p_endpoint is null or char_length(btrim(coalesce(p_label,''))) not between 1 and 48
    or (char_length(p_destination) between 10 and 480) is not true or (p_wrapped~'^[A-Za-z0-9_-]{80}$') is not true
    or (cardinality(p_topics) between 1 and 2 and p_topics <@ array['room.created','membership.changed']::text[]) is not true then
    raise exception using errcode='22023',message='Choose a label, webhook destination and topics';
  end if;
  perform sectalk_private.limit_action('v6_webhook_registration',8);
  perform 1 from public.st_v2_workspaces where id=p_workspace for update;
  if public.st_v6_integration_access(p_workspace)<>'verified' then
    raise exception using errcode='42501',message='Integration access changed';
  end if;
  if (select count(*) from sectalk_private.st_v6_webhooks e where e.workspace_id=p_workspace and e.revoked_at is null)>=5 then
    raise exception using errcode='22023',message='The active webhook limit has been reached';
  end if;
  insert into sectalk_private.st_v6_webhooks(id,workspace_id,owner,label,destination,wrapped_key,topics)
    values(p_endpoint,p_workspace,auth.uid(),btrim(p_label),p_destination,p_wrapped,
      array(select distinct t from unnest(p_topics) valueset(t) order by t));
  insert into public.st_v2_workspace_audit(workspace_id,actor,event,target)
    values(p_workspace,auth.uid(),'integration.webhook_created',p_endpoint);
end $$;

create function public.st_v6_revoke_webhook(p_workspace uuid,p_endpoint uuid)
returns void language plpgsql security definer set search_path='' as $$
begin
  if public.st_v6_integration_access(p_workspace)<>'verified' then
    raise exception using errcode='42501',message='Fresh integration administrator verification required';
  end if;
  update sectalk_private.st_v6_webhooks set revoked_at=clock_timestamp()
    where id=p_endpoint and workspace_id=p_workspace and revoked_at is null;
  if not found then return; end if;
  update sectalk_private.st_v6_webhook_jobs set state='cancelled',lease=null,lease_expires=null
    where endpoint_id=p_endpoint and state='queued';
  insert into public.st_v2_workspace_audit(workspace_id,actor,event,target)
    values(p_workspace,auth.uid(),'integration.webhook_revoked',p_endpoint);
end $$;

create function public.st_v6_webhook_status(p_workspace uuid)
returns jsonb language plpgsql stable security definer set search_path='' as $$
declare result jsonb;
begin
  if public.st_v6_integration_access(p_workspace)<>'verified' then
    raise exception using errcode='42501',message='Fresh integration administrator verification required';
  end if;
  select coalesce(jsonb_agg(jsonb_build_object('id',e.id,'label',e.label,'destination',e.destination,
    'topics',e.topics,'revoked_at',e.revoked_at,'deliveries',coalesce((
      select jsonb_agg(jsonb_build_object('id',j.id,'type',j.payload->>'type','created_at',j.created_at,
        'state',j.state,'attempts',j.attempts,'status',j.last_status) order by j.created_at desc)
      from (select * from sectalk_private.st_v6_webhook_jobs x where x.endpoint_id=e.id order by x.created_at desc limit 10) j
    ),'[]'::jsonb)) order by e.created_at desc),'[]'::jsonb)
  into result from (select * from sectalk_private.st_v6_webhooks e where e.workspace_id=p_workspace
    order by e.created_at desc limit 20) e;
  return result;
end $$;

create function sectalk_private.st_v6_emit_webhook_event()
returns trigger language plpgsql security definer set search_path='' as $$
declare workspace uuid; event uuid:=gen_random_uuid(); topic text; body jsonb;
begin
  if tg_table_name='st_v6_rooms' then
    if new.kind<>'public' or new.classification not in ('public','internal') or new.archived then return null; end if;
    workspace:=new.workspace_id;
    topic:='room.created';
    body:=jsonb_build_object('workspace_id',workspace,'room_id',new.id);
  else
    if tg_op='UPDATE' and (new.role,new.suspended_at) is not distinct from (old.role,old.suspended_at) then return null; end if;
    workspace:=case when tg_op='DELETE' then old.workspace_id else new.workspace_id end;
    topic:='membership.changed';
    body:=jsonb_build_object('workspace_id',workspace);
  end if;
  insert into sectalk_private.st_v6_webhook_jobs(endpoint_id,event_id,payload)
    select e.id,event,jsonb_build_object('id',event,'type',topic,'timestamp',clock_timestamp(),'data',body)
    from sectalk_private.st_v6_webhooks e where e.workspace_id=workspace and e.revoked_at is null
      and topic=any(e.topics) and sectalk_private.st_v6_webhook_entitled(e);
  return null;
end $$;
create trigger st_v6_webhook_room_insert after insert on public.st_v6_rooms
  for each row execute function sectalk_private.st_v6_emit_webhook_event();
create trigger st_v6_webhook_roster after insert or update of role,suspended_at or delete on public.st_v2_members
  for each row execute function sectalk_private.st_v6_emit_webhook_event();

create function public.st_v6_claim_webhooks()
returns table(id uuid,workspace_id uuid,endpoint_id uuid,event_id uuid,payload jsonb,destination text,wrapped_key text,lease uuid)
language plpgsql security definer set search_path='' as $$
begin
  update sectalk_private.st_v6_webhook_jobs j set state=case when j.attempts>=5 then 'failed' else 'cancelled' end,
    lease=null,lease_expires=null
    from sectalk_private.st_v6_webhooks e where j.state='queued' and e.id=j.endpoint_id
      and (j.lease is null or j.lease_expires<=now()) and (j.attempts>=5 or not sectalk_private.st_v6_webhook_entitled(e));
  return query with due as materialized (
    select j.id from sectalk_private.st_v6_webhook_jobs j join sectalk_private.st_v6_webhooks e on e.id=j.endpoint_id
    where j.state='queued' and j.attempts<5 and j.next_attempt<=now() and (j.lease is null or j.lease_expires<=now())
      and sectalk_private.st_v6_webhook_entitled(e)
    order by j.next_attempt,j.id limit 10 for update of j skip locked
  ), claimed as (
    update sectalk_private.st_v6_webhook_jobs j set lease=gen_random_uuid(),lease_expires=now()+interval '1 minute',attempts=j.attempts+1
      from due where j.id=due.id returning j.*
  ) select j.id,e.workspace_id,e.id,j.event_id,j.payload,e.destination,e.wrapped_key,j.lease
    from claimed j join sectalk_private.st_v6_webhooks e on e.id=j.endpoint_id;
end $$;

create function public.st_v6_webhook_lease_active(p_job uuid,p_lease uuid)
returns boolean language sql stable security definer set search_path='' as $$
  select exists(select 1 from sectalk_private.st_v6_webhook_jobs j join sectalk_private.st_v6_webhooks e on e.id=j.endpoint_id
    where j.id=p_job and j.lease=p_lease and j.state='queued' and j.lease_expires>now()
      and sectalk_private.st_v6_webhook_entitled(e))
$$;

create function public.st_v6_finish_webhook(p_job uuid,p_lease uuid,p_status integer,p_retry boolean)
returns void language sql security definer set search_path='' as $$
  update sectalk_private.st_v6_webhook_jobs j set
    state=case when p_status between 200 and 299 then 'sent' when p_retry and j.attempts<5 then 'queued' else 'failed' end,
    lease=null,lease_expires=null,last_status=p_status,
    next_attempt=now()+interval '1 minute'*power(2,greatest(0,j.attempts-1))
  where j.id=p_job and j.lease=p_lease and j.state='queued' and j.lease_expires>now()
$$;

revoke all on function sectalk_private.st_v6_webhook_entitled(sectalk_private.st_v6_webhooks),sectalk_private.st_v6_emit_webhook_event(),
  public.st_v6_register_webhook(uuid,uuid,text,text,text,text[]),public.st_v6_revoke_webhook(uuid,uuid),public.st_v6_webhook_status(uuid),
  public.st_v6_claim_webhooks(),public.st_v6_webhook_lease_active(uuid,uuid),public.st_v6_finish_webhook(uuid,uuid,integer,boolean)
  from public,anon,authenticated,service_role;
grant execute on function public.st_v6_register_webhook(uuid,uuid,text,text,text,text[]),
  public.st_v6_revoke_webhook(uuid,uuid),public.st_v6_webhook_status(uuid) to authenticated;
grant execute on function public.st_v6_claim_webhooks(),public.st_v6_webhook_lease_active(uuid,uuid),
  public.st_v6_finish_webhook(uuid,uuid,integer,boolean) to service_role;
select cron.schedule('sectalk-v6-prune-webhook-history','27 4 * * *',
  $job$delete from sectalk_private.st_v6_webhook_jobs where created_at<now()-interval '30 days'$job$);
notify pgrst,'reload schema';
commit;
