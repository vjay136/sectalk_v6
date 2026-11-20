begin;
create table sectalk_private.st_v7_nonpayment_cancellations (
  subscription text primary key,
  account uuid not null references auth.users on delete cascade,
  customer text not null,
  observed_at timestamptz not null
);
alter table sectalk_private.st_v7_nonpayment_cancellations enable row level security;
revoke all on sectalk_private.st_v7_nonpayment_cancellations from public,anon,authenticated,service_role;

create function sectalk_private.st_v7_workspace_payment_mode(p_workspace uuid)
returns jsonb language sql stable security definer set search_path='' as $$
  select coalesce((
    select jsonb_build_object('mode',case when g.deadline>statement_timestamp() then 'grace' else 'read_only' end,
      'grace_until',g.deadline)
    from public.st_v2_workspaces w join public.st_v2_subscriptions s on s.user_id=w.owner
    left join sectalk_private.st_v7_nonpayment_cancellations c on (c.subscription,c.account,c.customer)=(s.subscription_id,s.user_id,s.customer_id)
    cross join lateral (
      select case when s.status='past_due' then sectalk_private.st_v7_renewal_grace(s.user_id,s.subscription_id,s.period_end) else
        coalesce((select min(r.grace_until) from sectalk_private.st_v7_renewal_cases r
          where (r.recipient,r.customer,r.subscription)=(s.user_id,s.customer_id,s.subscription_id) and r.stage<>'paid'),
          s.period_end+make_interval(hours=>(select grace_hours from sectalk_private.st_v7_renewal_policy where singleton)),
          s.synced_at+make_interval(hours=>(select grace_hours from sectalk_private.st_v7_renewal_policy where singleton)))
      end deadline
    ) g
    where w.id=p_workspace and s.plan<>'free'
      and (s.status in ('past_due','unpaid') or (s.status='canceled' and c.subscription is not null))
      and g.deadline is not null
  ),'{"mode":"active"}')
$$;

create function public.st_v7_workspace_payment_state(p_workspace uuid default null,p_room uuid default null)
returns jsonb language plpgsql stable security definer set search_path='' as $$
declare actor uuid:=auth.uid(); tenant uuid:=p_workspace;
begin
  if actor is null or not coalesce(public.st_v7_current_session_valid(),false) or num_nonnulls(p_workspace,p_room)<>1 then
    raise exception 'Workspace payment state unavailable' using errcode='42501'; end if;
  if p_room is not null then
    select workspace_id into tenant from public.st_v6_rooms r where r.id=p_room
      and sectalk_private.st_v6_room_role(r.id,actor) is not null;
  end if;
  if tenant is null or sectalk_private.st_v2_role(tenant,actor) is null or not sectalk_private.st_v2_active(actor) then
    raise exception 'Workspace payment state unavailable' using errcode='42501'; end if;
  return sectalk_private.st_v7_workspace_payment_mode(tenant);
end $$;

create function sectalk_private.st_v7_workspace_write_scope(p_id uuid,p_parent text)
returns uuid language plpgsql stable set search_path='' as $$
begin
  if p_id is null then return null; end if;
  case p_parent
    when 'room' then return (select workspace_id from public.st_v6_rooms where id=p_id);
    when 'channel' then return (select workspace_id from public.st_v2_channels where id=p_id);
    when 'task' then return (select r.workspace_id from public.st_v6_tasks t join public.st_v6_rooms r on r.id=t.room_id where t.id=p_id);
    when 'meeting' then return (select workspace_id from public.st_v3_meetings where id=p_id);
    else return p_id;
  end case;
end $$;

create function sectalk_private.st_v7_require_workspace_write(p_workspace uuid)
returns void language plpgsql security definer set search_path='' as $$
begin
  if p_workspace is null then return; end if;
  perform 1 from public.st_v2_subscriptions s join public.st_v2_workspaces w on w.owner=s.user_id
    where w.id=p_workspace for share of s;
  if sectalk_private.st_v7_workspace_payment_mode(p_workspace)->>'mode'='read_only' then
    raise exception 'This workspace is read-only until payment is restored.' using errcode='PT423';
  end if;
end $$;

create function sectalk_private.st_v7_guard_workspace_write()
returns trigger language plpgsql security definer set search_path='' as $$
declare current_row jsonb:=to_jsonb(new); prior_row jsonb; tenant uuid; previous uuid;
begin
  if tg_op='UPDATE' then
    prior_row:=to_jsonb(old);
    if tg_argv[2]='room_post' and prior_row->>'removed_at' is null and current_row->>'removed_at' is not null
      and current_row->>'body'='Message removed' and current_row->>tg_argv[0]=prior_row->>tg_argv[0] then return new; end if;
    if tg_argv[2]='channel_post' and prior_row->>'quarantined_at' is null and current_row->>'quarantined_at' is not null
      and current_row->>'body'='Message quarantined' and current_row->>tg_argv[0]=prior_row->>tg_argv[0] then return new; end if;
    if tg_argv[2]='workspace_member' and current_row->>tg_argv[0]=prior_row->>tg_argv[0]
      and (current_row->>'suspended_at' is not null or (current_row->>'role'='member' and prior_row->>'role'='admin'))
      then return new; end if;
    if tg_argv[2]='file' and current_row->>'published_at' is not distinct from prior_row->>'published_at'
      and current_row->>tg_argv[0]=prior_row->>tg_argv[0] then return new; end if;
    if tg_argv[2]='recording' and current_row->>'status'<>'collecting' then return new; end if;
    previous:=sectalk_private.st_v7_workspace_write_scope((prior_row->>tg_argv[0])::uuid,tg_argv[1]);
  end if;
  tenant:=sectalk_private.st_v7_workspace_write_scope((current_row->>tg_argv[0])::uuid,tg_argv[1]);
  perform sectalk_private.st_v7_require_workspace_write(least(tenant,previous));
  if tenant is not null and previous is not null and tenant is distinct from previous then perform sectalk_private.st_v7_require_workspace_write(greatest(tenant,previous)); end if;
  return new;
end $$;

create trigger st_v7_payment_write before insert or update of workspace_id,name,kind,template,archived,slow_seconds on public.st_v6_rooms
  for each row execute function sectalk_private.st_v7_guard_workspace_write('workspace_id','direct');
create trigger st_v7_payment_write before insert or update of room_id,body,kind,parent_id,removed_at on public.st_v6_room_posts
  for each row execute function sectalk_private.st_v7_guard_workspace_write('room_id','room','room_post');
create trigger st_v7_payment_write before insert or update on public.st_v6_room_pins
  for each row execute function sectalk_private.st_v7_guard_workspace_write('room_id','room');
create trigger st_v7_payment_write before insert or update on sectalk_private.st_v6_room_reactions
  for each row execute function sectalk_private.st_v7_guard_workspace_write('room_id','room');

create trigger st_v7_payment_write before insert or update of workspace_id,name,visibility,archived on public.st_v2_channels
  for each row execute function sectalk_private.st_v7_guard_workspace_write('workspace_id','direct');
create trigger st_v7_payment_write before insert or update of channel_id,body on public.st_v2_posts
  for each row execute function sectalk_private.st_v7_guard_workspace_write('channel_id','channel','channel_post');
create trigger st_v7_payment_write before insert or update on public.st_v2_items
  for each row execute function sectalk_private.st_v7_guard_workspace_write('workspace_id','direct');
create trigger st_v7_payment_write before insert or update on public.st_v6_tasks
  for each row execute function sectalk_private.st_v7_guard_workspace_write('room_id','room');
create trigger st_v7_payment_write before insert or update on public.st_v6_task_people
  for each row execute function sectalk_private.st_v7_guard_workspace_write('task_id','task');

create trigger st_v7_payment_write before insert on public.st_v2_invites
  for each row execute function sectalk_private.st_v7_guard_workspace_write('workspace_id','direct');
create trigger st_v7_payment_write before insert or update of role,suspended_at,workspace_id on public.st_v2_members
  for each row execute function sectalk_private.st_v7_guard_workspace_write('workspace_id','direct','workspace_member');
create trigger st_v7_payment_write before insert or update on public.st_v6_workspace_groups
  for each row execute function sectalk_private.st_v7_guard_workspace_write('workspace_id','direct');
create trigger st_v7_payment_write before insert on public.st_v6_workspace_group_members
  for each row execute function sectalk_private.st_v7_guard_workspace_write('workspace_id','direct');
create trigger st_v7_payment_write before insert on public.st_v6_room_members
  for each row execute function sectalk_private.st_v7_guard_workspace_write('room_id','room');
create trigger st_v7_payment_write before insert on public.st_v6_room_entries
  for each row execute function sectalk_private.st_v7_guard_workspace_write('room_id','room');
create trigger st_v7_payment_write before insert on sectalk_private.st_v6_workspace_link_invites
  for each row execute function sectalk_private.st_v7_guard_workspace_write('workspace_id','direct');
create trigger st_v7_payment_write before insert on sectalk_private.st_v6_room_guest_link
  for each row execute function sectalk_private.st_v7_guard_workspace_write('room','room');
create trigger st_v7_payment_write before insert on sectalk_private.st_v6_channel_members
  for each row execute function sectalk_private.st_v7_guard_workspace_write('channel_id','channel');

create trigger st_v7_payment_write before insert or update of workspace,published_at on sectalk_private.st_v6_workspace_files
  for each row execute function sectalk_private.st_v7_guard_workspace_write('workspace','direct','file');
create trigger st_v7_payment_write before insert or update of workspace,published_at on sectalk_private.st_v6_room_files
  for each row execute function sectalk_private.st_v7_guard_workspace_write('workspace','direct','file');

create trigger st_v7_payment_write before insert or update of workspace_id,title,agenda,starts_at,ends_at on public.st_v3_meetings
  for each row execute function sectalk_private.st_v7_guard_workspace_write('workspace_id','direct');
create trigger st_v7_payment_write before insert on public.st_v6_meeting_chat
  for each row execute function sectalk_private.st_v7_guard_workspace_write('meeting_id','meeting');
create trigger st_v7_payment_write before insert or update of status on sectalk_private.st_v6_recording
  for each row execute function sectalk_private.st_v7_guard_workspace_write('meeting_id','meeting','recording');
create trigger st_v7_payment_write before insert on sectalk_private.st_v6_guest_link
  for each row execute function sectalk_private.st_v7_guard_workspace_write('meeting','meeting');

revoke all on function sectalk_private.st_v7_workspace_payment_mode(uuid),sectalk_private.st_v7_workspace_write_scope(uuid,text),
  sectalk_private.st_v7_require_workspace_write(uuid),sectalk_private.st_v7_guard_workspace_write(),
  public.st_v7_workspace_payment_state(uuid,uuid) from public,anon,authenticated,service_role;
grant execute on function public.st_v7_workspace_payment_state(uuid,uuid) to authenticated;
create or replace function sectalk_private.st_v7_sync_stripe_snapshot(event_key text, resource_key text, observed timestamptz, payload jsonb)
returns boolean language plpgsql security definer set search_path='' as $$
declare actor uuid:=(payload->>'user')::uuid; current_row public.st_v2_subscriptions;
begin
  if actor is null or payload->>'subscription' is distinct from resource_key
    or (payload->>'customer') !~ '^cus_[a-zA-Z0-9_]{1,100}$' or payload->>'customer' is null then return false; end if;
  perform pg_advisory_xact_lock(hashtextextended('sectalk-v6-billing:'||actor::text,0));
  select * into current_row from public.st_v2_subscriptions where user_id=actor for update;
  if (current_row.customer_id is not null and current_row.customer_id is distinct from payload->>'customer')
    or (current_row.subscription_id is distinct from resource_key and payload->>'status'='canceled')
    or not exists(select 1 from auth.users where id=actor) then return false; end if;
  perform public.st_v6_sync_catalog_subscription(event_key,actor,payload->>'customer',resource_key,
    payload->>'price',payload->>'legacy_plan',payload->>'legacy_cadence',payload->>'status',
    (payload->>'period_end')::timestamptz,(payload->>'cancel')::boolean,observed,payload->>'currency',(payload->>'amount')::integer);
  if exists(select 1 from public.st_v2_subscriptions s where s.user_id=actor and s.subscription_id=resource_key
    and s.customer_id=payload->>'customer' and s.synced_at=observed and s.status=payload->>'status') then
    if payload->>'status'='canceled' and payload->>'cancellation_reason'='payment_failed' then
      insert into sectalk_private.st_v7_nonpayment_cancellations as c(subscription,account,customer,observed_at)
      values(resource_key,actor,payload->>'customer',observed) on conflict(subscription) do update
      set account=excluded.account,customer=excluded.customer,observed_at=excluded.observed_at
      where c.observed_at<=excluded.observed_at;
    else
      delete from sectalk_private.st_v7_nonpayment_cancellations c where c.subscription=resource_key and c.observed_at<=observed;
    end if;
  end if;
  return true;
end $$;
create or replace function sectalk_private.st_v7_siem_entitled(p_workspace uuid,p_actor uuid)
returns boolean language sql stable set search_path='' as $$
  select exists(select 1 from public.st_v2_workspaces w where w.id=p_workspace and w.owner=p_actor
    and sectalk_private.st_v2_role(w.id,p_actor)='owner' and sectalk_private.st_v2_active(p_actor)
    and (sectalk_private.st_v2_effective_plan(p_actor)='enterprise' or
      (sectalk_private.st_v7_workspace_payment_mode(w.id)->>'mode'='read_only' and
       exists(select 1 from public.st_v2_subscriptions s where s.user_id=p_actor and s.plan='enterprise'))))
$$;
create or replace function public.st_v7_siem_batch(p_workspace uuid,p_period timestamptz,p_channel text)
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
  if p_channel<>'download' then perform sectalk_private.st_v7_require_workspace_write(p_workspace); end if;
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
commit;
