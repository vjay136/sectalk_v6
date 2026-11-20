begin;

create table sectalk_private.st_v7_operator_device_audit (
  id bigint generated always as identity primary key,
  actor uuid not null,
  owner uuid not null,
  device uuid not null,
  action text not null check(action in ('revoke','wipe','cancel_wipe','block_device','mark_managed','clear_managed')),
  command uuid,
  reason text not null check(char_length(reason) between 10 and 240),
  occurred_at timestamptz not null default clock_timestamp()
);
create index st_v7_operator_device_history on sectalk_private.st_v7_operator_device_audit(owner,device,id desc);
create unique index st_v7_operator_wipe_command on sectalk_private.st_v7_operator_device_audit(command)
  where action='wipe' and command is not null;
alter table sectalk_private.st_v7_operator_device_audit enable row level security;
revoke all on sectalk_private.st_v7_operator_device_audit from public,anon,authenticated,service_role;

alter table sectalk_private.st_v7_device_trust_audit drop constraint st_v7_device_trust_audit_source_check;
alter table sectalk_private.st_v7_device_trust_audit add constraint st_v7_device_trust_audit_source_check
  check(source in ('owner','provider','operator'));
create index st_v7_device_trust_latest on sectalk_private.st_v7_device_trust_audit(device_id,id desc);

create function sectalk_private.st_v7_end_device_sessions(
  p_owner uuid,p_device uuid,p_operator uuid default null,p_reason text default null
)
returns void language plpgsql set search_path='' as $$
begin
  with revoked as (
    delete from auth.sessions s using sectalk_private.st_v7_device_sessions b
    where s.id=b.session_id and s.user_id=p_owner and (b.owner,b.device_id)=(p_owner,p_device)
    returning s.id
  )
  insert into sectalk_private.st_v7_account_admin_audit(actor,target,action,request_id,reason)
    select p_operator,p_owner,'session_revoked',r.id,p_reason from revoked r where p_operator is not null;
  perform realtime.send('{}','session_lifecycle','st:account:'||p_owner,true);
end $$;

create function sectalk_private.st_v7_queue_device_command(
  p_owner uuid,p_device uuid,p_kind text,p_operator uuid default null,p_reason text default null
)
returns uuid language plpgsql set search_path='' as $$
declare target sectalk_private.st_v7_devices; command_id uuid;
begin
  select d.* into target from sectalk_private.st_v7_devices d where (d.id,d.owner)=(p_device,p_owner) for update;
  if target.id is null or target.wiped_at is not null or (p_kind='lock' and target.locked_at is not null)
    or exists(select 1 from sectalk_private.st_v7_device_commands c where c.device_id=p_device and c.state in ('pending','delivered'))
    then return null; end if;
  if p_operator is not null and p_kind='revoke' and not exists(
    select 1 from sectalk_private.st_v7_device_sessions b join auth.sessions s
      on s.id=b.session_id and s.user_id=b.owner where (b.owner,b.device_id)=(p_owner,p_device)
      and sectalk_private.st_v7_session_deadline(s.created_at,s.refreshed_at,s.not_after)>statement_timestamp())
    then return null; end if;

  insert into sectalk_private.st_v7_device_commands(device_id,kind,previous_lock)
    values(p_device,p_kind,target.locked_at) returning id into command_id;
  if p_kind in ('lock','wipe') then
    update sectalk_private.st_v7_devices set locked_at=coalesce(locked_at,clock_timestamp()) where id=p_device;
  end if;
  perform sectalk_private.st_v7_end_device_sessions(p_owner,p_device,p_operator,p_reason);
  perform realtime.send('{}','device_registry','st:account:'||p_owner,true);
  return command_id;
end $$;

create or replace function public.st_v7_issue_device_command(p_device uuid,p_action text,p_command uuid default null)
returns boolean language plpgsql security definer set search_path='' as $$
declare actor uuid:=auth.uid(); device sectalk_private.st_v7_devices;
  pending sectalk_private.st_v7_device_commands; assurance text;
begin
  if not sectalk_private.st_v7_manage_sessions() then
    raise exception 'Verify this session to manage devices' using errcode='42501';
  end if;
  if p_action is null or p_action not in ('revoke','lock','wipe','cancel','unlock') then
    raise exception 'Choose a valid remote device action' using errcode='22023';
  end if;
  assurance:=case when exists(select 1 from auth.mfa_factors f where f.user_id=actor and f.status='verified')
    then 'totp' else 'password' end;
  if not sectalk_private.st_v7_security_session(assurance) then
    raise exception 'Verify your current account credentials to change device access' using errcode='42501';
  end if;
  perform sectalk_private.limit_action('v7_remote_device',15);
  perform 1 from auth.users where id=actor for update;
  if p_action in ('revoke','lock','wipe') then
    return sectalk_private.st_v7_queue_device_command(actor,p_device,p_action) is not null;
  end if;

  select d.* into device from sectalk_private.st_v7_devices d where d.id=p_device and d.owner=actor for update;
  if not found then return false; end if;
  select c.* into pending from sectalk_private.st_v7_device_commands c
    where c.device_id=device.id and c.state in ('pending','delivered') for update;
  if p_action='cancel' then
    if pending.id is distinct from p_command or pending.state is distinct from 'pending'
      or exists(select 1 from sectalk_private.st_v7_operator_device_audit a where a.command=pending.id and a.action='wipe')
      then return false; end if;
    update sectalk_private.st_v7_device_commands set state='cancelled',cancelled_at=clock_timestamp() where id=pending.id;
    if pending.kind in ('lock','wipe') then
      update sectalk_private.st_v7_devices set locked_at=pending.previous_lock where id=device.id;
    end if;
  else
    if device.wiped_at is not null or pending.kind='wipe' then return false; end if;
    if pending.kind='lock' and pending.state='pending' then
      update sectalk_private.st_v7_device_commands set state='cancelled',cancelled_at=clock_timestamp() where id=pending.id;
    end if;
    update sectalk_private.st_v7_devices set locked_at=null where id=device.id;
  end if;
  perform realtime.send('{}','device_registry','st:account:'||actor,true);
  return true;
end $$;

create function public.st_v7_operator_device_inventory(p_owner uuid)
returns table(id uuid,trust text,registered_at timestamptz,active_sessions bigint,locked boolean,wiped boolean,
  operator_managed boolean,command_kind text,command_state text,operator_wipe boolean,audit jsonb)
language plpgsql stable security definer set search_path='' as $$
begin
  if public.st_v7_account_operator_access()<>'operator' or p_owner=auth.uid()
    or not sectalk_private.st_v7_admin_native_target(p_owner) then
    raise exception 'Registered device inventory is unavailable' using errcode='42501';
  end if;
  return query select d.id,d.state,d.created_at,b.session_count,d.locked_at is not null,d.wiped_at is not null,
    d.state='managed' and coalesce(t.source='operator',false),c.kind,c.state,
    exists(select 1 from sectalk_private.st_v7_operator_device_audit a where a.command=c.id and a.action='wipe'),h.events
  from sectalk_private.st_v7_devices d
  cross join lateral (select count(*) session_count from sectalk_private.st_v7_device_sessions l
    join auth.sessions s on s.id=l.session_id and s.user_id=l.owner
    where (l.device_id,l.owner)=(d.id,d.owner)
      and sectalk_private.st_v7_session_deadline(s.created_at,s.refreshed_at,s.not_after)>statement_timestamp()) b
  left join lateral (select a.source from sectalk_private.st_v7_device_trust_audit a where a.device_id=d.id
    order by a.id desc limit 1) t on true
  left join lateral (select a.id,a.kind,a.state from sectalk_private.st_v7_device_commands a where a.device_id=d.id
    order by a.requested_at desc,a.id limit 1) c on true
  cross join lateral (select coalesce(jsonb_agg(jsonb_build_object('action',j.action,'reason',j.reason,
    'occurred_at',j.occurred_at) order by j.id desc),'[]'::jsonb) events from (
      select a.* from sectalk_private.st_v7_operator_device_audit a where (a.owner,a.device)=(d.owner,d.id)
      order by a.id desc limit 5) j) h
  where d.owner=p_owner order by d.created_at desc,d.id limit 100;
end $$;

create function public.st_v7_operator_device_action(p_owner uuid,p_device uuid,p_action text,p_reason text)
returns boolean language plpgsql security definer set search_path='' as $$
declare actor_id uuid:=auth.uid(); note text:=btrim(p_reason); target sectalk_private.st_v7_devices;
  pending sectalk_private.st_v7_device_commands; command_id uuid; latest_source text; next_trust text;
begin
  if public.st_v7_account_operator_access()<>'operator' or p_owner is null or p_owner=actor_id or p_device is null then
    raise exception 'Registered device management is unavailable' using errcode='42501';
  end if;
  if p_action is null or p_action not in ('revoke','wipe','cancel_wipe','block_device','mark_managed','clear_managed')
    or note is null or char_length(note) not between 10 and 240 then
    raise exception 'Choose a device action and enter a case reference and reason between 10 and 240 characters' using errcode='22023';
  end if;
  perform sectalk_private.limit_action('v7_account_admin_mutation',8);
  perform 1 from sectalk_private.st_v7_account_operators o where o.user_id=actor_id and o.capability='operator' for share;
  if not found then raise exception 'Registered device management is unavailable' using errcode='42501'; end if;
  perform 1 from auth.users u where u.id=p_owner for update;
  perform 1 from public.st_profiles p where p.id=p_owner for update;
  if not sectalk_private.st_v7_admin_native_target(p_owner) then
    raise exception 'Registered device management is unavailable' using errcode='42501';
  end if;
  select d.* into target from sectalk_private.st_v7_devices d where (d.id,d.owner)=(p_device,p_owner) for update;
  if target.id is null or target.wiped_at is not null then return false; end if;

  if p_action in ('revoke','wipe') then
    command_id:=sectalk_private.st_v7_queue_device_command(p_owner,p_device,p_action,actor_id,note);
    if command_id is null then return false; end if;
  else
    select c.* into pending from sectalk_private.st_v7_device_commands c
      where c.device_id=p_device and c.state in ('pending','delivered') for update;
    if p_action='cancel_wipe' then
      if pending.kind is distinct from 'wipe' or pending.state is distinct from 'pending'
        or not exists(select 1 from sectalk_private.st_v7_operator_device_audit a where a.command=pending.id and a.action='wipe')
        then return false; end if;
      command_id:=pending.id;
      update sectalk_private.st_v7_device_commands set state='cancelled',cancelled_at=clock_timestamp() where id=pending.id;
      update sectalk_private.st_v7_devices set locked_at=pending.previous_lock where id=p_device;
    elsif p_action='block_device' then
      if target.state='blocked' then return false; end if;
      update sectalk_private.st_v7_devices set state='blocked' where id=p_device;
      insert into sectalk_private.st_v7_device_trust_audit(device_id,state,source) values(p_device,'blocked','operator');
      perform sectalk_private.st_v7_end_device_sessions(p_owner,p_device,actor_id,note);
    else
      if pending.id is not null or target.locked_at is not null then return false; end if;
      select a.source into latest_source from sectalk_private.st_v7_device_trust_audit a
        where a.device_id=p_device order by a.id desc limit 1;
      if p_action='mark_managed' and target.state='trusted' then next_trust:='managed';
      elsif p_action='clear_managed' and target.state='managed' and latest_source='operator' then next_trust:='trusted';
      else return false; end if;
      update sectalk_private.st_v7_devices set state=next_trust where id=p_device;
      insert into sectalk_private.st_v7_device_trust_audit(device_id,state,source) values(p_device,next_trust,'operator');
    end if;
    perform realtime.send('{}','device_registry','st:account:'||p_owner,true);
  end if;
  insert into sectalk_private.st_v7_operator_device_audit(actor,owner,device,action,command,reason)
    values(actor_id,p_owner,p_device,p_action,command_id,note);
  return true;
end $$;

-- Explicit provider designation supersedes the operator flag even when the device is already managed.
create or replace function public.st_v7_mark_device_managed(p_owner uuid,p_device uuid,p_managed boolean,p_reference text)
returns boolean language plpgsql security definer set search_path='' as $$
declare previous text; latest_source text; next_state text:=case when p_managed then 'managed' else 'known' end;
begin
  if p_managed is null or p_reference is null or char_length(btrim(p_reference)) not between 1 and 120 then return false; end if;
  perform 1 from auth.users where id=p_owner for update;
  select d.state into previous from sectalk_private.st_v7_devices d where d.owner=p_owner and d.id=p_device for update;
  if not found or previous='blocked' or (not p_managed and previous<>'managed') then return false; end if;
  if previous=next_state then
    select a.source into latest_source from sectalk_private.st_v7_device_trust_audit a
      where a.device_id=p_device order by a.id desc limit 1;
    if latest_source is distinct from 'operator' then return true; end if;
  else
    update sectalk_private.st_v7_devices set state=next_state where id=p_device;
  end if;
  insert into sectalk_private.st_v7_device_trust_audit(device_id,state,source,management_reference)
    values(p_device,next_state,'provider',btrim(p_reference));
  perform realtime.send('{}','device_registry','st:account:'||p_owner,true);
  return true;
end $$;

create or replace function public.st_v7_claim_device_command(p_owner uuid,p_device uuid,p_nonce uuid,p_at timestamptz)
returns jsonb language plpgsql security definer set search_path='' as $$
declare device sectalk_private.st_v7_devices; command sectalk_private.st_v7_device_commands;
begin
  if p_nonce is null or p_at is null or abs(extract(epoch from statement_timestamp()-p_at))>90 then return null; end if;
  select d.* into device from sectalk_private.st_v7_devices d where d.id=p_device and d.owner=p_owner for update;
  if not found then return null; end if;
  delete from sectalk_private.st_v7_device_poll_nonces where device_id=device.id and used_at<=statement_timestamp()-interval '3 minutes';
  insert into sectalk_private.st_v7_device_poll_nonces(device_id,nonce) values(device.id,p_nonce) on conflict do nothing;
  if not found then return null; end if;

  select c.* into command from sectalk_private.st_v7_device_commands c
    where c.device_id=device.id and c.state in ('pending','delivered') for update;
  if command.state='pending' and command.kind='wipe'
    and exists(select 1 from sectalk_private.st_v7_operator_device_audit a where a.command=command.id and a.action='wipe')
    and not sectalk_private.st_v7_admin_native_target(p_owner) then
    update sectalk_private.st_v7_device_commands set state='cancelled',cancelled_at=clock_timestamp() where id=command.id;
    update sectalk_private.st_v7_devices set locked_at=command.previous_lock where id=device.id returning * into device;
    command:=null;
    perform realtime.send('{}','device_registry','st:account:'||p_owner,true);
  elsif command.state='pending' then
    update sectalk_private.st_v7_device_commands
      set state='delivered',delivered_at=clock_timestamp(),receipt=encode(extensions.gen_random_bytes(32),'hex')
      where id=command.id returning * into command;
    if command.kind='wipe' then
      update sectalk_private.st_v7_devices set wiped_at=clock_timestamp() where id=device.id returning * into device;
    end if;
    perform realtime.send('{}','device_registry','st:account:'||p_owner,true);
  end if;
  return jsonb_build_object('locked',device.locked_at is not null,'wiped',device.wiped_at is not null,'blocked',device.state='blocked',
    'command',case when command.id is not null then jsonb_build_object(
      'id',command.id,'kind',command.kind,'receipt',command.receipt) end);
end $$;

drop function public.st_v7_list_device_commands();
create function public.st_v7_list_device_commands()
returns table(device uuid,locked boolean,wiped boolean,command uuid,kind text,state text,requested_at timestamptz,
  delivered_at timestamptz,acknowledged_at timestamptz,cancelled_at timestamptz,operator_wipe_pending boolean)
language plpgsql stable security definer set search_path='' as $$
begin
  if not sectalk_private.st_v7_manage_sessions() then
    raise exception 'Verify this session to read device commands' using errcode='42501';
  end if;
  return query select d.id,d.locked_at is not null,d.wiped_at is not null,c.id,c.kind,c.state,c.requested_at,
    c.delivered_at,c.acknowledged_at,c.cancelled_at,
    coalesce(c.state='pending' and c.kind='wipe',false) and exists(
      select 1 from sectalk_private.st_v7_operator_device_audit a where a.command=c.id and a.action='wipe')
  from sectalk_private.st_v7_devices d
  left join lateral (select a.* from sectalk_private.st_v7_device_commands a where a.device_id=d.id
    order by a.requested_at desc,a.id limit 1) c on true
  where d.owner=auth.uid() order by d.created_at desc,d.id limit 100;
end $$;

revoke all on function sectalk_private.st_v7_end_device_sessions(uuid,uuid,uuid,text),
  sectalk_private.st_v7_queue_device_command(uuid,uuid,text,uuid,text),
  public.st_v7_operator_device_inventory(uuid),public.st_v7_operator_device_action(uuid,uuid,text,text),
  public.st_v7_list_device_commands() from public,anon,authenticated,service_role;
grant execute on function public.st_v7_operator_device_inventory(uuid),public.st_v7_operator_device_action(uuid,uuid,text,text),
  public.st_v7_list_device_commands() to authenticated;
commit;
