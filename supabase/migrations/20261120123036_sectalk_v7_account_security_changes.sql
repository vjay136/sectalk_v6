begin;

create table sectalk_private.st_v7_account_security_changes (
  user_id uuid primary key references auth.users on delete cascade,
  kind text not null check(kind in ('email','authenticator','recovery')),
  state text not null check(state in ('pending','approved','applying','completed','cancelled')),
  binding bytea,
  requested_at timestamptz not null,
  ready_at timestamptz not null,
  expires_at timestamptz not null,
  approved_until timestamptz
);
create table sectalk_private.st_v7_account_security_events (
  id bigint generated always as identity primary key,
  user_id uuid not null references auth.users on delete cascade,
  kind text not null check(kind in ('email','authenticator','recovery','password')),
  action text not null check(action in ('requested','cancelled','completed')),
  occurred_at timestamptz not null default clock_timestamp()
);
create index st_v7_account_security_events_account on sectalk_private.st_v7_account_security_events(user_id,id desc);
alter table sectalk_private.st_v7_account_security_changes enable row level security;
alter table sectalk_private.st_v7_account_security_events enable row level security;
revoke all on sectalk_private.st_v7_account_security_changes,sectalk_private.st_v7_account_security_events
  from public,anon,authenticated,service_role;

create function sectalk_private.st_v7_security_session(p_method text default null)
returns boolean language sql stable security definer set search_path='' as $$
  select exists(select 1 from auth.sessions s
    where s.id::text=auth.jwt()->>'session_id' and s.user_id=auth.uid()
      and (s.not_after is null or s.not_after>now())
      and (p_method is null or exists(select 1 from auth.mfa_amr_claims a where a.session_id=s.id
        and a.authentication_method=p_method and a.updated_at>statement_timestamp()-interval '5 minutes'))
      and (p_method is distinct from 'totp' or (auth.jwt()->>'aal'='aal2' and s.aal='aal2'
        and exists(select 1 from auth.mfa_factors f where f.id=s.factor_id and f.user_id=s.user_id
          and f.status='verified' and f.factor_type='totp')))
      and (p_method is distinct from 'password' or (auth.jwt()->>'aal'='aal1' and coalesce(s.aal,'aal1')='aal1')))
$$;

create function sectalk_private.st_v7_record_security_event(p_user uuid,p_kind text,p_action text)
returns void language plpgsql set search_path='' as $$
begin
  insert into sectalk_private.st_v7_account_security_events(user_id,kind,action) values(p_user,p_kind,p_action);
  perform realtime.send('{}','account_security_lifecycle','st:account:'||p_user,true);
end $$;

create function public.st_v7_account_security_status()
returns jsonb language sql stable security definer set search_path='' as $$
  select jsonb_build_object('pending',(select jsonb_build_object(
    'kind',r.kind,'requested_at',r.requested_at,'ready_at',r.ready_at,'expires_at',r.expires_at,
    'provider_pending',r.kind='email' and coalesce(u.email_change,'')<>'')
    from sectalk_private.st_v7_account_security_changes r where r.user_id=u.id
      and r.state in ('pending','approved') and r.expires_at>now()))
  from auth.users u where u.id=auth.uid() and sectalk_private.st_v7_security_session()
$$;

create function public.st_v7_account_security_events()
returns table(id text,kind text,action text,occurred_at timestamptz)
language sql stable security definer set search_path='' as $$
  select e.id::text,e.kind,e.action,e.occurred_at from sectalk_private.st_v7_account_security_events e
  where e.user_id=auth.uid() order by e.id desc limit 25
$$;

create function sectalk_private.st_v7_finish_authenticator_reset(p_actor uuid,p_kind text)
returns void language plpgsql set search_path='' as $$
begin
  update sectalk_private.st_v7_account_security_changes set state='applying' where user_id=p_actor;
  delete from sectalk_private.account_recovery_sets where user_id=p_actor;
  delete from auth.mfa_factors where user_id=p_actor;
  delete from auth.sessions where user_id=p_actor;
  update sectalk_private.st_v7_account_security_changes
    set state='completed',binding=null,approved_until=null where user_id=p_actor;
  if p_kind='recovery' then
    insert into sectalk_private.account_recovery_events(user_id) values(p_actor);
  end if;
  perform sectalk_private.st_v7_record_security_event(p_actor,p_kind,'completed');
end $$;

create function public.st_v7_account_security_change(p_action text,p_kind text default null,p_value text default null)
returns text language plpgsql security definer set search_path='' as $$
declare
  actor uuid:=auth.uid();
  account auth.users;
  pending sectalk_private.st_v7_account_security_changes;
  current_time_utc timestamptz:=clock_timestamp();
  target text:=lower(btrim(p_value));
  token bytea;
  has_factor boolean;
begin
  if not sectalk_private.st_v7_security_session() then
    raise exception 'Sign in to manage account security' using errcode='42501';
  end if;
  select u.* into account from auth.users u where u.id=actor for update;
  select r.* into pending from sectalk_private.st_v7_account_security_changes r where r.user_id=actor for update;
  if p_action='cancel' then
    if pending.state not in ('pending','approved') or pending.user_id is null then return 'cancelled'; end if;
    update sectalk_private.st_v7_account_security_changes set state='cancelled',binding=null,approved_until=null where user_id=actor;
    if pending.kind='email' then
      update auth.users set email_change='',email_change_token_current='',email_change_token_new='',email_change_confirm_status=0
        where id=actor and coalesce(email_change,'')<>'';
    end if;
    perform sectalk_private.st_v7_record_security_event(actor,pending.kind,'cancelled');
    return 'cancelled';
  end if;
  if p_kind is null or p_kind not in ('email','authenticator') or p_action is null or p_action not in ('request','continue') then
    raise exception 'Choose a supported security change' using errcode='22023';
  end if;
  select exists(select 1 from auth.mfa_factors f where f.user_id=actor and f.status='verified') into has_factor;
  if not sectalk_private.st_v7_security_session(case when has_factor then 'totp' else 'password' end)
    or (p_kind='authenticator' and (not has_factor or exists(select 1 from sectalk_private.staff where user_id=actor))) then
    raise exception 'Verify your current account credentials to continue' using errcode='42501';
  end if;
  if p_kind='email' then
    if account.email_confirmed_at is null or target is null or length(target)>254 or target=lower(account.email)
      or target !~ '^[^[:space:]@]+@[^[:space:]@]+\.[^[:space:]@]+$' then
      raise exception 'Enter a different email address for your confirmed account' using errcode='22023';
    end if;
    token:=extensions.digest(target,'sha256');
  end if;
  perform sectalk_private.limit_action('v7_account_security_change',8);
  if p_action='request' then
    if pending.state in ('pending','approved') and pending.expires_at>current_time_utc then
      raise exception 'Cancel the active account security request before starting another' using errcode='22023';
    end if;
    if p_kind='email' and coalesce(account.email_change,'')<>'' then
      update auth.users set email_change='',email_change_token_current='',email_change_token_new='',email_change_confirm_status=0 where id=actor;
    end if;
    insert into sectalk_private.st_v7_account_security_changes(user_id,kind,state,binding,requested_at,ready_at,expires_at)
      values(actor,p_kind,'pending',token,current_time_utc,current_time_utc+interval '24 hours',current_time_utc+interval '7 days')
      on conflict(user_id) do update set kind=excluded.kind,state=excluded.state,binding=excluded.binding,
        requested_at=excluded.requested_at,ready_at=excluded.ready_at,expires_at=excluded.expires_at,approved_until=null;
    perform sectalk_private.st_v7_record_security_event(actor,p_kind,'requested');
    return 'pending';
  end if;
  if pending.kind is distinct from p_kind or pending.state not in ('pending','approved')
    or pending.ready_at>current_time_utc or pending.expires_at<=current_time_utc or pending.binding is distinct from token then
    raise exception 'This security request is unavailable or still cooling off' using errcode='22023';
  end if;
  if p_kind='email' then
    if coalesce(account.email_change,'')<>'' then return 'confirmation_sent'; end if;
    update sectalk_private.st_v7_account_security_changes
      set state='approved',approved_until=current_time_utc+interval '5 minutes' where user_id=actor;
    return 'send_confirmation';
  end if;
  perform sectalk_private.st_v7_finish_authenticator_reset(actor,p_kind);
  return 'completed';
end $$;

create function public.st_v7_recovery_security_reset(p_code text)
returns text language plpgsql security definer set search_path='' as $$
declare
  actor uuid:=auth.uid();
  pending sectalk_private.st_v7_account_security_changes;
  event_time timestamptz:=clock_timestamp();
  normal_code text;
  token bytea;
begin
  if not sectalk_private.st_v7_security_session('password') or exists(select 1 from sectalk_private.staff where user_id=actor)
    or p_code is null or length(p_code)>64 then return 'unavailable'; end if;
  perform 1 from auth.users where id=actor for update;
  perform sectalk_private.limit_action('account_authenticator_recovery',5);
  normal_code:=upper(regexp_replace(p_code,'[[:space:]-]','','g'));
  if normal_code !~ '^[0-9A-F]{32}$' then return 'unavailable'; end if;
  token:=extensions.digest(normal_code,'sha256');
  if not exists(select 1 from sectalk_private.account_recovery_sets r
    join auth.mfa_factors f on f.id=r.factor_id and f.user_id=r.user_id and f.status='verified' and f.factor_type='totp'
    where r.user_id=actor and token=any(r.code_hashes))
    or (select count(*) from auth.mfa_factors f where f.user_id=actor and f.status='verified')<>1 then return 'unavailable'; end if;
  select r.* into pending from sectalk_private.st_v7_account_security_changes r where r.user_id=actor for update;
  if pending.state in ('pending','approved') and pending.expires_at>event_time then
    if pending.kind<>'recovery' or pending.binding is distinct from token then return 'unavailable'; end if;
    if pending.ready_at>event_time then return 'pending'; end if;
    perform sectalk_private.st_v7_finish_authenticator_reset(actor,'recovery');
    return 'completed';
  end if;
  insert into sectalk_private.st_v7_account_security_changes(user_id,kind,state,binding,requested_at,ready_at,expires_at)
    values(actor,'recovery','pending',token,event_time,event_time+interval '24 hours',event_time+interval '7 days')
    on conflict(user_id) do update set kind=excluded.kind,state=excluded.state,binding=excluded.binding,
      requested_at=excluded.requested_at,ready_at=excluded.ready_at,expires_at=excluded.expires_at,approved_until=null;
  perform sectalk_private.st_v7_record_security_event(actor,'recovery','requested');
  return 'pending';
end $$;

create or replace function public.st_v7_recover_authenticator(p_code text)
returns boolean language sql security definer set search_path='' as $$
  select public.st_v7_recovery_security_reset(p_code)='completed'
$$;

-- GoTrue writes these columns after sending confirmation tokens. Enforce the
-- same approved destination at release and both mailbox proofs at final change.
create function sectalk_private.st_v7_guard_account_email()
returns trigger language plpgsql security definer set search_path='' as $$
declare pending sectalk_private.st_v7_account_security_changes;
begin
  -- Administrative SQL is outside the provider/client confirmation workflow.
  if session_user='postgres' and current_setting('role')='none' then return new; end if;
  if new.email is distinct from old.email and old.email_confirmed_at is not null then
    select r.* into pending from sectalk_private.st_v7_account_security_changes r where r.user_id=old.id for update;
    if pending.kind is distinct from 'email' or pending.state is distinct from 'approved'
      or pending.expires_at<=clock_timestamp() or pending.ready_at>clock_timestamp()
      or old.email_change_confirm_status is distinct from 1
      or nullif(lower(old.email_change),'') is distinct from lower(new.email)
      or pending.binding is distinct from extensions.digest(lower(new.email),'sha256') then
      raise exception 'Account email change requires both confirmations and an approved request' using errcode='42501';
    end if;
    update sectalk_private.st_v7_account_security_changes
      set state='completed',binding=null,approved_until=null where user_id=old.id;
    perform sectalk_private.st_v7_record_security_event(old.id,'email','completed');
  elsif nullif(new.email_change,'') is not null
    and (new.email_change is distinct from old.email_change or new.email_change_sent_at is distinct from old.email_change_sent_at) then
    select r.* into pending from sectalk_private.st_v7_account_security_changes r where r.user_id=old.id for update;
    if pending.kind is distinct from 'email' or pending.state is distinct from 'approved'
      or coalesce(pending.approved_until,clock_timestamp())<=clock_timestamp()
      or pending.binding is distinct from extensions.digest(lower(new.email_change),'sha256') then
      raise exception 'Account email change requires an approved security request' using errcode='42501';
    end if;
  end if;
  return new;
end $$;
create trigger st_v7_guard_account_email before update of email,email_change,email_change_sent_at on auth.users
  for each row execute function sectalk_private.st_v7_guard_account_email();

create function sectalk_private.st_v7_guard_factor_removal()
returns trigger language plpgsql security definer set search_path='' as $$
begin
  if session_user='postgres' and current_setting('role')='none' then
    if tg_op='DELETE' then return old; end if;
    return new;
  end if;
  if old.status='verified' and exists(select 1 from auth.users where id=old.user_id)
    and (tg_op='DELETE' or new.status is distinct from old.status or new.user_id is distinct from old.user_id
      or new.factor_type is distinct from old.factor_type)
    and not exists(select 1 from sectalk_private.st_v7_account_security_changes r
      where r.user_id=old.user_id and r.kind in ('authenticator','recovery') and r.state='applying') then
    raise exception 'Verified factors require the deliberate account reset workflow' using errcode='42501';
  end if;
  if tg_op='DELETE' then return old; end if;
  return new;
end $$;
create trigger st_v7_guard_factor_removal before delete or update of status,user_id,factor_type on auth.mfa_factors
  for each row execute function sectalk_private.st_v7_guard_factor_removal();

create function sectalk_private.st_v7_notify_password_change()
returns trigger language plpgsql security definer set search_path='' as $$
begin
  if nullif(old.encrypted_password,'') is not null and nullif(new.encrypted_password,'') is not null
    and old.encrypted_password is distinct from new.encrypted_password then
    perform sectalk_private.st_v7_record_security_event(old.id,'password','completed');
  end if;
  return new;
end $$;
create trigger st_v7_notify_password_change after update of encrypted_password on auth.users
  for each row execute function sectalk_private.st_v7_notify_password_change();

revoke all on function sectalk_private.st_v7_security_session(text),sectalk_private.st_v7_record_security_event(uuid,text,text),
  sectalk_private.st_v7_finish_authenticator_reset(uuid,text),sectalk_private.st_v7_guard_account_email(),
  sectalk_private.st_v7_guard_factor_removal(),sectalk_private.st_v7_notify_password_change(),
  public.st_v7_account_security_status(),public.st_v7_account_security_events(),
  public.st_v7_account_security_change(text,text,text),public.st_v7_recovery_security_reset(text)
  from public,anon,authenticated,service_role;
grant execute on function public.st_v7_account_security_status(),public.st_v7_account_security_events(),
  public.st_v7_account_security_change(text,text,text),public.st_v7_recovery_security_reset(text) to authenticated;
commit;
