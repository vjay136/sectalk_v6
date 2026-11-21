begin;
create table sectalk_private.st_v8_disclosure_operators (
  account uuid primary key references sectalk_private.staff(user_id) on delete cascade
);
create table sectalk_private.st_v8_disclosure_intake (
  id uuid primary key,
  receipt_hash text not null unique check(receipt_hash ~ '^[0-9a-f]{64}$'),
  envelope text not null check(length(envelope) between 48 and 22000 and envelope ~ '^[A-Za-z0-9_.-]+$'),
  state text not null default 'received' check(state in ('received','reviewing','resolved','dismissed')),
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);
create index on sectalk_private.st_v8_disclosure_intake(state,created_at desc,id);
create table sectalk_private.st_v8_disclosure_audit (
  id bigint generated always as identity primary key,
  report uuid not null references sectalk_private.st_v8_disclosure_intake on delete cascade,
  actor uuid references auth.users on delete set null,
  action text not null check(action in ('received','opened','reviewing','resolved','dismissed')),
  created_at timestamptz not null default now()
);
create index on sectalk_private.st_v8_disclosure_audit(report,id);
create table sectalk_private.st_v8_disclosure_limits (
  window_id bigint not null,
  scope text not null,
  used integer not null check(used>0),
  primary key(window_id,scope)
);
alter table sectalk_private.st_v8_disclosure_operators enable row level security;
alter table sectalk_private.st_v8_disclosure_intake enable row level security;
alter table sectalk_private.st_v8_disclosure_audit enable row level security;
alter table sectalk_private.st_v8_disclosure_limits enable row level security;
revoke all on sectalk_private.st_v8_disclosure_operators,sectalk_private.st_v8_disclosure_intake,
  sectalk_private.st_v8_disclosure_audit,sectalk_private.st_v8_disclosure_limits from public,anon,authenticated,service_role;

create function public.st_v8_disclosure_submit(p_id uuid,p_receipt text,p_envelope text,p_scope text default null)
returns text language plpgsql security definer set search_path='' as $$
declare tick bigint:=floor(extract(epoch from clock_timestamp())/900); allowed integer;
begin
  if p_scope is not null and p_scope !~ '^[0-9a-f]{64}$' then return 'invalid'; end if;
  if p_id is null or p_receipt is null or p_receipt !~ '^[0-9a-f]{64}$'
    or p_envelope is null or length(p_envelope) not between 48 and 22000
    or p_envelope !~ '^v1\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$' then return 'invalid'; end if;
  if p_scope is not null then
    insert into sectalk_private.st_v8_disclosure_limits as limits values(tick,p_scope,1)
      on conflict(window_id,scope) do update set used=limits.used+1 where limits.used<5 returning used into allowed;
    if not found then return 'limited'; end if;
  end if;
  insert into sectalk_private.st_v8_disclosure_limits as limits values(tick,'all',1)
    on conflict(window_id,scope) do update set used=limits.used+1 where limits.used<40 returning used into allowed;
  if not found then return 'limited'; end if;
  delete from sectalk_private.st_v8_disclosure_limits where window_id<tick-96;
  insert into sectalk_private.st_v8_disclosure_intake(id,receipt_hash,envelope) values(p_id,p_receipt,p_envelope);
  insert into sectalk_private.st_v8_disclosure_audit(report,action) values(p_id,'received');
  return 'received';
end $$;

create function public.st_v8_disclosure_access()
returns text language sql stable security definer set search_path='' as $$
  select case when not exists(select 1 from sectalk_private.st_v8_disclosure_operators where account=auth.uid())
    or not coalesce(sectalk_private.st_v2_active(auth.uid()),false) or not coalesce(public.st_v7_current_session_valid(),false)
    or public.st_v7_login_risk_status() is distinct from 'clear' or public.st_v7_account_under_lockdown()
    then 'none' when sectalk_private.st_v7_security_session('totp') then 'verified' else 'mfa' end
$$;
create function public.st_v8_disclosure_queue(p_action text,p_id uuid default null,p_state text default null)
returns jsonb language plpgsql security definer set search_path='' as $$
declare entry sectalk_private.st_v8_disclosure_intake;
begin
  if public.st_v8_disclosure_access() is distinct from 'verified' then
    raise exception 'Fresh disclosure operator assurance required' using errcode='42501';
  end if;
  if p_action='list' and p_state in ('received','reviewing','resolved','dismissed') then
    return coalesce((select jsonb_agg(to_jsonb(q)) from (
      select id,state,created_at,updated_at from sectalk_private.st_v8_disclosure_intake
      where state=p_state order by created_at desc,id limit 50
    ) q),'[]');
  elsif p_action='open' then
    select * into entry from sectalk_private.st_v8_disclosure_intake where id=p_id;
    if not found then return null; end if;
    insert into sectalk_private.st_v8_disclosure_audit(report,actor,action) values(p_id,auth.uid(),'opened');
    return jsonb_build_object('id',entry.id,'state',entry.state,'envelope',entry.envelope,
      'created_at',entry.created_at,'updated_at',entry.updated_at);
  elsif p_action='move' then
    update sectalk_private.st_v8_disclosure_intake set state=p_state,updated_at=now() where id=p_id and
      ((state='received' and p_state='reviewing') or (state='reviewing' and p_state in ('resolved','dismissed')))
      returning * into entry;
    if not found then return null; end if;
    insert into sectalk_private.st_v8_disclosure_audit(report,actor,action) values(p_id,auth.uid(),p_state);
    return jsonb_build_object('state',entry.state);
  end if;
  return null;
end $$;
revoke all on function public.st_v8_disclosure_submit(uuid,text,text,text),public.st_v8_disclosure_access(),
  public.st_v8_disclosure_queue(text,uuid,text) from public,anon,authenticated,service_role;
grant execute on function public.st_v8_disclosure_submit(uuid,text,text,text) to service_role;
grant execute on function public.st_v8_disclosure_access(),public.st_v8_disclosure_queue(text,uuid,text) to authenticated;
commit;
