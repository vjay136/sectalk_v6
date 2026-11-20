begin;

create or replace function public.st_v7_sensitive_action_status(p_kind text)
returns text language plpgsql stable security definer set search_path='' as $$
declare actor uuid:=auth.uid(); native_session uuid;
begin
  if p_kind is null or p_kind not in ('billing','room_role','export','integration_key','history_transfer')
    or not public.st_v7_current_session_valid() or public.st_v7_account_under_lockdown()
    or public.st_v7_login_risk_status()<>'clear' then return 'unavailable'; end if;
  if p_kind in ('export','integration_key') or exists(select 1 from auth.mfa_factors f where f.user_id=actor and f.status='verified') then
    return case when sectalk_private.st_v7_security_session('totp') then 'verified' else 'totp' end;
  end if;
  native_session:=(auth.jwt()->>'session_id')::uuid;
  if exists(select 1 from auth.mfa_amr_claims a where a.session_id=native_session
      and a.authentication_method='passkey' and a.created_at>statement_timestamp()-interval '5 minutes')
    or sectalk_private.st_v7_security_session('password') then return 'verified'; end if;
  if public.st_v7_passkey_only() then return 'passkey'; end if;
  return 'password';
end $$;

create table sectalk_private.st_v7_group_history_transfers (
  id uuid primary key default gen_random_uuid(),
  group_id uuid not null references sectalk_private.st_group_chats on delete cascade,
  actor uuid not null references auth.users on delete cascade,
  source uuid not null,
  target uuid not null,
  native_session uuid not null,
  epochs integer[] not null check(cardinality(epochs) between 1 and 16),
  expires_at timestamptz not null default (now()+interval '3 minutes'),
  completed_at timestamptz,
  restored integer,
  check(source<>target),
  check((completed_at is null)=(restored is null))
);
create index st_v7_group_history_actor on sectalk_private.st_v7_group_history_transfers(actor,expires_at);
alter table sectalk_private.st_v7_group_history_transfers enable row level security;
revoke all on sectalk_private.st_v7_group_history_transfers from public,anon,authenticated,service_role;

create function sectalk_private.st_v7_group_history_source(p_group uuid)
returns uuid language sql stable security definer set search_path='' as $$
  select d.id from sectalk_private.st_v7_device_sessions s
  join sectalk_private.st_v7_devices d on (d.owner,d.id)=(s.owner,s.device_id)
  join sectalk_private.st_group_members m on (m.group_id,m.actor)=(p_group,d.owner)
  where s.owner=(select auth.uid()) and s.session_id::text=auth.jwt()->>'session_id'
    and d.state in ('trusted','managed') and sectalk_private.st_v7_manage_sessions();
$$;

create function public.st_v7_group_history_targets(p_group uuid)
returns jsonb language sql stable security definer set search_path='' as $$
  select coalesce(jsonb_agg(to_jsonb(available) order by available.created_at desc),'[]'::jsonb)
  from (select d.id,d.created_at,d.state
    from sectalk_private.st_v7_devices d
    cross join lateral (select sectalk_private.st_v7_group_history_source(p_group) device) source
    where d.owner=(select auth.uid()) and d.id<>source.device and d.state in ('trusted','managed')
      and exists(select 1 from sectalk_private.st_group_envelopes e where e.group_id=p_group and e.device=source.device
        and not exists(select 1 from sectalk_private.st_group_envelopes kept
          where (kept.group_id,kept.epoch,kept.device)=(p_group,e.epoch,d.id)))
    order by d.created_at desc limit 32) available;
$$;

create function public.st_v7_prepare_group_history(p_group uuid,p_target uuid)
returns jsonb language plpgsql security definer set search_path='' as $$
declare owner_actor uuid:=auth.uid(); source uuid; destination sectalk_private.st_v7_devices; work sectalk_private.st_v7_group_history_transfers;
declare selected integer[]; originals jsonb;
begin
  source:=sectalk_private.st_v7_group_history_source(p_group);
  if source is null or p_target is null or p_target=source or public.st_v7_sensitive_action_status('history_transfer')<>'verified' then
    raise exception using errcode='42501',message='Fresh sign-in and an approved source browser are required';
  end if;
  select * into destination from sectalk_private.st_v7_devices d where d.owner=owner_actor and d.id=p_target and d.state in ('trusted','managed');
  if not found then raise exception using errcode='42501',message='The approved history destination is unavailable'; end if;
  perform sectalk_private.limit_action('v7_group_history_transfer',8);
  select array_agg(e.epoch order by e.epoch),jsonb_agg(jsonb_build_object('epoch',e.epoch,'ephemeral',e.ephemeral,'sealed',e.sealed) order by e.epoch)
    into selected,originals from (select src.* from sectalk_private.st_group_envelopes src
      where src.group_id=p_group and src.device=source and not exists(
        select 1 from sectalk_private.st_group_envelopes target
          where (target.group_id,target.epoch,target.device)=(p_group,src.epoch,p_target))
      order by src.epoch desc limit 16) e;
  if selected is null then return null; end if;
  delete from sectalk_private.st_v7_group_history_transfers t where t.actor=owner_actor and t.completed_at is null and t.expires_at<now();
  insert into sectalk_private.st_v7_group_history_transfers(group_id,actor,source,target,native_session,epochs)
    values(p_group,owner_actor,source,p_target,(auth.jwt()->>'session_id')::uuid,selected) returning * into work;
  return jsonb_build_object('nonce',work.id,'group',p_group,'source',source,'target',p_target,'original',originals,
    'recipient',jsonb_build_object('owner_id',destination.owner,'device',destination.id,'signing_key',destination.signing_key,
      'agreement_key',destination.agreement_key,'bundle_signature',destination.bundle_signature));
end $$;

create function public.st_v7_group_history_proof(p_nonce uuid)
returns jsonb language sql stable security definer set search_path='' as $$
  select jsonb_build_object('nonce',t.id,'group',t.group_id,'source',t.source,'target',t.target,
    'epochs',t.epochs,'signing',d.signing_key,'actor',t.actor,'session',t.native_session)
  from sectalk_private.st_v7_group_history_transfers t
  join sectalk_private.st_v7_devices d on (d.owner,d.id)=(t.actor,t.source)
  where t.id=p_nonce and t.actor=(select auth.uid()) and t.native_session::text=auth.jwt()->>'session_id'
    and t.source=sectalk_private.st_v7_group_history_source(t.group_id) and t.expires_at>now()
    and public.st_v7_sensitive_action_status('history_transfer')='verified';
$$;

create function public.st_v7_finish_group_history(p_nonce uuid,p_actor uuid,p_session uuid,p_envelopes jsonb)
returns integer language plpgsql security definer set search_path='' as $$
declare work sectalk_private.st_v7_group_history_transfers; matching integer[]; inserted integer;
begin
  select * into work from sectalk_private.st_v7_group_history_transfers where id=p_nonce;
  if not found or work.actor is distinct from p_actor or work.native_session is distinct from p_session then return null; end if;
  perform 1 from sectalk_private.st_group_chats where id=work.group_id for update;
  select * into work from sectalk_private.st_v7_group_history_transfers where id=p_nonce for update;
  if not found or work.expires_at<=now() or sectalk_private.st_v2_active(work.actor) is not true
    or not exists(select 1 from sectalk_private.st_group_members m where (m.group_id,m.actor)=(work.group_id,work.actor))
    or not exists(select 1 from sectalk_private.st_v7_device_sessions s join auth.sessions a on a.id=s.session_id
      where (s.session_id,s.owner,s.device_id)=(work.native_session,work.actor,work.source) and a.user_id=work.actor
        and (a.not_after is null or a.not_after>now()))
    or (select count(*) from sectalk_private.st_v7_devices d where d.owner=work.actor and d.id in (work.source,work.target)
      and d.state in ('trusted','managed'))<>2 then return null; end if;
  if work.completed_at is not null then return work.restored; end if;
  if jsonb_typeof(p_envelopes) is distinct from 'array' or jsonb_array_length(p_envelopes)<>cardinality(work.epochs) then return null; end if;
  select array_agg(candidate.epoch order by candidate.epoch) into matching
    from jsonb_to_recordset(p_envelopes) as candidate(epoch integer,sealed text,ephemeral text)
    where candidate.sealed ~ '^[A-Za-z0-9_-]{80}$' and candidate.ephemeral ~ '^[A-Za-z0-9_-]{87}$'
      and exists(select 1 from sectalk_private.st_group_envelopes e
        where (e.group_id,e.epoch,e.device)=(work.group_id,candidate.epoch,work.source));
  if matching is distinct from work.epochs then return null; end if;
  insert into sectalk_private.st_group_envelopes(group_id,epoch,device,sealed,ephemeral)
    select work.group_id,e.epoch,work.target,e.sealed,e.ephemeral
    from jsonb_to_recordset(p_envelopes) as e(epoch integer,sealed text,ephemeral text)
    on conflict(group_id,epoch,device) do nothing;
  get diagnostics inserted=row_count;
  update sectalk_private.st_v7_group_history_transfers set completed_at=clock_timestamp(),restored=inserted where id=p_nonce;
  perform realtime.send(jsonb_build_object('group',work.group_id),'group_history_transferred','st:account:'||work.actor,true);
  return inserted;
end $$;

revoke all on function sectalk_private.st_v7_group_history_source(uuid),public.st_v7_group_history_targets(uuid),
  public.st_v7_prepare_group_history(uuid,uuid),public.st_v7_group_history_proof(uuid),
  public.st_v7_finish_group_history(uuid,uuid,uuid,jsonb) from public,anon,authenticated,service_role;
grant execute on function public.st_v7_group_history_targets(uuid),public.st_v7_prepare_group_history(uuid,uuid),
  public.st_v7_group_history_proof(uuid) to authenticated;
grant execute on function public.st_v7_finish_group_history(uuid,uuid,uuid,jsonb) to service_role;

commit;
