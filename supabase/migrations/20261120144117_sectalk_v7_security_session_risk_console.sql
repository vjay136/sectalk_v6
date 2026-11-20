begin;

alter table sectalk_private.st_v7_signin_risk add column if not exists operator_requested_at timestamptz;
alter table sectalk_private.st_v7_account_admin_audit drop constraint st_v7_account_admin_audit_action_check;
alter table sectalk_private.st_v7_account_admin_audit add constraint st_v7_account_admin_audit_action_check
  check(action in ('force_logout','reset_requested','reset_completed','session_revoked','session_step_up'));

create or replace function public.st_v7_login_risk_status()
returns text language plpgsql stable security definer set search_path='' as $$
declare
  actor uuid:=auth.uid();
  token jsonb:=auth.jwt();
  signed_session uuid;
  risk sectalk_private.st_v7_signin_risk;
  proof_at timestamptz;
begin
  if not public.st_v7_current_session_valid() then return 'inactive'; end if;
  signed_session:=(token->>'session_id')::uuid;
  select r.* into risk from sectalk_private.st_v7_signin_risk r where r.session_id=signed_session and r.user_id=actor;
  if exists(select 1 from auth.mfa_factors f where f.user_id=actor and f.status='verified') then
    if token->>'aal'='aal2' and exists(
      select 1 from auth.sessions s join auth.mfa_factors f
       on f.id=s.factor_id and f.user_id=s.user_id and f.status='verified' and f.factor_type='totp'
      join auth.mfa_amr_claims a on a.session_id=s.id and a.authentication_method='totp'
      where s.id=signed_session and s.user_id=actor and s.aal='aal2'
        and (risk.operator_requested_at is null or (
          a.updated_at>=risk.operator_requested_at and exists (
            select 1 from jsonb_array_elements(case when jsonb_typeof(token->'amr')='array' then token->'amr' else '[]'::jsonb end) as claim
            where claim->>'method'='totp' and claim->>'timestamp' ~ '^[0-9]{1,12}$'
              and (claim->>'timestamp')::bigint>extract(epoch from date_trunc('second',risk.operator_requested_at))
              and (claim->>'timestamp')::bigint>=extract(epoch from date_trunc('second',a.updated_at))
          )))) then return 'clear'; end if;
    return 'authenticator';
  end if;
  if risk.session_id is null then return 'clear'; end if;
  if risk.operator_requested_at is not null then return 'authenticator'; end if;
  proof_at:=least(risk.mailbox_verified_at,risk.trusted_device_verified_at);
  if proof_at is not null then
    if token->>'iat' ~ '^[0-9]{1,12}$'
      and to_timestamp((token->>'iat')::double precision)>date_trunc('second',proof_at) then
      return 'clear';
    end if;
    return 'refresh';
  end if;
  return 'email';
end $$;

create or replace function public.st_v7_security_risk_sessions(p_impossible_travel boolean default false)
returns table(account_id uuid,handle text,display_name text,session_id uuid,browser text,last_active_at timestamptz,
  assessed_at timestamptz,signals text[],step_up_state text)
language plpgsql security definer set search_path='' as $$
begin
  if public.st_v7_account_operator_access() not in ('operator','reviewer') then
    raise exception 'Security session review is unavailable' using errcode='42501';
  end if;
  perform sectalk_private.limit_action('v7_security_risk_sessions',60);
  return query
    select s.user_id,p.handle,p.name,s.id,coalesce(sectalk_private.st_v7_login_browser(s.user_agent),'Browser or app'),
      coalesce(s.refreshed_at at time zone 'UTC',s.created_at),r.assessed_at,r.signals,
      case when pending.operator_requested_at is not null and not exists(select 1 from auth.mfa_amr_claims a
        where a.session_id=s.id and a.authentication_method='totp'
          and date_trunc('second',a.updated_at)>date_trunc('second',pending.operator_requested_at)) then 'pending'
        when pending.operator_requested_at is not null then 'verified'
        when exists(select 1 from auth.mfa_factors f where f.user_id=s.user_id and f.status='verified' and f.factor_type='totp') then 'available'
        else 'unavailable' end
    from sectalk_private.st_v7_session_scores r join auth.sessions s on s.id=r.session_id and s.user_id=r.user_id
    join public.st_profiles p on p.id=s.user_id
    left join sectalk_private.st_v7_signin_risk pending on pending.session_id=s.id and pending.user_id=s.user_id
    where r.score>=60 and s.user_id<>auth.uid() and sectalk_private.st_v7_admin_native_target(s.user_id)
      and sectalk_private.st_v7_session_deadline(s.created_at,s.refreshed_at,s.not_after)>statement_timestamp()
      and (p_impossible_travel is not true or 'impossible_travel'=any(r.signals))
    order by r.assessed_at desc,s.id limit 100;
end $$;

create or replace function public.st_v7_require_risk_session_totp(p_user uuid,p_session uuid,p_reason text)
returns boolean language plpgsql security definer set search_path='' as $$
declare actor uuid:=auth.uid(); reason text:=btrim(p_reason); observed timestamptz;
begin
  if public.st_v7_account_operator_access()<>'operator' or p_user is null or p_user=actor or p_session is null then
    raise exception 'Session verification request is unavailable' using errcode='42501';
  end if;
  if reason is null or char_length(reason) not between 10 and 240 then
    raise exception 'Enter a case reference and reason between 10 and 240 characters' using errcode='22023';
  end if;
  perform sectalk_private.limit_action('v7_account_admin_mutation',8);
  perform 1 from sectalk_private.st_v7_account_operators a where a.user_id=actor and a.capability='operator' for share;
  if not found then raise exception 'Session verification request is unavailable' using errcode='42501'; end if;
  perform 1 from auth.users u where u.id=p_user for update;
  if not sectalk_private.st_v7_admin_native_target(p_user) then
    raise exception 'Session verification request is unavailable' using errcode='42501';
  end if;
  select s.created_at into observed from auth.sessions s join sectalk_private.st_v7_session_scores score
   on score.session_id=s.id and score.user_id=s.user_id and score.score>=60
  where s.id=p_session and s.user_id=p_user
    and sectalk_private.st_v7_session_deadline(s.created_at,s.refreshed_at,s.not_after)>statement_timestamp()
  for update of s;
  if not found or not exists(select 1 from auth.mfa_factors f where f.user_id=p_user and f.factor_type='totp' and f.status='verified')
    then return false; end if;
  insert into sectalk_private.st_v7_signin_risk as current(session_id,user_id,observed_at,operator_requested_at)
    values(p_session,p_user,observed,clock_timestamp()) on conflict(session_id) do update
    set operator_requested_at=excluded.operator_requested_at
    where current.user_id=excluded.user_id and (current.operator_requested_at is null or exists(
      select 1 from auth.mfa_amr_claims a where a.session_id=p_session and a.authentication_method='totp'
        and date_trunc('second',a.updated_at)>date_trunc('second',current.operator_requested_at)));
  if not found then return false; end if;
  insert into sectalk_private.st_v7_account_admin_audit(actor,target,action,request_id,reason)
    values(actor,p_user,'session_step_up',p_session,reason);
  perform realtime.send('{}','assurance_changed','st:assurance:'||p_user,true);
  return true;
end $$;

-- This topic has no application data and remains reachable during assurance step-up.
-- Other app topics continue to apply their usual authenticated rejoin rules.
drop policy if exists st_v7_assurance_hint on realtime.messages;
create policy st_v7_assurance_hint on realtime.messages for select to authenticated
  using(extension='broadcast' and (select realtime.topic())='st:assurance:'||(select auth.uid())::text
    and (select public.st_v7_current_session_valid()));
drop policy if exists st_v7_assurance_hint_scope on realtime.messages;
create policy st_v7_assurance_hint_scope on realtime.messages as restrictive for select to public
  using(coalesce((select realtime.topic()),'') not like 'st:assurance:%'
    or (extension='broadcast' and (select realtime.topic())='st:assurance:'||(select auth.uid())::text));
drop policy if exists st_v7_assurance_hint_server_only on realtime.messages;
create policy st_v7_assurance_hint_server_only on realtime.messages as restrictive for insert to public
  with check(coalesce((select realtime.topic()),'') not like 'st:assurance:%');
alter policy st_v7_signin_gate_broadcast on realtime.messages using(
  ((select realtime.topic())='st:assurance:'||(select auth.uid())::text)
  or not (select public.st_v7_step_up_pending()));

create or replace function sectalk_private.st_v7_hint_operator_session_end()
returns trigger language plpgsql security definer set search_path='' as $$
begin
  if new.action in ('session_revoked','force_logout','reset_completed') then
    perform realtime.send('{}','assurance_changed','st:assurance:'||new.target,true);
  end if;
  return new;
end $$;
drop trigger if exists st_v7_hint_operator_session_end on sectalk_private.st_v7_account_admin_audit;
create trigger st_v7_hint_operator_session_end after insert on sectalk_private.st_v7_account_admin_audit
  for each row execute function sectalk_private.st_v7_hint_operator_session_end();

revoke all on function public.st_v7_security_risk_sessions(boolean),public.st_v7_require_risk_session_totp(uuid,uuid,text)
  from public,anon,authenticated,service_role;
revoke all on function sectalk_private.st_v7_hint_operator_session_end() from public,anon,authenticated,service_role;
grant execute on function public.st_v7_security_risk_sessions(boolean),public.st_v7_require_risk_session_totp(uuid,uuid,text)
  to authenticated;

commit;
