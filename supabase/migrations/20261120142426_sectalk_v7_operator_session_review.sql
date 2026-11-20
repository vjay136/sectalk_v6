begin;

alter table sectalk_private.st_v7_account_admin_audit drop constraint st_v7_account_admin_audit_action_check;
alter table sectalk_private.st_v7_account_admin_audit add constraint st_v7_account_admin_audit_action_check
  check(action in ('force_logout','reset_requested','reset_completed','session_revoked'));

create or replace function public.st_v7_account_data_unavailable()
returns boolean language sql stable security definer set search_path='' as $$
  select exists(select 1 from sectalk_private.st_v7_account_lockdowns l where l.user_id=auth.uid()
    and (l.released_at is null or not public.st_v7_current_session_valid()))
    or (not public.st_v7_current_session_valid() and (
      exists(select 1 from sectalk_private.st_v7_account_admin_audit a where a.target=auth.uid()
        and a.action in ('force_logout','reset_completed','session_revoked'))
      or exists(select 1 from sectalk_private.st_v7_account_security_events e where e.user_id=auth.uid()
        and e.kind in ('recovery','authenticator') and e.action='completed')));
$$;

create function public.st_v7_account_admin_sessions(p_user uuid)
returns table(id uuid,browser text,started_at timestamptz,last_active_at timestamptz,expires_at timestamptz,
  assurance text,risk text,signals text[])
language plpgsql security definer set search_path='' as $$
begin
  if public.st_v7_account_operator_access() not in ('operator','reviewer') or p_user=auth.uid()
    or not sectalk_private.st_v7_admin_native_target(p_user) then
    raise exception 'Account session review is unavailable' using errcode='42501';
  end if;
  perform sectalk_private.limit_action('v7_account_admin_sessions',60);
  return query select s.id,
    case when s.user_agent ilike '%Edg/%' then 'Edge'
         when s.user_agent ilike '%Chrome/%' then 'Chrome'
         when s.user_agent ilike '%Firefox/%' then 'Firefox'
         when s.user_agent ilike '%Safari/%' then 'Safari'
         else 'Browser or app' end,
    s.created_at,coalesce(s.refreshed_at at time zone 'UTC',s.created_at),
    sectalk_private.st_v7_session_deadline(s.created_at,s.refreshed_at,s.not_after),
    case when s.aal::text='aal2' then 'Authenticator verified' else 'Password verified' end,
    case when score.score>=60 then 'High' when score.score>=25 then 'Elevated'
         when score.score is not null then 'Low' else 'Unassessed' end,
    coalesce(score.signals,'{}'::text[])
  from auth.sessions s left join sectalk_private.st_v7_session_scores score
    on score.session_id=s.id and score.user_id=s.user_id
  where s.user_id=p_user and sectalk_private.st_v7_session_deadline(s.created_at,s.refreshed_at,s.not_after)>statement_timestamp()
  order by coalesce(s.refreshed_at at time zone 'UTC',s.created_at) desc,s.id limit 101;
end $$;

create function public.st_v7_account_admin_revoke_session(p_user uuid,p_session uuid,p_reason text)
returns boolean language plpgsql security definer set search_path='' as $$
declare actor_id uuid:=auth.uid(); reason text:=btrim(p_reason);
begin
  if public.st_v7_account_operator_access()<>'operator' or p_user is null or p_user=actor_id or p_session is null then
    raise exception 'Account session revocation is unavailable' using errcode='42501';
  end if;
  if reason is null or char_length(reason) not between 10 and 240 then
    raise exception 'Enter a case reference and reason between 10 and 240 characters' using errcode='22023';
  end if;
  perform sectalk_private.limit_action('v7_account_admin_mutation',8);
  perform 1 from sectalk_private.st_v7_account_operators o where o.user_id=actor_id and o.capability='operator' for share;
  if not found then raise exception 'Account session revocation is unavailable' using errcode='42501'; end if;
  perform 1 from auth.users u where u.id=p_user for update;
  perform 1 from public.st_profiles p where p.id=p_user for update;
  if not sectalk_private.st_v7_admin_native_target(p_user) then
    raise exception 'Account session revocation is unavailable' using errcode='42501';
  end if;
  delete from auth.sessions s where s.user_id=p_user and s.id=p_session;
  if not found then return false; end if;
  insert into sectalk_private.st_v7_account_admin_audit(actor,target,action,request_id,reason)
    values(actor_id,p_user,'session_revoked',p_session,reason);
  perform realtime.send('{}','session_lifecycle','st:account:'||p_user,true);
  return true;
end $$;

revoke all on function public.st_v7_account_admin_sessions(uuid),public.st_v7_account_admin_revoke_session(uuid,uuid,text)
  from public,anon,authenticated,service_role;
grant execute on function public.st_v7_account_admin_sessions(uuid),public.st_v7_account_admin_revoke_session(uuid,uuid,text)
  to authenticated;

commit;
