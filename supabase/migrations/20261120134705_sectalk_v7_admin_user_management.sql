begin;

-- Provision this independently of workspace membership and moderation.
create table sectalk_private.st_v7_account_operators (
  user_id uuid primary key references auth.users on delete cascade,
  capability text not null check(capability in ('operator','reviewer'))
);
comment on table sectalk_private.st_v7_account_operators is
  'Provision through privileged database administration. Operators can end sessions and request a reset; separate reviewers can approve a matured request.';
create table sectalk_private.st_v7_account_admin_audit (
  id bigint generated always as identity primary key,
  actor uuid not null,
  target uuid not null,
  action text not null check(action in ('force_logout','reset_requested','reset_completed')),
  request_id uuid,
  reason text not null check(char_length(reason) between 10 and 240),
  occurred_at timestamptz not null default clock_timestamp()
);
create index st_v7_account_admin_history on sectalk_private.st_v7_account_admin_audit(target,id desc);
alter table sectalk_private.st_v7_account_operators enable row level security;
alter table sectalk_private.st_v7_account_admin_audit enable row level security;
revoke all on sectalk_private.st_v7_account_operators,sectalk_private.st_v7_account_admin_audit
  from public,anon,authenticated,service_role;

-- The native provider ends refresh sessions. Enforce the same revocation on
-- already issued bearer tokens through the existing data and realtime gates.
create or replace function public.st_v7_account_data_unavailable()
returns boolean language sql stable security definer set search_path='' as $$
  select exists(select 1 from sectalk_private.st_v7_account_lockdowns l where l.user_id=auth.uid()
    and (l.released_at is null or not public.st_v7_current_session_valid()))
    or (exists(select 1 from sectalk_private.st_v7_account_admin_audit a where a.target=auth.uid()
        and a.action in ('force_logout','reset_completed'))
      and not public.st_v7_current_session_valid());
$$;

create policy st_v7_account_data_storage_gate on storage.objects as restrictive for all to authenticated
  using(not (select public.st_v7_account_data_unavailable()))
  with check(not (select public.st_v7_account_data_unavailable()));

create function sectalk_private.st_v7_admin_fresh()
returns boolean language sql stable security definer set search_path='' as $$
  select public.st_v7_current_session_valid() and sectalk_private.st_v7_security_session('totp');
$$;

create function public.st_v7_account_operator_access()
returns text language sql stable security definer set search_path='' as $$
  select coalesce((select case when sectalk_private.st_v7_admin_fresh() then a.capability else 'mfa' end
    from sectalk_private.st_v7_account_operators a where a.user_id=auth.uid()
      and sectalk_private.st_v2_active(a.user_id) and public.st_v7_current_session_valid()),'none');
$$;

create function sectalk_private.st_v7_admin_native_target(p_user uuid)
returns boolean language sql stable security definer set search_path='' as $$
  select exists(select 1 from auth.users u join public.st_profiles p on p.id=u.id
    where u.id=p_user and u.email_confirmed_at is not null and nullif(u.encrypted_password,'') is not null
      and not u.is_sso_user and not u.is_anonymous and u.deleted_at is null
      and exists(select 1 from auth.identities i where i.user_id=u.id and i.provider='email')
      and not exists(select 1 from auth.identities i where i.user_id=u.id and i.provider<>'email')
      and not exists(select 1 from sectalk_private.staff s where s.user_id=u.id)
      and not exists(select 1 from sectalk_private.st_v7_account_operators a where a.user_id=u.id));
$$;

create function public.st_v7_account_admin_directory(
  p_search text default '',p_status text default 'all',p_after text default ''
)
returns table(id uuid,handle text,name text,status text)
language plpgsql security definer set search_path='' as $$
declare q text:=lower(btrim(coalesce(p_search,'')));
begin
  if public.st_v7_account_operator_access() not in ('operator','reviewer') then
    raise exception 'Account operator verification required' using errcode='42501';
  end if;
  if char_length(q)>50 or p_status is null or p_status not in ('all','active','restricted')
    or p_after is null or p_after !~ '^[a-z0-9_]{0,24}$' then
    raise exception 'Invalid directory filter' using errcode='22023';
  end if;
  perform sectalk_private.limit_action('v7_account_admin_directory',60);
  return query select p.id,p.handle,p.name,case when s.user_id is null then 'active' else 'restricted' end
    from public.st_profiles p join auth.users u on u.id=p.id and u.deleted_at is null
    left join sectalk_private.suspensions s on s.user_id=p.id and s.until_at>statement_timestamp()
    where p.handle>p_after and (q='' or strpos(p.handle,q)=1 or strpos(lower(p.name),q)=1)
      and (p_status='all' or (p_status='restricted')=(s.user_id is not null))
    order by p.handle limit 41;
end $$;

create function public.st_v7_account_admin_profile(p_user uuid)
returns jsonb language plpgsql security definer set search_path='' as $$
begin
  if public.st_v7_account_operator_access() not in ('operator','reviewer') then
    raise exception 'Account operator verification required' using errcode='42501';
  end if;
  perform sectalk_private.limit_action('v7_account_admin_profile',60);
  return (select jsonb_build_object('id',p.id,'handle',p.handle,'name',p.name,'created_at',u.created_at,
    'eligible',p.id<>auth.uid() and sectalk_private.st_v7_admin_native_target(p.id),
    'has_authenticator',exists(select 1 from auth.mfa_factors f where f.user_id=p.id and f.status='verified'),
    'restricted',exists(select 1 from sectalk_private.suspensions s where s.user_id=p.id and s.until_at>statement_timestamp()),
    'reset',(select jsonb_build_object('ready_at',c.ready_at,'expires_at',c.expires_at)
      from sectalk_private.st_v7_account_security_changes c where c.user_id=p.id and c.kind='authenticator'
        and c.state='pending' and c.expires_at>statement_timestamp() and exists(
          select 1 from sectalk_private.st_v7_account_admin_audit a where a.target=p.id and a.action='reset_requested'
            and c.binding=extensions.digest(a.request_id::text,'sha256'))),
    'history',(select coalesce(jsonb_agg(jsonb_build_object('action',h.action,'occurred_at',h.occurred_at,
      'actor',h.actor,'reason',h.reason) order by h.id desc),'[]'::jsonb) from (
        select a.* from sectalk_private.st_v7_account_admin_audit a where a.target=p.id order by a.id desc limit 20
      ) h))
    from public.st_profiles p join auth.users u on u.id=p.id and u.deleted_at is null where p.id=p_user);
end $$;

-- Keep target security history and recipient-only device invalidations in the existing lifecycle.
alter table sectalk_private.st_v7_account_security_events drop constraint st_v7_account_security_events_kind_check;
alter table sectalk_private.st_v7_account_security_events add constraint st_v7_account_security_events_kind_check
  check(kind in ('email','authenticator','recovery','password','sessions'));

create function public.st_v7_account_admin_action(p_user uuid,p_action text,p_reason text)
returns void language plpgsql security definer set search_path='' as $$
declare
  actor_id uuid:=auth.uid();
  operator_capability text:=public.st_v7_account_operator_access();
  reason text:=btrim(p_reason);
  stamp timestamptz:=clock_timestamp();
  request_key uuid;
  pending sectalk_private.st_v7_account_security_changes;
begin
  if p_action is null or p_action not in ('force_logout','reset_requested','reset_completed')
    or p_user is null or p_user=actor_id or operator_capability is distinct from
      (case when p_action='reset_completed' then 'reviewer' else 'operator' end) then
    raise exception 'This account operation is unavailable' using errcode='42501';
  end if;
  if reason is null or char_length(reason) not between 10 and 240 then
    raise exception 'Enter a case reference and reason between 10 and 240 characters' using errcode='22023';
  end if;
  perform sectalk_private.limit_action('v7_account_admin_mutation',8);
  perform 1 from sectalk_private.st_v7_account_operators o
    where o.user_id=actor_id and o.capability=operator_capability for share;
  if not found then
    raise exception 'This account operation is unavailable' using errcode='42501';
  end if;
  perform 1 from auth.users u where u.id=p_user for update;
  perform 1 from public.st_profiles p where p.id=p_user for update;
  if not sectalk_private.st_v7_admin_native_target(p_user) then
    raise exception 'This account operation is unavailable' using errcode='42501';
  end if;
  if p_action='force_logout' then
    delete from auth.sessions where user_id=p_user;
    perform sectalk_private.st_v7_record_security_event(p_user,'sessions','completed');
    perform realtime.send('{}','session_lifecycle','st:account:'||p_user,true);
  else
    select c.* into pending from sectalk_private.st_v7_account_security_changes c where c.user_id=p_user for update;
    if p_action='reset_requested' then
      if (pending.state in ('pending','approved') and pending.expires_at>stamp)
        or not exists(select 1 from auth.mfa_factors f where f.user_id=p_user and f.status='verified') then
        raise exception 'An authenticator reset cannot be requested for this account' using errcode='22023';
      end if;
      request_key:=gen_random_uuid();
      insert into sectalk_private.st_v7_account_security_changes(user_id,kind,state,binding,requested_at,ready_at,expires_at)
        values(p_user,'authenticator','pending',extensions.digest(request_key::text,'sha256'),stamp,
          stamp+interval '24 hours',stamp+interval '7 days')
        on conflict(user_id) do update set kind=excluded.kind,state=excluded.state,binding=excluded.binding,
          requested_at=excluded.requested_at,ready_at=excluded.ready_at,expires_at=excluded.expires_at,approved_until=null;
      perform sectalk_private.st_v7_record_security_event(p_user,'authenticator','requested');
    else
      if pending.kind is distinct from 'authenticator' or pending.state is distinct from 'pending'
        or pending.ready_at>stamp or pending.expires_at<=stamp then
        raise exception 'The reset is unavailable or still cooling off' using errcode='22023';
      end if;
      select a.request_id into request_key from sectalk_private.st_v7_account_admin_audit a
        join sectalk_private.st_v7_account_operators o on o.user_id=a.actor and o.capability='operator'
        where a.target=p_user and a.action='reset_requested' and a.actor<>actor_id
          and extensions.digest(a.request_id::text,'sha256')=pending.binding
        order by a.id desc limit 1 for share of o;
      if request_key is null then
        raise exception 'Independent account operator approval required' using errcode='42501';
      end if;
      perform sectalk_private.st_v7_finish_authenticator_reset(p_user,'authenticator');
      perform realtime.send('{}','session_lifecycle','st:account:'||p_user,true);
    end if;
  end if;
  insert into sectalk_private.st_v7_account_admin_audit(actor,target,action,request_id,reason)
    values(actor_id,p_user,p_action,request_key,reason);
end $$;

create or replace function public.st_v7_account_security_status()
returns jsonb language sql stable security definer set search_path='' as $$
  select jsonb_build_object('pending',(select jsonb_build_object(
    'kind',r.kind,'requested_at',r.requested_at,'ready_at',r.ready_at,'expires_at',r.expires_at,
    'provider_pending',r.kind='email' and coalesce(u.email_change,'')<>'',
    'support_requested',r.kind='authenticator' and r.binding is not null)
    from sectalk_private.st_v7_account_security_changes r where r.user_id=u.id
      and r.state in ('pending','approved') and r.expires_at>now()))
  from auth.users u where u.id=auth.uid() and sectalk_private.st_v7_security_session()
$$;

create function public.st_v7_workspace_people_verified(p_workspace uuid)
returns boolean language sql stable security definer set search_path='' as $$
  select coalesce(sectalk_private.st_v2_role(p_workspace,auth.uid()) in ('owner','admin'),false)
    and sectalk_private.st_v2_active(auth.uid()) and sectalk_private.st_v7_admin_fresh();
$$;

create function public.st_v7_workspace_people(
  p_workspace uuid,p_search text default '',p_role text default 'all',p_status text default 'all',p_after text default ''
)
returns table(id uuid,handle text,name text,role text,joined_at timestamptz,suspended_at timestamptz)
language plpgsql stable security definer set search_path='' as $$
declare q text:=lower(btrim(coalesce(p_search,'')));
begin
  if not public.st_v7_workspace_people_verified(p_workspace) then
    raise exception 'Workspace administrator verification required' using errcode='42501';
  end if;
  if char_length(q)>50 or p_role is null or p_role not in ('all','owner','admin','member')
    or p_status is null or p_status not in ('all','active','suspended') or p_after is null
    or p_after !~ '^[a-z0-9_]{0,24}$' then
    raise exception 'Invalid workspace people filter' using errcode='22023';
  end if;
  return query select p.id,p.handle,p.name,m.role,m.joined_at,m.suspended_at
    from public.st_v2_members m join public.st_profiles p on p.id=m.user_id
    where m.workspace_id=p_workspace and p.handle>p_after
      and (q='' or strpos(p.handle,q)=1 or strpos(lower(p.name),q)=1)
      and (p_role='all' or m.role=p_role)
      and (p_status='all' or (p_status='suspended')=(m.suspended_at is not null))
    order by p.handle limit 41;
end $$;

create or replace function public.st_v2_set_member(p_workspace uuid,p_member uuid,p_role text)
returns void language plpgsql security definer set search_path='' as $$
declare
  actor uuid:=auth.uid();
  actor_role text;
  target_role text;
begin
  perform sectalk_private.limit_action('v2_role',12);
  perform id from public.st_v2_workspaces where id=p_workspace for update;
  actor_role:=sectalk_private.st_v2_role(p_workspace,actor);
  if not coalesce(actor_role in ('owner','admin'),false) or not sectalk_private.st_v2_active(actor)
    or p_member is null or p_member=actor or p_role is null or p_role not in ('admin','member','remove','suspend','restore')
  then raise exception 'Workspace action unavailable'; end if;
  select m.role into target_role from public.st_v2_members m
    where m.workspace_id=p_workspace and m.user_id=p_member;
  if target_role is null or target_role='owner'
    or (actor_role='admin' and (target_role<>'member' or p_role not in ('suspend','restore')))
  then raise exception 'Workspace member unavailable'; end if;
  if not sectalk_private.st_v7_admin_fresh() then
    raise exception 'Workspace administrator verification required' using errcode='42501';
  end if;
  case p_role
    when 'remove' then
      delete from public.st_v2_members where workspace_id=p_workspace and user_id=p_member;
    when 'suspend' then
      update public.st_v2_members set suspended_at=clock_timestamp()
        where workspace_id=p_workspace and user_id=p_member and suspended_at is null;
    when 'restore' then
      update public.st_v2_members set suspended_at=null
        where workspace_id=p_workspace and user_id=p_member and suspended_at is not null;
    else
      update public.st_v2_members set role=p_role where workspace_id=p_workspace and user_id=p_member;
  end case;
  if found then
    insert into public.st_v2_workspace_audit(workspace_id,actor,event,target)
      values(p_workspace,actor,'member.'||p_role,p_member);
  end if;
end $$;

revoke all on function sectalk_private.st_v7_admin_fresh(),sectalk_private.st_v7_admin_native_target(uuid),
  public.st_v7_account_operator_access(),public.st_v7_account_admin_directory(text,text,text),public.st_v7_workspace_people_verified(uuid),
  public.st_v7_account_admin_profile(uuid),public.st_v7_account_admin_action(uuid,text,text),
  public.st_v7_workspace_people(uuid,text,text,text,text),public.st_v2_set_member(uuid,uuid,text)
  from public,anon,authenticated,service_role;
grant execute on function public.st_v7_account_operator_access(),public.st_v7_account_admin_directory(text,text,text),
  public.st_v7_account_admin_profile(uuid),public.st_v7_account_admin_action(uuid,text,text),
  public.st_v7_workspace_people_verified(uuid),public.st_v7_workspace_people(uuid,text,text,text,text),
  public.st_v2_set_member(uuid,uuid,text) to authenticated;

commit;
