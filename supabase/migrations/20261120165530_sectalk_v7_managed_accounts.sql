begin;
create table sectalk_private.st_v7_managed_accounts (
  id uuid primary key default gen_random_uuid(),
  workspace uuid not null references public.st_v2_workspaces(id) on delete cascade,
  supervisor uuid not null references public.st_profiles(id) on delete cascade,
  participant uuid not null references public.st_profiles(id) on delete cascade,
  state text not null default 'pending' check(state in ('pending','active','ended')),
  restrict_contacts boolean not null default true,
  requested_at timestamptz not null default clock_timestamp(),
  changed_at timestamptz not null default clock_timestamp(),
  check(supervisor<>participant)
);
create unique index st_v7_managed_account_live on sectalk_private.st_v7_managed_accounts(workspace,participant) where state in ('pending','active');
create index st_v7_managed_accounts_participant on sectalk_private.st_v7_managed_accounts(participant,workspace)
  where state='active' and restrict_contacts;
create index st_v7_managed_accounts_supervisor on sectalk_private.st_v7_managed_accounts(workspace,supervisor);
alter table sectalk_private.st_v7_managed_accounts enable row level security;
revoke all on sectalk_private.st_v7_managed_accounts from public,anon,authenticated,service_role;

create function public.st_v7_managed_account(p_workspace uuid,p_action text default 'read',
  p_target uuid default null,p_link uuid default null,p_restrict boolean default null)
returns jsonb language plpgsql security definer set search_path='' as $$
declare actor uuid:=auth.uid(); workspace_type text; role text; entry sectalk_private.st_v7_managed_accounts;
  target_actor uuid;
begin
  if not public.st_v7_current_session_valid() or public.st_v7_account_under_lockdown()
    or public.st_v7_login_risk_status() is distinct from 'clear' or not sectalk_private.st_v2_active(actor)
    or not exists(select 1 from auth.users u where u.id=actor and u.email_confirmed_at is not null) then
    raise exception using errcode='42501',message='Managed account access is unavailable';
  end if;
  select p.workspace_type into workspace_type from public.st_v6_workspace_policy p where p.workspace_id=p_workspace
    and p.workspace_type in ('family','school');
  role:=sectalk_private.st_v2_role(p_workspace,actor);
  if workspace_type is null or role is null then raise exception using errcode='42501',message='Managed account access is unavailable'; end if;

  if p_action is distinct from 'read' then
    if public.st_v7_sensitive_action_status('room_role') is distinct from 'verified' then
      raise exception using errcode='42501',message='Verify your current sign-in to change managed account settings';
    end if;
    perform sectalk_private.limit_action('v7_managed_account',12);
    if p_action='offer' then
      if role not in ('owner','admin') or p_target is null or p_target=actor then
        raise exception using errcode='42501',message='Choose an eligible workspace member';
      end if;
      target_actor:=p_target;
    else
      select a.participant into target_actor from sectalk_private.st_v7_managed_accounts a where a.workspace=p_workspace and a.id=p_link
        and actor in (a.supervisor,a.participant);
      if not found then raise exception using errcode='42501',message='Managed account relationship is unavailable'; end if;
    end if;
    perform pg_advisory_xact_lock(hashtextextended('managed-account:'||target_actor::text,0));
    if p_action='offer' then
      -- Lock in UUID order so simultaneous proposals and roster removal serialize.
      perform 1 from public.st_v2_members m where m.workspace_id=p_workspace and m.user_id in (actor,p_target)
        order by m.user_id for no key update;
      if coalesce(sectalk_private.st_v2_role(p_workspace,actor),'') not in ('owner','admin')
        or sectalk_private.st_v2_role(p_workspace,p_target) is distinct from 'member'
        or not sectalk_private.st_v2_active(p_target)
        or not exists(select 1 from auth.users u where u.id=p_target and u.email_confirmed_at is not null) then
        raise exception using errcode='42501',message='Choose an eligible workspace member';
      end if;
      update sectalk_private.st_v7_managed_accounts a set state='ended',changed_at=clock_timestamp()
        where a.workspace=p_workspace and a.participant=p_target and a.state='pending' and a.requested_at<=now()-interval '7 days';
      if exists(select 1 from sectalk_private.st_v7_managed_accounts a where a.workspace=p_workspace
        and a.participant=p_target and a.state in ('pending','active')) then
        raise exception using errcode='PT409',message='This member already has a current proposal or relationship';
      end if;
      insert into sectalk_private.st_v7_managed_accounts(workspace,supervisor,participant) values(p_workspace,actor,p_target)
        returning * into entry;
    else
      select * into entry from sectalk_private.st_v7_managed_accounts a where a.workspace=p_workspace and a.id=p_link for update;
      if not found or actor not in (entry.supervisor,entry.participant) or entry.state='ended' then
        raise exception using errcode='42501',message='Managed account relationship is unavailable';
      end if;
      if p_action='accept' and actor=entry.participant and entry.state='pending' and entry.requested_at>now()-interval '7 days'
        and sectalk_private.st_v2_role(p_workspace,entry.participant)='member'
        and sectalk_private.st_v2_role(p_workspace,entry.supervisor) in ('owner','admin')
        and sectalk_private.st_v2_active(entry.supervisor) then
        update sectalk_private.st_v7_managed_accounts set state='active',changed_at=clock_timestamp() where id=entry.id;
      elsif p_action='restrict' and actor=entry.supervisor and entry.state='active' and p_restrict is not null
        and sectalk_private.st_v2_role(p_workspace,actor) in ('owner','admin')
        and sectalk_private.st_v2_role(p_workspace,entry.participant)='member'
        and sectalk_private.st_v2_active(entry.participant) then
        update sectalk_private.st_v7_managed_accounts set restrict_contacts=p_restrict,changed_at=clock_timestamp() where id=entry.id;
      elsif p_action='end' then
        update sectalk_private.st_v7_managed_accounts set state='ended',changed_at=clock_timestamp() where id=entry.id;
      else
        raise exception using errcode='42501',message='Managed account action is unavailable';
      end if;
    end if;
    insert into public.st_v2_workspace_audit(workspace_id,actor,event,target)
      values(p_workspace,actor,'workspace.managed_account_'||p_action,entry.participant);
  end if;

  return jsonb_build_object('kind',workspace_type,'relationships',coalesce((
    select jsonb_agg(jsonb_build_object('id',a.id,'supervisor',a.supervisor,'participant',a.participant,
      'state',case when a.state='pending' and a.requested_at<=now()-interval '7 days' then 'expired' else a.state end,
      'restrictContacts',a.restrict_contacts,'changedAt',a.changed_at,
      'verifiedDevices',case when a.state='active' and sectalk_private.st_v2_role(p_workspace,a.supervisor) in ('owner','admin')
        and sectalk_private.st_v2_role(p_workspace,a.participant)='member' and sectalk_private.st_v2_active(a.supervisor)
        and sectalk_private.st_v2_active(a.participant)
        then (select count(*) from sectalk_private.st_v7_devices d where d.owner=a.participant and d.state in ('trusted','managed')) end)
      order by a.changed_at desc)
    from (select * from sectalk_private.st_v7_managed_accounts x
      where x.workspace=p_workspace and actor in (x.supervisor,x.participant) order by x.changed_at desc limit 30) a
  ),'[]'));
end
$$;

create function sectalk_private.st_v7_end_invalid_managed_relationships()
returns trigger language plpgsql security definer set search_path='' as $$
begin
  update sectalk_private.st_v7_managed_accounts a set state='ended',changed_at=clock_timestamp()
    where a.workspace=old.workspace_id and a.state in ('pending','active')
      and ((a.supervisor=old.user_id and (tg_op='DELETE' or new.role not in ('owner','admin') or new.suspended_at is not null))
        or (a.participant=old.user_id and (tg_op='DELETE' or new.role<>'member' or new.suspended_at is not null)));
  return null;
end
$$;
create trigger st_v7_managed_account_lifecycle after update of role,suspended_at or delete on public.st_v2_members
  for each row execute function sectalk_private.st_v7_end_invalid_managed_relationships();

create function sectalk_private.st_v7_enforce_managed_contact()
returns trigger language plpgsql security definer set search_path='' as $$
begin
  if new.status not in ('pending','accepted') then return new; end if;
  if tg_op='UPDATE' and old.status='accepted' then return new; end if;
  if tg_op='UPDATE' then
    -- The contact row is already locked here. A concurrent insert can hold its
    -- consent lock before checking the same row, so retry without waiting.
    if not pg_try_advisory_xact_lock(hashtextextended('managed-account:'||new.member_a::text,0))
       or not pg_try_advisory_xact_lock(hashtextextended('managed-account:'||new.member_b::text,0)) then
      raise exception using errcode='PT409',message='Contact settings changed. Try again.';
    end if;
  else
    perform pg_advisory_xact_lock(hashtextextended('managed-account:'||new.member_a::text,0));
    perform pg_advisory_xact_lock(hashtextextended('managed-account:'||new.member_b::text,0));
  end if;
  if tg_op='INSERT' and exists(select 1 from public.st_chats c
    where c.member_a=new.member_a and c.member_b=new.member_b and c.status='accepted') then return new; end if;
  if exists(select 1 from sectalk_private.st_v7_managed_accounts a
    where a.participant in (new.member_a,new.member_b) and a.state='active' and a.restrict_contacts
      and sectalk_private.st_v2_role(a.workspace,a.supervisor) in ('owner','admin')
      and sectalk_private.st_v2_role(a.workspace,a.participant)='member' and sectalk_private.st_v2_active(a.supervisor)
      and sectalk_private.st_v2_role(a.workspace,case when a.participant=new.member_a then new.member_b else new.member_a end) is null
  ) then raise exception using errcode='42501',message='This contact request is unavailable'; end if;
  return new;
end
$$;
create trigger st_v7_managed_contact_floor before insert or update of status on public.st_chats
  for each row execute function sectalk_private.st_v7_enforce_managed_contact();

revoke all on function public.st_v7_managed_account(uuid,text,uuid,uuid,boolean),
  sectalk_private.st_v7_end_invalid_managed_relationships(),sectalk_private.st_v7_enforce_managed_contact()
  from public,anon,authenticated,service_role;
grant execute on function public.st_v7_managed_account(uuid,text,uuid,uuid,boolean) to authenticated;
commit;
