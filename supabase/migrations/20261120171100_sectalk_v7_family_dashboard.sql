begin;
alter table sectalk_private.st_v7_managed_accounts add column file_consent boolean not null default false,
  add column restrict_file_links boolean not null default false,
  add constraint st_v7_family_file_consent check(not restrict_file_links or file_consent);
create index st_v7_family_attachment_restrictions on sectalk_private.st_v7_managed_accounts(participant)
  where state='active' and file_consent and restrict_file_links;
create or replace function public.st_v7_managed_account(p_workspace uuid,p_action text default 'read',
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
        update sectalk_private.st_v7_managed_accounts set state='active',changed_at=clock_timestamp(),
          file_consent=workspace_type='family' and coalesce(p_restrict,false),
          restrict_file_links=workspace_type='family' and coalesce(p_restrict,false) where id=entry.id;
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


create function public.st_v7_family_file_policy(p_workspace uuid,p_action text default 'read',
  p_link uuid default null,p_restrict boolean default null)
returns jsonb language plpgsql security definer set search_path='' as $$
declare actor uuid:=auth.uid(); item sectalk_private.st_v7_managed_accounts;
begin
  -- Reuse workspace type, active membership, verified email, valid session and security checks.
  if public.st_v7_managed_account(p_workspace)->>'kind' is distinct from 'family' then
    raise exception using errcode='42501',message='Family settings are unavailable';
  end if;
  if p_action is distinct from 'read' then
    if public.st_v7_sensitive_action_status('room_role') is distinct from 'verified' then
      raise exception using errcode='42501',message='Verify your current sign-in to change sharing protection';
    end if;
    perform sectalk_private.limit_action('v7_family_file_policy',10);
    select * into item from sectalk_private.st_v7_managed_accounts a where a.workspace=p_workspace
      and a.id=p_link and a.state='active' and actor in (a.supervisor,a.participant) for update;
    if not found or sectalk_private.st_v2_role(p_workspace,item.participant) is distinct from 'member'
      or coalesce(sectalk_private.st_v2_role(p_workspace,item.supervisor),'') not in ('owner','admin')
      or not sectalk_private.st_v2_active(item.participant) or not sectalk_private.st_v2_active(item.supervisor) then
      raise exception using errcode='42501',message='Family relationship is unavailable';
    end if;
    if p_action='agree' and actor=item.participant and not item.file_consent then
      update sectalk_private.st_v7_managed_accounts set file_consent=true,restrict_file_links=true where id=item.id;
    elsif p_action='withdraw' and actor=item.participant and item.file_consent then
      update sectalk_private.st_v7_managed_accounts set file_consent=false,restrict_file_links=false where id=item.id;
    elsif p_action='set' and actor=item.supervisor and item.file_consent and p_restrict is not null then
      update sectalk_private.st_v7_managed_accounts set restrict_file_links=p_restrict where id=item.id;
    else
      raise exception using errcode='42501',message='Sharing protection action is unavailable';
    end if;
    insert into public.st_v2_workspace_audit(workspace_id,actor,event,target)
      values(p_workspace,actor,'workspace.family_file_protection_'||p_action,item.participant);
  end if;

  return coalesce((select jsonb_agg(jsonb_build_object('id',a.id,'supervisor',a.supervisor,'participant',a.participant,
    'consent',a.file_consent,'restricted',a.restrict_file_links,
    'recentTrustedCheck',exists(select 1 from sectalk_private.st_v7_device_sessions b
      join sectalk_private.st_v7_devices d on (d.owner,d.id)=(b.owner,b.device_id)
      join auth.sessions s on s.id=b.session_id and s.user_id=b.owner
      where b.owner=a.participant and d.state in ('trusted','managed') and s.created_at>now()-interval '7 days'
        and sectalk_private.st_v7_session_deadline(s.created_at,s.refreshed_at,s.not_after)>now()))
    order by a.changed_at desc)
    from (select * from sectalk_private.st_v7_managed_accounts
      where workspace=p_workspace and state='active' and actor in (supervisor,participant)
        and sectalk_private.st_v2_role(p_workspace,participant)='member'
        and sectalk_private.st_v2_role(p_workspace,supervisor) in ('owner','admin')
        and sectalk_private.st_v2_active(participant) and sectalk_private.st_v2_active(supervisor)
      order by changed_at desc limit 30) a),'[]');
end
$$;

create or replace function sectalk_private.st_v6_shareable_file(p_file uuid,p_owner uuid)
returns boolean language sql stable set search_path='' as $$
  select exists(select 1 from public.st_v5_files f join public.st_messages m on m.id=f.message_id
    where f.id=p_file and f.deleted_at is null and (p_owner is null or f.uploader=p_owner) and m.revoked_at is null
      and sectalk_private.st_v2_chat_write(f.chat_id,f.uploader)
      and not exists(select 1 from sectalk_private.st_v7_managed_accounts a
        where a.participant=f.uploader and a.state='active' and a.file_consent and a.restrict_file_links
          and sectalk_private.st_v2_role(a.workspace,a.participant)='member'
          and sectalk_private.st_v2_role(a.workspace,a.supervisor) in ('owner','admin')
          and sectalk_private.st_v2_active(a.supervisor)));
$$;

revoke all on function public.st_v7_family_file_policy(uuid,text,uuid,boolean) from public,anon,authenticated,service_role;
grant execute on function public.st_v7_family_file_policy(uuid,text,uuid,boolean) to authenticated;
commit;
