begin;

-- Outgoing administration requires both applicable policies. Leave the
-- separate approved offboarding path on its existing invitation-only check.
create function sectalk_private.st_v8_app_invitation_allows(p_workspace uuid)
returns boolean language sql stable security definer set search_path='' as $$
  select sectalk_private.st_v8_entry_sso_allows(p_workspace)
    and sectalk_private.st_v8_invitation_admin_sso_allows(p_workspace);
$$;
revoke all on function sectalk_private.st_v8_app_invitation_allows(uuid) from public,anon,authenticated,service_role;
grant execute on function sectalk_private.st_v8_app_invitation_allows(uuid) to authenticated;

alter policy st_v8_invitation_admin_sso on public.st_v2_invites
  using(invitee=(select auth.uid()) or sectalk_private.st_v8_app_invitation_allows(workspace_id));

create or replace function public.st_v8_workspace_invitation_admin_requires_sso(p_workspace uuid)
returns boolean language sql stable security definer set search_path='' as $$
  select sectalk_private.st_v2_active(auth.uid())
    and coalesce(sectalk_private.st_v2_role(p_workspace,auth.uid()) in ('owner','admin'),false)
    and not sectalk_private.st_v8_app_invitation_allows(p_workspace);
$$;

create or replace function sectalk_private.st_v6_manage_link_invites(p_workspace uuid)
returns boolean language sql stable set search_path='' as $$
  select coalesce(sectalk_private.st_v2_role(p_workspace,auth.uid()) in ('owner','admin'),false)
    and sectalk_private.st_v2_active(auth.uid())
    and sectalk_private.st_v8_app_invitation_allows(p_workspace)
$$;

create or replace function sectalk_private.st_v6_invite_workspace_handles(p_workspace uuid,p_handles text[])
returns table(handle text, sent boolean)
language plpgsql security definer set search_path='' as $$
declare
  actor uuid:=auth.uid();
  title text;
  peer uuid;
  normalized_handle text;
begin
  select name into title from public.st_v2_workspaces where id=p_workspace for update;
  if title is null or not coalesce(sectalk_private.st_v2_role(p_workspace,actor) in ('owner','admin'),false)
    or not sectalk_private.st_v2_active(actor)
  then raise exception 'Workspace action unavailable'; end if;

  if not sectalk_private.st_v8_app_invitation_allows(p_workspace) then
    raise exception 'Sign in through your workspace provider to send invitations' using errcode='42501';
  end if;
  if coalesce(cardinality(p_handles),0) not between 1 and 100 or array_ndims(p_handles)<>1
    or exists(select 1 from unnest(p_handles) h where h is null or char_length(h)>64)
  then raise exception 'Provide between 1 and 100 SecTalk handles'; end if;

  for normalized_handle in
    select lower(btrim(h)) from unnest(p_handles) with ordinality as input(h,position)
    group by lower(btrim(h)) order by min(position)
  loop
    handle:=normalized_handle;
    sent:=false;
    select p.id into peer from public.st_profiles p where p.handle=normalized_handle;
    if peer is not null and peer<>actor and sectalk_private.open_pair(actor,peer)
      and not exists(select 1 from public.st_v2_members where workspace_id=p_workspace and user_id=peer)
    then
      insert into public.st_v2_invites(workspace_id,invitee,created_by,workspace_name)
        values(p_workspace,peer,actor,title) on conflict(workspace_id,invitee) do nothing;
      sent:=found;
      if sent then
        insert into public.st_v2_workspace_audit(workspace_id,actor,event,target)
          values(p_workspace,actor,'member.invited',peer);
      end if;
    end if;
    return next;
  end loop;
end $$;

create or replace function public.st_v7_workspace_email_template(p_workspace uuid,p_action text default 'read',
  p_subject text default null,p_body text default null,p_version integer default null)
returns jsonb language plpgsql security definer set search_path='' as $$
declare ws public.st_v2_workspaces; actor uuid:=auth.uid(); active_version integer; selected_version integer;
begin
  if not public.st_v7_current_session_valid() or public.st_v7_account_under_lockdown()
    or public.st_v7_login_risk_status() is distinct from 'clear' or not sectalk_private.st_v2_active(actor) then
    raise exception using errcode='42501',message='Workspace email settings unavailable';
  end if;
  if p_action='delivery' then
    if coalesce(sectalk_private.st_v2_role(p_workspace,actor),'') not in ('owner','admin') then
      raise exception using errcode='42501',message='Workspace email settings unavailable';
    end if;
    select * into ws from public.st_v2_workspaces where id=p_workspace;
  elsif p_action='read' then
    select * into ws from public.st_v2_workspaces where id=p_workspace and owner=actor;
  else
    select * into ws from public.st_v2_workspaces where id=p_workspace and owner=actor for no key update;
  end if;
  if not found then raise exception using errcode='42501',message='Workspace email settings unavailable'; end if;

  if not sectalk_private.st_v8_entry_sso_allows(p_workspace)
    or (p_action='delivery' and not sectalk_private.st_v8_invitation_admin_sso_allows(p_workspace)) then
    raise exception using errcode='42501',message='Sign in through your workspace provider to manage invitations';
  end if;

  if p_action is distinct from 'delivery' and not sectalk_private.st_v8_organization_sso_allows(p_workspace) then
    raise exception 'Sign in through your workspace provider to manage organization settings' using errcode='42501';
  end if;

  if p_action not in ('read','delivery') then
    if public.st_v7_sensitive_action_status('room_role') is distinct from 'verified' then
      raise exception using errcode='42501',message='Verify your current sign-in to change email templates';
    end if;
    perform sectalk_private.limit_action('v7_workspace_email_template',10);
    if p_action='publish' then
      if p_subject is null or char_length(btrim(p_subject)) not between 1 and 100 or p_subject~'[[:cntrl:]]'
        or p_body is null or char_length(btrim(p_body)) not between 1 and 1500 or translate(p_body,E'\n\t','')~'[[:cntrl:]]'
        or (replace(p_subject,'{{organization}}','')||replace(p_body,'{{organization}}',''))~'[{}<>]'
        or p_subject~*'(https?://|www\.|mailto:)' or p_body~*'(https?://|www\.|mailto:)' then
        raise exception using errcode='22023',message='Use plain text and the organization variable. The invitation link is included automatically.';
      end if;
      select coalesce(max(version),0)+1 into selected_version
        from sectalk_private.st_v7_workspace_email_versions where workspace=p_workspace;
      if selected_version>100 then raise exception using errcode='22023',message='This workspace has reached 100 published versions'; end if;
      insert into sectalk_private.st_v7_workspace_email_versions(workspace,version,subject,body)
        values(p_workspace,selected_version,btrim(p_subject),btrim(p_body));
    elsif p_action='activate' then
      selected_version:=p_version;
      if selected_version is null or (selected_version<>0 and not exists(select 1
        from sectalk_private.st_v7_workspace_email_versions where workspace=p_workspace and version=selected_version)) then
        raise exception using errcode='22023',message='Choose an available template version';
      end if;
    else
      raise exception using errcode='22023',message='Invalid email template action';
    end if;
    if selected_version=0 then
      delete from sectalk_private.st_v7_workspace_email_active where workspace=p_workspace;
    else
      insert into sectalk_private.st_v7_workspace_email_active values(p_workspace,selected_version)
        on conflict(workspace) do update set version=excluded.version;
    end if;
    insert into public.st_v2_workspace_audit(workspace_id,actor,event) values(p_workspace,actor,
      case when p_action='publish' then 'workspace.email_template_published' else 'workspace.email_template_restored' end);
  end if;

  select version into active_version from sectalk_private.st_v7_workspace_email_active where workspace=p_workspace;
  if p_action='delivery' then
    return jsonb_build_object('organization',ws.name,'template',(select jsonb_build_object('subject',subject,'body',body)
      from sectalk_private.st_v7_workspace_email_versions where workspace=p_workspace and version=active_version));
  end if;
  return jsonb_build_object('organization',ws.name,'active',coalesce(active_version,0),'versions',
    coalesce((select jsonb_agg(jsonb_build_object('version',version,'subject',subject,'body',body,'createdAt',created_at) order by version desc)
      from sectalk_private.st_v7_workspace_email_versions where workspace=p_workspace),'[]'));
end
$$;

commit;
