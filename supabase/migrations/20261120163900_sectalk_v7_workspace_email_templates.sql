begin;
create table sectalk_private.st_v7_workspace_email_versions (
  workspace uuid not null references public.st_v2_workspaces(id) on delete cascade,
  version integer not null check(version between 1 and 100),
  subject text not null check(char_length(subject) between 1 and 100),
  body text not null check(char_length(body) between 1 and 1500),
  created_at timestamptz not null default clock_timestamp(),
  primary key(workspace,version)
);
create table sectalk_private.st_v7_workspace_email_active (
  workspace uuid primary key references public.st_v2_workspaces(id) on delete cascade,
  version integer not null,
  foreign key(workspace,version) references sectalk_private.st_v7_workspace_email_versions(workspace,version)
);
alter table sectalk_private.st_v7_workspace_email_versions enable row level security;
alter table sectalk_private.st_v7_workspace_email_active enable row level security;
revoke all on sectalk_private.st_v7_workspace_email_versions,sectalk_private.st_v7_workspace_email_active
  from public,anon,authenticated,service_role;

create function public.st_v7_workspace_email_template(p_workspace uuid,p_action text default 'read',
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
revoke all on function public.st_v7_workspace_email_template(uuid,text,text,text,integer) from public,anon,authenticated,service_role;
grant execute on function public.st_v7_workspace_email_template(uuid,text,text,text,integer) to authenticated;
commit;
