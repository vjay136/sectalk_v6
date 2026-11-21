begin;

create table sectalk_private.st_v8_workspace_legal_hold_sso (
  workspace uuid primary key references public.st_v2_workspaces on delete cascade,
  protocol text not null check(protocol in ('saml','oidc')),
  provider text not null
);
alter table sectalk_private.st_v8_workspace_legal_hold_sso enable row level security;
revoke all on table sectalk_private.st_v8_workspace_legal_hold_sso from public,anon,authenticated,service_role;

create function sectalk_private.st_v8_legal_hold_sso_allows(p_workspace uuid)
returns boolean language sql stable security definer set search_path='' as $$
  select not exists(select 1 from sectalk_private.st_v8_workspace_legal_hold_sso p
    where p.workspace=p_workspace
      and sectalk_private.st_v8_workspace_session_receipt(p.workspace,p.protocol,p.provider) is not true);
$$;
revoke all on function sectalk_private.st_v8_legal_hold_sso_allows(uuid) from public,anon,authenticated,service_role;

create function public.st_v8_workspace_legal_hold_policy(p_workspace uuid,p_require boolean default null)
returns jsonb language plpgsql security definer set search_path='' as $$
declare access text:=sectalk_private.st_v7_file_egress_operator(p_workspace); setup sectalk_private.st_v7_workspace_sso;
begin
  if access is distinct from 'verified' then return jsonb_build_object('access',access); end if;
  if p_require is not null then
    perform sectalk_private.limit_action('v8_legal_hold_sso_policy',5);
    perform 1 from public.st_v2_workspaces w where w.id=p_workspace for update;
    if not found or sectalk_private.st_v7_file_egress_operator(p_workspace) is distinct from 'verified' then
      raise insufficient_privilege;
    end if;
    if p_require then
      select * into setup from sectalk_private.st_v7_workspace_sso c where c.workspace=p_workspace;
      if not found or sectalk_private.st_v7_workspace_sso_provider(p_workspace,setup.domain,setup.protocol)
        is distinct from setup.provider or not exists(
          select 1 from sectalk_private.st_v7_workspace_sso_sessions r join auth.sessions s on (s.id,s.user_id)=(r.session,r.principal)
          where r.workspace=p_workspace and (r.protocol,r.provider)=(setup.protocol,setup.provider)
            and sectalk_private.st_v2_active(r.principal) and sectalk_private.st_v2_role(p_workspace,r.principal) is not null
            and sectalk_private.st_v7_session_deadline(s.created_at,s.refreshed_at,s.not_after)>statement_timestamp()
        ) then return '{"access":"verified","error":"verified_provider_session_required"}'; end if;
      insert into sectalk_private.st_v8_workspace_legal_hold_sso(workspace,protocol,provider)
        values(p_workspace,setup.protocol,setup.provider)
        on conflict(workspace) do update set protocol=excluded.protocol,provider=excluded.provider;
    else
      delete from sectalk_private.st_v8_workspace_legal_hold_sso p where p.workspace=p_workspace;
    end if;
    if found then
      insert into public.st_v2_workspace_audit(workspace_id,actor,event)
        values(p_workspace,auth.uid(),case when p_require then 'workspace.legal_hold_sso_required'
          else 'workspace.legal_hold_sso_recovered' end);
    end if;
  end if;
  return jsonb_build_object('access','verified',
    'required',exists(select 1 from sectalk_private.st_v8_workspace_legal_hold_sso p where p.workspace=p_workspace));
end $$;

revoke all on function public.st_v8_workspace_legal_hold_policy(uuid,boolean) from public,anon,authenticated,service_role;
grant execute on function public.st_v8_workspace_legal_hold_policy(uuid,boolean) to authenticated;

-- Keep the independent governance sections available. Only the hold ledger,
-- administration and repeated hold rationale require this optional receipt.
create or replace function public.st_v6_workspace_hold_state(p_workspace uuid)
returns jsonb language plpgsql stable security definer set search_path='' as $$
declare access text:=sectalk_private.st_v6_holds_access(p_workspace);
begin
  if access='none' then
    raise exception 'Workspace governance is unavailable' using errcode='42501';
  end if;
  if access='mfa' then return jsonb_build_object('access',access); end if;
  if not sectalk_private.st_v8_legal_hold_sso_allows(p_workspace) then
    return jsonb_build_object('access',access,'hold_sso_required',true);
  end if;
  return jsonb_build_object('access',access,'holds',coalesce((
    select jsonb_agg(to_jsonb(h) order by h.created_at desc,h.id) from (
      select id,room_id,member_id,from_at,until_at,reason,created_at,released_at,release_reason
      from sectalk_private.st_v6_workspace_holds where workspace_id=p_workspace
      order by created_at desc,id limit 100
    ) h
  ),'[]'::jsonb));
end $$;

create or replace function public.st_v6_place_workspace_hold(
  p_workspace uuid,p_id uuid,p_room uuid,p_member uuid,p_from timestamptz,p_until timestamptz,p_reason text
)
returns uuid language plpgsql security definer set search_path='' as $$
declare clean_reason text:=btrim(p_reason);
declare existing sectalk_private.st_v6_workspace_holds;
begin
  if sectalk_private.st_v6_holds_access(p_workspace)<>'verified' then
    raise exception 'Verify an authenticator to manage preservation holds' using errcode='42501';
  end if;
  if p_id is null or clean_reason is null or char_length(clean_reason) not between 12 and 300
    or (p_room is null and p_member is null and p_from is null and p_until is null)
    or (p_from is not null and p_until is not null and p_from>=p_until)
    or (p_from is not null and not isfinite(p_from)) or (p_until is not null and not isfinite(p_until))
  then raise exception 'Choose a scope and provide a clear reason' using errcode='22023'; end if;
  perform sectalk_private.limit_action('v6_workspace_hold',10);
  perform pg_advisory_xact_lock(hashtextextended('sectalk-workspace-hold:'||p_workspace::text,0));
  perform 1 from public.st_v2_workspaces where id=p_workspace for no key update;
  if sectalk_private.st_v6_holds_access(p_workspace)<>'verified' then
    raise exception 'Workspace governance is unavailable' using errcode='42501';
  end if;
  if not sectalk_private.st_v8_legal_hold_sso_allows(p_workspace) then
    raise exception using errcode='42501',message='Sign in with workspace single sign-on to manage legal holds.';
  end if;
  select * into existing from sectalk_private.st_v6_workspace_holds where id=p_id;
  if found then
    if existing.workspace_id=p_workspace and existing.placed_by=auth.uid()
      and row(existing.room_id,existing.member_id,existing.from_at,existing.until_at,existing.reason)
        is not distinct from row(p_room,p_member,p_from,p_until,clean_reason) then return p_id; end if;
    raise exception 'Preservation hold request ID is already in use';
  end if;
  if (p_room is not null and not exists(select 1 from public.st_v6_rooms where id=p_room and workspace_id=p_workspace))
    or (p_member is not null and not exists(select 1 from public.st_v2_members where user_id=p_member and workspace_id=p_workspace))
  then raise exception 'Choose a room or member of this workspace' using errcode='22023'; end if;
  if (select count(*) from sectalk_private.st_v6_workspace_holds h
    where h.workspace_id=p_workspace and h.released_at is null)>=50
  then raise exception 'The workspace already has 50 active preservation holds'; end if;
  insert into sectalk_private.st_v6_workspace_holds(id,workspace_id,room_id,member_id,from_at,until_at,reason,placed_by)
    values(p_id,p_workspace,p_room,p_member,p_from,p_until,clean_reason,auth.uid());
  insert into public.st_v2_workspace_audit(workspace_id,actor,event,target)
    values(p_workspace,auth.uid(),'workspace.hold_placed',p_id);
  return p_id;
end $$;

create or replace function public.st_v6_release_workspace_hold(p_workspace uuid,p_id uuid,p_reason text)
returns void language plpgsql security definer set search_path='' as $$
declare clean_reason text:=btrim(p_reason);
begin
  if sectalk_private.st_v6_holds_access(p_workspace)<>'verified' then
    raise exception 'Verify an authenticator to manage preservation holds' using errcode='42501';
  end if;
  if clean_reason is null or char_length(clean_reason) not between 12 and 300 then
    raise exception 'Provide a release reason' using errcode='22023';
  end if;
  perform sectalk_private.limit_action('v6_workspace_hold',10);
  perform pg_advisory_xact_lock(hashtextextended('sectalk-workspace-hold:'||p_workspace::text,0));
  perform 1 from public.st_v2_workspaces where id=p_workspace for no key update;
  if sectalk_private.st_v6_holds_access(p_workspace)<>'verified' then
    raise exception 'Workspace governance is unavailable' using errcode='42501';
  end if;
  if not sectalk_private.st_v8_legal_hold_sso_allows(p_workspace) then
    raise exception using errcode='42501',message='Sign in with workspace single sign-on to manage legal holds.';
  end if;
  update sectalk_private.st_v6_workspace_holds set released_at=clock_timestamp(),released_by=auth.uid(),release_reason=clean_reason
  where id=p_id and workspace_id=p_workspace and released_at is null;
  if found then
    insert into public.st_v2_workspace_audit(workspace_id,actor,event,target)
      values(p_workspace,auth.uid(),'workspace.hold_released',p_id);
  elsif not exists(select 1 from sectalk_private.st_v6_workspace_holds where id=p_id and workspace_id=p_workspace) then
    raise exception 'Preservation hold unavailable' using errcode='42501';
  end if;
end $$;

create or replace function public.st_v7_evidence_vault(p_workspace uuid)
returns jsonb language plpgsql stable security definer set search_path='' as $$
declare viewer text:=public.st_v7_compliance_access(p_workspace); options jsonb:='[]'; snapshots jsonb;
begin
  if viewer not in ('admin','owner') then return jsonb_build_object('access',viewer); end if;
  if viewer='admin' then
    select coalesce(jsonb_agg(to_jsonb(selected)),'[]'::jsonb) into options from (
      select c.id as case_id,c.case_reference,r.id as report_id,h.id as hold_id,case
        when sectalk_private.st_v8_legal_hold_sso_allows(p_workspace) then h.reason
        else 'Active preservation hold' end as hold_reason
      from sectalk_private.st_v7_compliance_cases c cross join lateral jsonb_array_elements(c.sources) src
      join sectalk_private.st_v6_room_reports r on src->>'kind'='room_report' and r.id::text=src->>'id'
      join public.st_v6_room_posts p on (p.room_id,p.id)=(r.room_id,r.post_id)
      join sectalk_private.st_v6_workspace_holds h on h.workspace_id=c.workspace_id and h.released_at is null
      where c.workspace_id=p_workspace and c.requester=auth.uid() and r.workspace_id=p_workspace
        and r.share_with_workspace and r.status in ('open','reviewing') and p.removed_at is null
        and sectalk_private.st_v7_compliance_grant_live(c)
        and (h.room_id is null or h.room_id=p.room_id) and (h.member_id is null or h.member_id=p.sender)
        and (h.from_at is null or h.from_at<=p.created_at) and (h.until_at is null or h.until_at>p.created_at)
        and not exists(select 1 from sectalk_private.st_v7_evidence_snapshots s
          where (s.case_id,s.report_id,s.hold_id)=(c.id,r.id,h.id))
      order by c.created_at desc,r.id,h.id limit 100
    ) selected;
  end if;
  select coalesce(jsonb_agg(jsonb_build_object('id',s.id,'case_id',s.case_id,'case_reference',c.case_reference,
    'report_id',s.report_id,'hold_id',s.hold_id,'sha256',s.sha256,'captured_at',s.captured_at,
    'held',h.id is not null and h.released_at is null,
    'can_download',viewer='admin' and sectalk_private.st_v7_evidence_read_live(s),
    'custody',(select coalesce(jsonb_agg(to_jsonb(e) order by e.sequence desc),'[]'::jsonb)
      from (select a.sequence,a.previous_sha256,a.sha256,a.payload from sectalk_private.st_v7_evidence_custody a
        where a.snapshot_id=s.id order by a.sequence desc limit 30) e)) order by s.captured_at desc,s.id),'[]'::jsonb)
  into snapshots from (select v.* from sectalk_private.st_v7_evidence_snapshots v
    where v.workspace_id=p_workspace and (viewer='owner' or v.requester=auth.uid())
    order by v.captured_at desc,v.id limit 50) s
  left join sectalk_private.st_v7_compliance_cases c on c.id=s.case_id
  left join sectalk_private.st_v6_workspace_holds h on h.id=s.hold_id;
  return jsonb_build_object('access',viewer,'options',options,'snapshots',snapshots);
end $$;

commit;
