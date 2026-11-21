begin;

create table sectalk_private.st_v8_managed_room_evidence (
  report uuid primary key references sectalk_private.st_v6_room_reports on delete cascade,
  room uuid not null,
  post uuid not null,
  workspace uuid not null,
  sender uuid not null,
  key_version integer not null,
  revision text not null check(revision~'^[a-f0-9]{64}$'),
  body text not null,
  nonce text not null,
  tag text not null,
  wrapped_dek text not null
);
create table sectalk_private.st_v8_managed_room_evidence_reads (
  id bigint generated always as identity primary key,
  report uuid not null,
  actor uuid not null,
  revision text not null,
  occurred_at timestamptz not null default clock_timestamp()
);
alter table sectalk_private.st_v8_managed_room_evidence enable row level security;
alter table sectalk_private.st_v8_managed_room_evidence_reads enable row level security;
revoke all on sectalk_private.st_v8_managed_room_evidence,sectalk_private.st_v8_managed_room_evidence_reads
  from public,anon,authenticated,service_role;

create function public.st_v8_submit_managed_room_report(p_room uuid,p_post uuid,p_revision text,
  p_category text,p_details text,p_consent boolean)
returns uuid language plpgsql security definer set search_path='' as $$
declare m sectalk_private.st_v8_managed_room_posts; report_id uuid; actor uuid:=auth.uid();
begin
  if p_consent is not true or coalesce(p_revision,'')!~'^[a-f0-9]{64}$'
    or coalesce(p_category,'') not in ('harassment','threat','scam','impersonation','spam','sexual_content','other')
    or char_length(coalesce(p_details,''))>1500 then
    raise exception 'Choose a category and approve sharing this revision with Platform Safety' using errcode='22023';
  end if;
  if public.st_v8_managed_room_readable(p_room) is not true then
    raise exception 'Room post unavailable for reporting' using errcode='42501';
  end if;
  select * into m from sectalk_private.st_v8_managed_room_posts where room=p_room and id=p_post
    and sender<>actor for share;
  if not found then raise exception 'Room post unavailable for reporting' using errcode='42501'; end if;
  if p_revision<>encode(sha256(convert_to(concat_ws(':',m.room,m.id,m.workspace,m.sender,
      m.key_version,m.body,m.nonce,m.tag,m.wrapped_dek),'UTF8')),'hex') then
    raise exception 'Message revision changed. Reload it before reporting.' using errcode='PT409';
  end if;
  perform sectalk_private.limit_action('v6_room_report',10);
  insert into sectalk_private.st_v6_room_reports(workspace_id,room_id,post_id,reporter,subject,category,details,share_with_workspace)
    values(m.workspace,m.room,m.id,actor,m.sender,p_category,btrim(coalesce(p_details,'')),false)
    on conflict(reporter,room_id,post_id) do nothing returning id into report_id;
  if report_id is null then
    select r.id into report_id from sectalk_private.st_v6_room_reports r
      join sectalk_private.st_v8_managed_room_evidence e on e.report=r.id and e.revision=p_revision
      where r.reporter=actor and r.room_id=p_room and r.post_id=p_post;
    if report_id is null then
      raise exception 'A different revision has already been reported' using errcode='PT409';
    end if;
    return report_id;
  end if;
  insert into sectalk_private.st_v8_managed_room_evidence
    values(report_id,m.room,m.id,m.workspace,m.sender,m.key_version,p_revision,m.body,m.nonce,m.tag,m.wrapped_dek);
  return report_id;
end $$;

create function public.st_v8_managed_room_evidence_present(p_report uuid)
returns boolean language sql stable security definer set search_path='' as $$
  select coalesce(sectalk_private.st_v6_case_redaction_staff() and public.st_v7_current_session_valid()
    and not public.st_v7_account_under_lockdown() and exists(
      select 1 from sectalk_private.st_v8_managed_room_evidence e
        join sectalk_private.st_v6_room_reports r on r.id=e.report
      where e.report=p_report and r.reporter<>auth.uid() and e.sender<>auth.uid()),false)
$$;

create function public.st_v8_managed_room_evidence_access(p_report uuid,p_revision text default null)
returns boolean language plpgsql security definer set search_path='' as $$
declare evidence_revision text;
begin
  if not public.st_v8_managed_room_evidence_present(p_report)
    or not sectalk_private.st_v7_security_session('totp') then return false; end if;
  select e.revision into evidence_revision from sectalk_private.st_v8_managed_room_evidence e
    join sectalk_private.st_v6_room_reports r on r.id=e.report
    join sectalk_private.st_v7_tenant_key_state k on k.workspace=e.workspace and k.destroyed_at is null
    where e.report=p_report and r.reporter<>auth.uid() and e.sender<>auth.uid()
      and (p_revision is null or e.revision=p_revision);
  if not found then return false; end if;
  if p_revision is not null then
    insert into sectalk_private.st_v8_managed_room_evidence_reads(report,actor,revision)
      values(p_report,auth.uid(),evidence_revision);
  end if;
  return true;
end $$;

create function public.st_v8_managed_room_evidence_envelope(p_report uuid)
returns jsonb language sql stable security definer set search_path='' as $$
  select jsonb_build_object('room',e.room,'id',e.post,'sender',e.sender,'revision',e.revision,
    'envelope',jsonb_build_object('body',e.body,'nonce',e.nonce,'tag',e.tag,'wrapped_dek',e.wrapped_dek),
    'key',jsonb_build_object('workspace',e.workspace,'version',k.version,'custody',k.custody,
      'ref',k.provider_ref,'wrapped',k.wrapped))
  from sectalk_private.st_v8_managed_room_evidence e
  join sectalk_private.st_v7_tenant_key_versions k on (k.workspace,k.version)=(e.workspace,e.key_version)
  join sectalk_private.st_v7_tenant_key_state s on s.workspace=e.workspace and s.destroyed_at is null
  where e.report=p_report
$$;

revoke all on function public.st_v8_submit_managed_room_report(uuid,uuid,text,text,text,boolean),
  public.st_v8_managed_room_evidence_present(uuid),public.st_v8_managed_room_evidence_access(uuid,text),
  public.st_v8_managed_room_evidence_envelope(uuid)
  from public,anon,authenticated,service_role;
grant execute on function public.st_v8_submit_managed_room_report(uuid,uuid,text,text,text,boolean),
  public.st_v8_managed_room_evidence_present(uuid),public.st_v8_managed_room_evidence_access(uuid,text) to authenticated;
grant execute on function public.st_v8_managed_room_evidence_envelope(uuid) to service_role;
notify pgrst,'reload schema';
commit;
