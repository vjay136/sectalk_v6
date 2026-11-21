begin;

alter table sectalk_private.st_v8_managed_room_posts
  drop constraint st_v8_managed_room_posts_wrapped_dek_check,
  add constraint st_v8_managed_room_posts_wrapped_dek_check check(
    length(wrapped_dek) between 80 and 2048 and wrapped_dek~'^[A-Za-z0-9_-]+$');
create index st_v8_managed_room_evidence_workspace_report
  on sectalk_private.st_v8_managed_room_evidence(workspace,report);

create function public.st_v8_submit_consented_managed_room_report(p_room uuid,p_post uuid,p_revision text,
  p_category text,p_details text,p_consent boolean,p_workspace_consent boolean)
returns uuid language plpgsql security definer set search_path='' as $$
declare report_id uuid; already_submitted boolean;
begin
  if p_workspace_consent is null or (p_workspace_consent and p_category not in ('spam','other')) then
    raise exception 'Workspace disclosure is available for spam and other reports' using errcode='22023';
  end if;
  perform pg_advisory_xact_lock(hashtextextended('managed-room-report:'||concat_ws(':',auth.uid(),p_room,p_post),0));
  select r.share_with_workspace into already_submitted from sectalk_private.st_v6_room_reports r
    where r.reporter=auth.uid() and r.room_id=p_room and r.post_id=p_post;
  report_id:=public.st_v8_submit_managed_room_report(p_room,p_post,p_revision,p_category,p_details,p_consent);
  if already_submitted is not null and already_submitted is distinct from p_workspace_consent then
    raise exception 'Consent cannot be changed after reporting' using errcode='PT409';
  end if;
  if already_submitted is null and p_workspace_consent then
    update sectalk_private.st_v6_room_reports set share_with_workspace=true where id=report_id;
  end if;
  return report_id;
end $$;

-- Serialize both reporting entry points so platform-only capture cannot be upgraded by a concurrent request.
create function sectalk_private.st_v8_lock_room_report_insert()
returns trigger language plpgsql set search_path='' as $$
begin
  perform pg_advisory_xact_lock(hashtextextended('managed-room-report:'||
    concat_ws(':',new.reporter,new.room_id,new.post_id),0));
  return new;
end $$;
create trigger st_v8_lock_room_report_insert before insert on sectalk_private.st_v6_room_reports
  for each row execute function sectalk_private.st_v8_lock_room_report_insert();

create function sectalk_private.st_v8_held_managed_room_sources(
  p_workspace uuid,p_actor uuid,p_reviewer uuid,p_report uuid
) returns table(id uuid,category text,hold_id uuid,room_id uuid,post_id uuid,sender uuid,revision text,
  envelope jsonb,key_version integer,reported_at timestamptz)
language sql stable set search_path='' as $$
  select r.id,r.category,h.id,e.room,e.post,e.sender,e.revision,
    jsonb_build_object('body',e.body,'nonce',e.nonce,'tag',e.tag,'wrapped_dek',e.wrapped_dek),
    e.key_version,r.created_at
  from sectalk_private.st_v8_managed_room_evidence e
  join sectalk_private.st_v6_room_reports r on
    (r.id,r.room_id,r.post_id,r.workspace_id,r.subject)=(e.report,e.room,e.post,e.workspace,e.sender)
  join public.st_v6_rooms managed_room on (managed_room.id,managed_room.workspace_id)=(e.room,e.workspace)
  join sectalk_private.st_v8_managed_room_posts m on (m.room,m.id,m.workspace,m.sender,m.key_version)=
    (e.room,e.post,e.workspace,e.sender,e.key_version)
  join sectalk_private.st_v7_tenant_key_versions k on (k.workspace,k.version)=(e.workspace,e.key_version)
  join sectalk_private.st_v7_tenant_key_state s on s.workspace=e.workspace and s.destroyed_at is null
  cross join lateral (
    select h.id from sectalk_private.st_v6_workspace_holds h where h.workspace_id=e.workspace
      and (h.room_id is null or h.room_id=e.room) and (h.member_id is null or h.member_id=e.sender)
      and h.released_at is null and (h.from_at is null or h.from_at<=m.created_at)
      and (h.until_at is null or h.until_at>m.created_at)
    order by h.created_at,h.id limit 1
  ) h
  where e.workspace=p_workspace and (p_report is null or e.report=p_report)
    and r.share_with_workspace and r.handed_off_at is not null and r.category in ('spam','other')
    and r.status in ('open','reviewing') and not managed_room.archived
    and managed_room.classification in ('public','internal','confidential')
    and (e.body,e.nonce,e.tag,e.wrapped_dek)=(m.body,m.nonce,m.tag,m.wrapped_dek)
    and e.revision=encode(sha256(convert_to(concat_ws(':',e.room,e.post,e.workspace,e.sender,
      e.key_version,e.body,e.nonce,e.tag,e.wrapped_dek),'UTF8')),'hex')
    and p_actor not in (r.reporter,e.sender) and sectalk_private.st_v2_role(e.workspace,p_actor)='admin'
    and sectalk_private.st_v2_active(p_actor) and sectalk_private.st_v8_managed_room_allowed(managed_room,p_actor,false)
    and sectalk_private.open_pair(p_actor,e.sender)
    and exists(select 1 from public.st_v2_members member
      where member.workspace_id=e.workspace and member.role='owner'
        and (p_reviewer is null or member.user_id=p_reviewer)
        and member.user_id not in (p_actor,r.reporter,e.sender)
        and sectalk_private.st_v2_active(member.user_id)
        and sectalk_private.st_v8_managed_room_allowed(managed_room,member.user_id,false)
        and sectalk_private.open_pair(member.user_id,e.sender))
  order by r.created_at desc,r.id limit 50;
$$;

alter function public.st_v7_compliance_sources(uuid) set schema sectalk_private;
create function public.st_v7_compliance_sources(p_workspace uuid)
returns table(kind text,id text,label text,occurred_at timestamptz)
language plpgsql stable security definer set search_path='' as $$
begin
  return query select x.* from sectalk_private.st_v7_compliance_sources(p_workspace) x;
  return query select 'managed_room_report'::text,r.id::text,r.category,r.reported_at
    from sectalk_private.st_v8_held_managed_room_sources(p_workspace,auth.uid(),null,null) r;
end $$;

alter function sectalk_private.st_v7_compliance_record(uuid,uuid,uuid,text,text) rename to st_v8_compliance_record_base;
create function sectalk_private.st_v7_compliance_record(p_workspace uuid,p_actor uuid,p_reviewer uuid,p_kind text,p_id text)
returns jsonb language plpgsql stable set search_path='' set timezone='UTC' as $$
begin
  if p_kind<>'managed_room_report' then
    return sectalk_private.st_v8_compliance_record_base(p_workspace,p_actor,p_reviewer,p_kind,p_id);
  end if;
  if p_id!~'^[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}$' then return null; end if;
  return (select jsonb_build_object('id',r.id,'category',r.category,'room',r.room_id,'post',r.post_id,
    'author',r.sender,'encrypted_revision',r.revision,'hold',r.hold_id,'envelope',r.envelope)
    from sectalk_private.st_v8_held_managed_room_sources(p_workspace,p_actor,p_reviewer,p_id::uuid) r);
end $$;

create function public.st_v8_managed_room_compliance_keys(p_ticket uuid)
returns jsonb language plpgsql stable security definer set search_path='' as $$
declare c sectalk_private.st_v7_compliance_cases;
begin
  select * into c from sectalk_private.st_v7_compliance_cases where ticket=p_ticket and operation='download';
  if c.id is null or not sectalk_private.st_v7_compliance_operation_live(c)
    or sectalk_private.st_v7_compliance_revalidate(c) is null then return null; end if;
  return coalesce((select jsonb_object_agg(r.id,jsonb_build_object('workspace',k.workspace,'version',k.version,
      'custody',k.custody,'ref',k.provider_ref,'wrapped',k.wrapped))
    from jsonb_array_elements(c.sources) e(item)
    cross join lateral sectalk_private.st_v8_held_managed_room_sources(c.workspace_id,c.requester,c.reviewer,
      case when e.item->>'kind'='managed_room_report' then (e.item->>'id')::uuid end) r
    join sectalk_private.st_v7_tenant_key_versions k on (k.workspace,k.version)=(c.workspace_id,r.key_version)
    where e.item->>'kind'='managed_room_report'),'{}'::jsonb);
end $$;

revoke all on function public.st_v8_submit_consented_managed_room_report(uuid,uuid,text,text,text,boolean,boolean),
  sectalk_private.st_v8_lock_room_report_insert(),sectalk_private.st_v8_held_managed_room_sources(uuid,uuid,uuid,uuid),
  sectalk_private.st_v7_compliance_sources(uuid),public.st_v7_compliance_sources(uuid),
  sectalk_private.st_v7_compliance_record(uuid,uuid,uuid,text,text),public.st_v8_managed_room_compliance_keys(uuid)
  from public,anon,authenticated,service_role;
grant execute on function public.st_v8_submit_consented_managed_room_report(uuid,uuid,text,text,text,boolean,boolean),
  public.st_v7_compliance_sources(uuid) to authenticated;
grant execute on function public.st_v8_managed_room_compliance_keys(uuid) to service_role;
notify pgrst,'reload schema';
commit;
