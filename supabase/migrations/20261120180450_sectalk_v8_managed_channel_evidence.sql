begin;

alter table sectalk_private.st_v7_channel_reports add column managed_revision text check(managed_revision~'^[a-f0-9]{64}$');
create table sectalk_private.st_v8_managed_report_tickets (
  id uuid primary key default gen_random_uuid(),
  channel uuid not null,
  post uuid not null,
  actor uuid not null,
  native_session uuid not null,
  revision text not null,
  category text not null,
  details text not null,
  tenant_consent boolean not null,
  expires_at timestamptz not null default clock_timestamp()+interval '30 seconds'
);
create index st_v8_managed_report_ticket_expiry on sectalk_private.st_v8_managed_report_tickets(expires_at);
create table sectalk_private.st_v8_managed_evidence_views (
  id bigint generated always as identity primary key,
  report uuid not null,
  workspace uuid not null,
  actor uuid not null,
  review_scope text not null check(review_scope in ('platform','workspace')),
  revision text not null,
  occurred_at timestamptz not null default clock_timestamp()
);
create trigger st_v8_immutable_managed_evidence_views before update or delete on sectalk_private.st_v8_managed_evidence_views
  for each row execute function sectalk_private.st_v7_immutable_threat_audit();
alter table sectalk_private.st_v8_managed_report_tickets enable row level security;
alter table sectalk_private.st_v8_managed_evidence_views enable row level security;
revoke all on sectalk_private.st_v8_managed_report_tickets,sectalk_private.st_v8_managed_evidence_views
  from public,anon,authenticated,service_role;

create function sectalk_private.st_v8_managed_revision(e sectalk_private.st_v8_channel_payloads)
returns text language sql immutable strict set search_path='' as $$
  select encode(sha256(convert_to(jsonb_build_array(e.workspace,e.post,e.key_version,e.body,e.nonce,e.tag,e.wrapped_dek)::text,
    'UTF8')),'hex');
$$;

create or replace function sectalk_private.st_v8_guard_managed_channel_report()
returns trigger language plpgsql security definer set search_path='' as $$
begin
  if tg_op='UPDATE' then
    if old.managed_revision is not null and
      (new.managed_revision,new.workspace_id,new.channel_id,new.post_id,new.evidence,new.reporter,new.tenant_consent,new.category,new.details)
      is distinct from
      (old.managed_revision,old.workspace_id,old.channel_id,old.post_id,old.evidence,old.reporter,old.tenant_consent,old.category,old.details) then
      raise exception 'Managed snapshot evidence and consent are immutable' using errcode='42501'; end if;
    return new;
  end if;
  if exists(select 1 from public.st_v2_channels c where c.id=new.channel_id and c.encryption_mode='managed')
    and not exists(select 1 from public.st_v2_posts p join sectalk_private.st_v8_channel_payloads e on e.post=p.id
      where p.id=new.post_id and p.channel_id=new.channel_id and p.sender=new.subject and p.quarantined_at is null
        and e.workspace=new.workspace_id and new.managed_revision=sectalk_private.st_v8_managed_revision(e)) then
    raise exception 'Managed channel reports require an approved evidence capture source' using errcode='42501';
  end if;
  return new;
end $$;
create trigger st_v8_guard_managed_evidence_update before update on sectalk_private.st_v7_channel_reports
  for each row execute function sectalk_private.st_v8_guard_managed_channel_report();

create function public.st_v8_begin_managed_channel_report(p_channel uuid,p_post uuid,p_category text,p_details text,
  p_share_with_safety boolean,p_share_with_workspace boolean)
returns jsonb language plpgsql security definer set search_path='' as $$
declare actor_id uuid:=auth.uid(); chosen_revision text; receipt uuid;
begin
  if p_share_with_safety is not true or p_share_with_workspace is null or p_category is null
    or p_category not in ('harassment','threat','scam','impersonation','spam','sexual_content','other')
    or char_length(coalesce(p_details,''))>1500 then
    raise exception 'Affirmative consent and a valid category are required' using errcode='22023'; end if;
  if public.st_v8_managed_channel_still_readable(p_channel) is not true then
    raise exception 'Managed channel report unavailable' using errcode='42501'; end if;
  select sectalk_private.st_v8_managed_revision(e) into chosen_revision from public.st_v2_posts p
    join sectalk_private.st_v8_channel_payloads e on e.post=p.id
    where p.id=p_post and p.channel_id=p_channel and p.sender<>actor_id and p.quarantined_at is null
      and sectalk_private.st_v2_post_read(p.channel_id,p.sender,actor_id);
  if chosen_revision is null then raise exception 'Managed channel report unavailable' using errcode='42501'; end if;
  select r.id into receipt from sectalk_private.st_v7_channel_reports r where r.reporter=actor_id
    and r.channel_id=p_channel and r.post_id=p_post;
  if receipt is not null then return jsonb_build_object('report',receipt); end if;
  perform sectalk_private.limit_action('v7_channel_report',10);
  delete from sectalk_private.st_v8_managed_report_tickets where expires_at<=statement_timestamp();
  insert into sectalk_private.st_v8_managed_report_tickets(channel,post,actor,native_session,revision,category,details,tenant_consent)
    values(p_channel,p_post,actor_id,(auth.jwt()->>'session_id')::uuid,chosen_revision,p_category,
      btrim(coalesce(p_details,'')),p_share_with_workspace and p_category in ('spam','other')) returning id into receipt;
  return jsonb_build_object('ticket',receipt);
end $$;

create function sectalk_private.st_v8_managed_report_live(t sectalk_private.st_v8_managed_report_tickets)
returns boolean language sql stable set search_path='' as $$
  select t.id is not null and t.expires_at>statement_timestamp() and sectalk_private.st_v2_active(t.actor)
    and not exists (select 1 from sectalk_private.st_v7_account_lockdowns l where l.user_id=t.actor and l.released_at is null)
    and exists(select 1 from auth.sessions s where s.id=t.native_session and s.user_id=t.actor
      and sectalk_private.st_v7_session_deadline(s.created_at,s.refreshed_at,s.not_after)>statement_timestamp());
$$;

create function public.st_v8_load_managed_channel_report(p_ticket uuid,p_actor uuid)
returns jsonb language sql stable security definer set search_path='' as $$
  select jsonb_build_object('id',p.id,'channel',p.channel_id,'sender',p.sender,
    'key',jsonb_build_object('workspace',e.workspace,'version',k.version,'custody',k.custody,
      'ref',k.provider_ref,'wrapped',k.wrapped),
    'envelope',jsonb_build_object('body',e.body,'nonce',e.nonce,'tag',e.tag,'wrapped_dek',e.wrapped_dek))
  from sectalk_private.st_v8_managed_report_tickets t join public.st_v2_posts p on (p.id,p.channel_id)=(t.post,t.channel)
  join sectalk_private.st_v8_channel_payloads e on e.post=p.id
  join sectalk_private.st_v7_tenant_key_versions k on (k.workspace,k.version)=(e.workspace,e.key_version)
  where t.id=p_ticket and t.actor=p_actor and sectalk_private.st_v8_managed_report_live(t)
    and p.sender<>t.actor and p.quarantined_at is null and sectalk_private.st_v2_post_read(p.channel_id,p.sender,t.actor)
    and t.revision=sectalk_private.st_v8_managed_revision(e);
$$;

create function public.st_v8_finish_managed_channel_report(p_ticket uuid,p_actor uuid,p_evidence text)
returns uuid language plpgsql security definer set search_path='' as $$
declare t sectalk_private.st_v8_managed_report_tickets; source record; receipt uuid;
begin
  if char_length(coalesce(btrim(p_evidence),'')) not between 1 and 4000 then return null; end if;
  delete from sectalk_private.st_v8_managed_report_tickets where id=p_ticket and actor=p_actor returning * into t;
  if sectalk_private.st_v8_managed_report_live(t) is not true then return null; end if;
  select p.sender,e.workspace into source from public.st_v2_posts p join sectalk_private.st_v8_channel_payloads e on e.post=p.id
    where p.id=t.post and p.channel_id=t.channel and p.sender<>t.actor and p.quarantined_at is null
      and sectalk_private.st_v2_post_read(p.channel_id,p.sender,t.actor) and t.revision=sectalk_private.st_v8_managed_revision(e)
    for share of p,e;
  if not found then return null; end if;
  insert into sectalk_private.st_v7_channel_reports(workspace_id,channel_id,post_id,reporter,subject,category,details,evidence,tenant_consent,managed_revision)
    values(source.workspace,t.channel,t.post,t.actor,source.sender,t.category,t.details,p_evidence,t.tenant_consent,t.revision)
    on conflict(reporter,channel_id,post_id) do nothing returning id into receipt;
  if receipt is null then
    select r.id into receipt from sectalk_private.st_v7_channel_reports r where (r.reporter,r.channel_id,r.post_id)=(t.actor,t.channel,t.post);
  end if;
  return receipt;
end $$;

create function public.st_v8_view_managed_channel_report(p_report uuid,p_scope text)
returns text language plpgsql security definer set search_path='' as $$
declare item sectalk_private.st_v7_channel_reports; me uuid:=auth.uid();
begin
  if sectalk_private.st_v7_admin_fresh() is not true or public.st_v7_account_under_lockdown()
    or not sectalk_private.st_v7_channel_report_staff(p_scope) then
    raise exception 'Fresh channel evidence review access required' using errcode='42501'; end if;
  select * into item from sectalk_private.st_v7_channel_reports where id=p_report;
  if item.managed_revision is null or me=item.reporter or me is not distinct from item.subject
    or (p_scope='workspace' and (not item.tenant_consent or item.handed_off_at is null
      or not sectalk_private.st_v7_channel_report_local(item.channel_id,item.workspace_id,me))) then
    raise exception 'Managed channel evidence unavailable' using errcode='42501'; end if;
  perform sectalk_private.limit_action('v8_managed_report_view',30);
  insert into sectalk_private.st_v8_managed_evidence_views(report,workspace,actor,review_scope,revision)
    values(item.id,item.workspace_id,me,p_scope,item.managed_revision);
  return item.evidence;
end $$;

create function sectalk_private.st_v8_held_channel_sources(p_workspace uuid,p_actor uuid,p_reviewer uuid,p_report uuid)
returns table(id uuid,category text,channel_id uuid,post_id uuid,author_id uuid,revision text,hold_id uuid,body text,reported_at timestamptz)
language sql stable set search_path='' as $$
  select r.id,r.category,r.channel_id,r.post_id,p.sender,r.managed_revision,h.id,r.evidence,r.created_at
  from sectalk_private.st_v7_channel_reports r
  join public.st_v2_channels c on (c.id,c.workspace_id)=(r.channel_id,r.workspace_id) and c.encryption_mode='managed'
  join public.st_v2_posts p on (p.id,p.channel_id,p.sender)=(r.post_id,r.channel_id,r.subject)
  join sectalk_private.st_v8_channel_payloads e on e.post=p.id and e.workspace=r.workspace_id
  cross join lateral (
    select h.id from sectalk_private.st_v6_workspace_holds h where h.workspace_id=r.workspace_id
      and h.room_id is null and h.released_at is null
      and (h.member_id is null or h.member_id=p.sender)
      and (h.from_at is null or h.from_at<=p.created_at) and (h.until_at is null or h.until_at>p.created_at)
    order by h.created_at,h.id limit 1
  ) h
  where r.workspace_id=p_workspace and (p_report is null or r.id=p_report) and r.tenant_consent and r.handed_off_at is not null
    and r.state in ('open','reviewing') and r.managed_revision=sectalk_private.st_v8_managed_revision(e)
    and p_actor is distinct from p.sender and p_actor<>r.reporter
    and sectalk_private.st_v7_channel_report_local(r.channel_id,r.workspace_id,p_actor)
    and sectalk_private.st_v2_post_read(r.channel_id,p.sender,p_actor)
    and (p_reviewer is null or (p_reviewer is distinct from p.sender and p_reviewer<>r.reporter
      and sectalk_private.st_v7_channel_report_local(r.channel_id,r.workspace_id,p_reviewer)
      and sectalk_private.st_v2_post_read(r.channel_id,p.sender,p_reviewer)))
  order by r.created_at desc,r.id limit 50;
$$;

revoke all on function sectalk_private.st_v8_managed_revision(sectalk_private.st_v8_channel_payloads),
  sectalk_private.st_v8_managed_report_live(sectalk_private.st_v8_managed_report_tickets),
  sectalk_private.st_v8_held_channel_sources(uuid,uuid,uuid,uuid),public.st_v8_begin_managed_channel_report(uuid,uuid,text,text,boolean,boolean),
  public.st_v8_load_managed_channel_report(uuid,uuid),public.st_v8_finish_managed_channel_report(uuid,uuid,text),
  public.st_v8_view_managed_channel_report(uuid,text) from public,anon,authenticated,service_role;
grant execute on function public.st_v8_begin_managed_channel_report(uuid,uuid,text,text,boolean,boolean),
  public.st_v8_view_managed_channel_report(uuid,text) to authenticated;
grant execute on function public.st_v8_load_managed_channel_report(uuid,uuid),
  public.st_v8_finish_managed_channel_report(uuid,uuid,text) to service_role;

create or replace function public.st_v7_channel_report_queue(p_scope text)
returns jsonb language plpgsql stable security definer set search_path='' as $$
begin
  if not sectalk_private.st_v7_channel_report_staff(p_scope) then
    raise exception using errcode='42501',message='Channel report review is unavailable';
  end if;
  return coalesce((select jsonb_agg(to_jsonb(q) order by q.created_at desc,q.id) from(
    select r.id,r.category,r.state,r.created_at,r.handed_off_at,r.category in ('spam','other') and r.tenant_consent as handoff_allowed,
      case when p_scope='platform' then r.details else '' end as details,case when r.managed_revision is null then r.evidence end as evidence,r.managed_revision is not null as managed,c.name as channel_name,w.name as workspace_name
    from sectalk_private.st_v7_channel_reports r
    left join public.st_v2_channels c on c.id=r.channel_id and c.workspace_id=r.workspace_id
    left join public.st_v2_workspaces w on w.id=r.workspace_id
    where auth.uid()<>r.reporter and auth.uid() is distinct from r.subject
      and (p_scope='platform' or (r.handed_off_at is not null and
        sectalk_private.st_v7_channel_report_local(r.channel_id,r.workspace_id,auth.uid())))
    order by r.created_at desc,r.id limit 100
  ) q),'[]'::jsonb);
end $$;

create or replace function public.st_v7_compliance_sources(p_workspace uuid)
returns table(kind text,id text,label text,occurred_at timestamptz)
language plpgsql stable security definer set search_path='' as $$
begin
  if public.st_v7_compliance_access(p_workspace)<>'admin' then
    raise exception 'Fresh workspace administrator verification required' using errcode='42501';
  end if;
  return query select 'audit'::text,a.id::text,a.event,a.created_at
    from public.st_v2_workspace_audit a where a.workspace_id=p_workspace
    order by a.created_at desc,a.id desc limit 50;
  return query select 'room_report'::text,r.id::text,r.category,r.reported_at
    from sectalk_private.st_v7_compliance_report_sources(p_workspace,auth.uid(),null,null) r;
  return query select 'managed_channel_report'::text,r.id::text,r.category,r.reported_at
    from sectalk_private.st_v8_held_channel_sources(p_workspace,auth.uid(),null,null) r;
end $$;

create or replace function sectalk_private.st_v7_compliance_record(p_workspace uuid,p_actor uuid,p_reviewer uuid,p_kind text,p_id text)
returns jsonb language plpgsql stable set search_path='' set timezone='UTC' as $$
begin
  if p_kind='audit' and p_id~'^[1-9][0-9]{0,17}$' then
    return (select jsonb_build_object('id',a.id::text,'event',a.event,'actor',a.actor,'target',a.target,'created_at',a.created_at)
      from public.st_v2_workspace_audit a where a.workspace_id=p_workspace and a.id=p_id::bigint);
  elsif p_kind='room_report' and p_id~'^[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}$' then
    return (select jsonb_build_object('id',r.id,'category',r.category,'room',r.room_id,'post',r.post_id,'author',r.author_id,
      'revision',r.revision,'body',r.body)
      from sectalk_private.st_v7_compliance_report_sources(p_workspace,p_actor,p_reviewer,p_id::uuid) r);
  elsif p_kind='managed_channel_report' and p_id~'^[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}$' then
    return (select jsonb_build_object('id',r.id,'category',r.category,'channel',r.channel_id,'post',r.post_id,
      'author',r.author_id,'encrypted_revision',r.revision,'hold',r.hold_id,'body',r.body)
      from sectalk_private.st_v8_held_channel_sources(p_workspace,p_actor,p_reviewer,p_id::uuid) r);
  end if;
  return null;
end $$;

notify pgrst,'reload schema';
commit;
