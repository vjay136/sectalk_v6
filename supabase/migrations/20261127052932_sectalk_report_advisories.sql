begin;

create table sectalk_private.st_report_lineage (
  report uuid primary key references public.st_reports(id) on delete cascade,
  root uuid not null references sectalk_private.st_forward_lineage(id),
  received_at timestamptz not null
);
create index st_report_lineage_root_received on sectalk_private.st_report_lineage(root,received_at);
create table sectalk_private.st_message_advisories (
  root uuid primary key references sectalk_private.st_forward_lineage(id),
  report uuid not null references public.st_reports(id) on delete cascade,
  verdict text not null check(verdict in ('warning','cleared')),
  category text check(category in ('spam','unwanted','fake','abuse','fraud','gambling','insecure_link','other')),
  check((verdict='warning')=(category is not null))
);
alter table sectalk_private.st_report_lineage enable row level security;
alter table sectalk_private.st_message_advisories enable row level security;
revoke all on sectalk_private.st_report_lineage,sectalk_private.st_message_advisories from public,anon,authenticated,service_role;

create function sectalk_private.st_anchor_report_lineage()
returns trigger language plpgsql security definer set search_path='' as $$
declare
  current_message public.st_messages;
  fingerprint bytea;
  case_root uuid;
begin
  if new.chat_id is null or new.message_id is null or new.evidence is null then return new; end if;
  select * into current_message from public.st_messages m
    where (m.chat_id,m.id,m.sender)=(new.chat_id,new.message_id,new.subject) and m.body=new.evidence;
  if not found or current_message.revoked_at is not null or current_message.expires_at is not null then return new; end if;
  fingerprint:=extensions.digest(new.evidence,'sha256');
  insert into sectalk_private.st_forward_lineage(kind,scope_id,message_id,body_digest,actor,original_known)
    values('direct',new.chat_id,new.message_id,fingerprint,new.subject,not current_message.forwarded)
    on conflict(kind,scope_id,message_id,body_digest) do nothing;
  select coalesce(n.root_id,n.id) into strict case_root from sectalk_private.st_forward_lineage n
    where n.kind='direct' and n.scope_id=new.chat_id and n.message_id=new.message_id and n.body_digest=fingerprint;
  insert into sectalk_private.st_report_lineage(report,root,received_at)
    values(new.id,case_root,new.created_at);
  return new;
end;
$$;
revoke all on function sectalk_private.st_anchor_report_lineage() from public,anon,authenticated,service_role;
create trigger st_report_lineage_after_insert after insert on public.st_reports
  for each row execute function sectalk_private.st_anchor_report_lineage();

-- Historical cases are eligible only if their evidence still matches the live revision.
insert into sectalk_private.st_forward_lineage(kind,scope_id,message_id,body_digest,actor,original_known)
  select 'direct',m.chat_id,m.id,extensions.digest(r.evidence,'sha256'),m.sender,not m.forwarded
  from public.st_reports r join public.st_messages m
    on (m.chat_id,m.id,m.sender)=(r.chat_id,r.message_id,r.subject) and m.body=r.evidence
  where m.revoked_at is null and m.expires_at is null
  on conflict(kind,scope_id,message_id,body_digest) do nothing;
insert into sectalk_private.st_report_lineage(report,root,received_at)
  select r.id,coalesce(n.root_id,n.id),r.created_at
  from public.st_reports r join sectalk_private.st_forward_lineage n
    on n.kind='direct' and (n.scope_id,n.message_id)=(r.chat_id,r.message_id)
    and n.body_digest=extensions.digest(r.evidence,'sha256');

create function sectalk_private.st_can_review_report_lineage()
returns boolean language sql stable set search_path='' as $$
  select coalesce(sectalk_private.st_v6_case_redaction_staff(),false)
    and coalesce(public.st_v7_current_session_valid(),false)
    and public.st_v7_login_risk_status() is not distinct from 'clear'
    and not public.st_v7_account_under_lockdown();
$$;
revoke all on function sectalk_private.st_can_review_report_lineage() from public,anon,authenticated,service_role;

create function public.st_report_propagation(p_report uuid)
returns jsonb language plpgsql stable security definer set search_path='' as $$
declare
  result jsonb;
begin
  if not sectalk_private.st_can_review_report_lineage() then
    raise exception 'Verified moderator access is required' using errcode='42501';
  end if;
  select jsonb_build_object(
    'eligible',true,'verdict',advisory.verdict,'category',advisory.category,
    'can_change',advisory.report is null or advisory.report=p_report,
    'forward_count',(select count(*) from sectalk_private.st_forward_lineage f where f.root_id=origin.id),
    'forwarders',(select count(distinct f.actor) from sectalk_private.st_forward_lineage f where f.root_id=origin.id),
    'original_name',case when origin.original_known then profile.name end,
    'first_report_at',(select min(r.received_at) from sectalk_private.st_report_lineage r where r.root=origin.id)
  ) into result
  from sectalk_private.st_report_lineage anchor
  join public.st_reports case_row on case_row.id=anchor.report
  join sectalk_private.st_forward_lineage origin on origin.id=anchor.root
  left join public.st_profiles profile on profile.id=origin.actor
  left join sectalk_private.st_message_advisories advisory on advisory.root=origin.id
  where anchor.report=p_report and auth.uid() not in (case_row.reporter,case_row.subject);
  return coalesce(result,jsonb_build_object('eligible',false));
end;
$$;

create function public.st_report_propagation_members(p_report uuid,p_offset integer default 0)
returns table(display_name text,handle text,shares bigint,original boolean)
language plpgsql stable security definer set search_path='' as $$
begin
  if not sectalk_private.st_can_review_report_lineage() then
    raise exception 'Verified moderator access is required' using errcode='42501';
  end if;
  return query
    with lineage as (
      select anchor.root from sectalk_private.st_report_lineage anchor
      join public.st_reports r on r.id=anchor.report
      where anchor.report=p_report and auth.uid() not in (r.reporter,r.subject)
    ), participants as (
      select f.actor,count(*) filter (where f.root_id is not null) as share_count,
        bool_or(f.root_id is null and f.original_known) as is_original
      from lineage l join sectalk_private.st_forward_lineage f on f.root_id=l.root or f.id=l.root
      where f.actor is not null and (f.root_id is not null or f.original_known)
      group by f.actor
    )
    select p.name,p.handle,f.share_count,f.is_original
    from participants f join public.st_profiles p on p.id=f.actor
    order by f.is_original desc,f.share_count desc,p.id
    limit 25 offset greatest(0,least(coalesce(p_offset,0),10000));
end;
$$;

create function public.st_set_report_advisory(p_report uuid,p_verdict text,p_category text,p_note text)
returns void language plpgsql security definer set search_path='' as $$
declare
  case_row public.st_reports;
  case_root uuid;
  owner_report uuid;
begin
  if not sectalk_private.st_can_review_report_lineage() then
    raise exception 'Verified moderator access is required' using errcode='42501';
  end if;
  perform sectalk_private.limit_action('report_advisory',20);
  if p_verdict is null or p_verdict not in ('warning','cleared','remove')
    or p_note is null or char_length(btrim(p_note)) not between 4 and 500
    or (p_verdict='warning' and (p_category is null or p_category not in
      ('spam','unwanted','fake','abuse','fraud','gambling','insecure_link','other')))
    or (p_verdict<>'warning' and p_category is not null) then
    raise exception 'Choose a verdict and enter a staff reason' using errcode='22023';
  end if;
  select * into case_row from public.st_reports r where r.id=p_report for update;
  if not found or auth.uid() in (case_row.reporter,case_row.subject) then
    raise exception 'Report unavailable' using errcode='42501';
  end if;
  if (p_verdict='warning' and case_row.status<>'resolved')
    or (p_verdict='cleared' and case_row.status<>'dismissed')
    or (p_verdict='remove' and case_row.status not in ('resolved','dismissed')) then
    raise exception 'The report needs a matching final decision' using errcode='PT409';
  end if;
  select anchor.root into case_root from sectalk_private.st_report_lineage anchor
    where anchor.report=p_report;
  if not found then raise exception 'No exact message revision was recorded' using errcode='PT409'; end if;
  -- Serialize competing cases for the same content without exposing the report to recipients.
  perform id from sectalk_private.st_forward_lineage where id=case_root for update;
  select a.report into owner_report from sectalk_private.st_message_advisories a where a.root=case_root;
  if owner_report is not null and owner_report<>p_report then
    raise exception 'Another case controls this advisory' using errcode='PT409';
  end if;
  if p_verdict='remove' then
    delete from sectalk_private.st_message_advisories where root=case_root;
  else
    insert into sectalk_private.st_message_advisories as a(root,report,verdict,category)
      values(case_root,p_report,p_verdict,p_category)
      on conflict(root) do update set verdict=excluded.verdict,category=excluded.category
      where (a.verdict,a.category) is distinct from (excluded.verdict,excluded.category);
  end if;
  if found then
    insert into sectalk_private.audit(actor,report_id,action,note)
      values(auth.uid(),p_report,'advisory_'||p_verdict,btrim(p_note));
  end if;
end;
$$;

create function public.st_direct_message_advisories(p_chat uuid,p_messages uuid[])
returns table(message_id uuid,verdict text,category text)
language sql stable security definer set search_path='' as $$
  with viewer as (
    select auth.uid() as id where cardinality(p_messages) between 1 and 100
      and sectalk_private.member(p_chat,auth.uid())
      and not public.st_v7_step_up_pending() and not public.st_v7_account_data_unavailable()
  )
  select m.id,coalesce(a.verdict,'reported'),a.category
  from viewer v
  join public.st_messages m on m.chat_id=p_chat and m.id=any(p_messages)
  join sectalk_private.st_forward_lineage n on n.kind='direct' and n.scope_id=p_chat
    and n.message_id=m.id and n.body_digest=extensions.digest(m.body,'sha256')
  left join sectalk_private.st_message_advisories a on a.root=coalesce(n.root_id,n.id)
  where m.revoked_at is null and (m.expires_at is null or m.expires_at>statement_timestamp())
    and not exists(select from public.st_v5_hidden_messages h where h.message_id=m.id and h.user_id=v.id)
    and (a.root is not null or exists(
      select from sectalk_private.st_report_lineage anchor
      join public.st_reports r on r.id=anchor.report
      where anchor.root=coalesce(n.root_id,n.id) and r.chat_id=p_chat and r.message_id=m.id
        and r.reporter=v.id and r.status in ('open','reviewing')
    ));
$$;

revoke all on function public.st_report_propagation(uuid), public.st_report_propagation_members(uuid,integer),
  public.st_set_report_advisory(uuid,text,text,text), public.st_direct_message_advisories(uuid,uuid[])
  from public,anon,authenticated,service_role;
grant execute on function public.st_report_propagation(uuid), public.st_report_propagation_members(uuid,integer),
  public.st_set_report_advisory(uuid,text,text,text), public.st_direct_message_advisories(uuid,uuid[])
  to authenticated;
notify pgrst,'reload schema';
commit;
