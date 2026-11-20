begin;

create table sectalk_private.st_v6_warning_proposals (
  id uuid primary key default gen_random_uuid(),
  feedback_month date not null,
  category text not null,
  rule_version text not null,
  cohort_size bigint not null check(cohort_size>=5 and cohort_size%5=0),
  kind text not null check(kind in ('rule_review','threshold_review')),
  minimum_confidence integer,
  status text not null default 'pending' check(status in ('pending','approved','declined')),
  submitted_by uuid not null,
  submitted_at timestamptz not null default clock_timestamp(),
  reviewed_by uuid,
  reviewed_at timestamptz,
  unique(feedback_month,category,rule_version),
  check((kind='rule_review' and minimum_confidence is null) or
    (kind='threshold_review' and minimum_confidence is not null and minimum_confidence between 60 and 95)),
  check((status='pending' and reviewed_by is null and reviewed_at is null) or
    (status<>'pending' and reviewed_by is not null and reviewed_at is not null and submitted_by<>reviewed_by))
);
alter table sectalk_private.st_v6_warning_proposals enable row level security;
revoke all on sectalk_private.st_v6_warning_proposals from public,anon,authenticated,service_role;
create index st_v6_warning_proposals_recent on sectalk_private.st_v6_warning_proposals(submitted_at desc,id);

create function sectalk_private.st_v6_require_warning_reviewer()
returns void language plpgsql stable set search_path='' as $$
begin
  if public.st_staff_status()<>'verified' or not sectalk_private.st_v2_active(auth.uid()) then
    raise exception 'Active staff MFA required' using errcode='42501';
  end if;
end
$$;

create function sectalk_private.st_v6_warning_proposals()
returns table(id uuid,feedback_month date,category text,rule_version text,cohort_size bigint,
  kind text,minimum_confidence integer,status text,can_review boolean)
language plpgsql stable security definer set search_path='' as $$
begin
  perform sectalk_private.st_v6_require_warning_reviewer();
  return query
    select p.id,p.feedback_month,p.category,p.rule_version,p.cohort_size,p.kind,p.minimum_confidence,p.status,
      p.status='pending' and p.submitted_by<>auth.uid()
    from sectalk_private.st_v6_warning_proposals p
    order by p.submitted_at desc,p.id limit 100;
end
$$;

create function sectalk_private.st_v6_propose_warning_change(
  p_category text,p_rule_version text,p_kind text,p_minimum_confidence integer
)
returns uuid language plpgsql security definer set search_path='' as $$
declare period date:=date_trunc('month',now() at time zone 'UTC')::date;
declare eligible_accounts bigint;
declare proposal uuid;
begin
  perform sectalk_private.st_v6_require_warning_reviewer();
  if p_kind is null or p_kind not in ('rule_review','threshold_review')
    or (p_kind='rule_review' and p_minimum_confidence is not null)
    or (p_kind='threshold_review' and (p_minimum_confidence is null or p_minimum_confidence not between 60 and 95))
  then raise exception 'Choose a valid warning proposal'; end if;
  select s.accounts into eligible_accounts from sectalk_private.st_v6_risk_feedback_summary() s
    where s.category=p_category and s.rule_version=p_rule_version;
  if eligible_accounts is null then raise exception 'Feedback cohort unavailable'; end if;
  perform sectalk_private.limit_action('v6_warning_proposal',15);

  insert into sectalk_private.st_v6_warning_proposals(
    feedback_month,category,rule_version,cohort_size,kind,minimum_confidence,submitted_by
  ) values(period,p_category,p_rule_version,eligible_accounts,p_kind,p_minimum_confidence,auth.uid())
  on conflict(feedback_month,category,rule_version) do nothing returning id into proposal;
  if found then return proposal; end if;

  select p.id into proposal from sectalk_private.st_v6_warning_proposals p
    where p.feedback_month=period and p.category=p_category and p.rule_version=p_rule_version
      and p.submitted_by=auth.uid() and p.kind=p_kind
      and p.minimum_confidence is not distinct from p_minimum_confidence;
  if proposal is null then raise exception 'A proposal already exists for this cohort'; end if;
  return proposal;
end
$$;

create function sectalk_private.st_v6_review_warning_change(p_id uuid,p_status text)
returns void language plpgsql security definer set search_path='' as $$
begin
  perform sectalk_private.st_v6_require_warning_reviewer();
  if p_status is null or p_status not in ('approved','declined') then raise exception 'Choose a review decision'; end if;
  perform sectalk_private.limit_action('v6_warning_proposal_review',20);
  update sectalk_private.st_v6_warning_proposals
  set status=p_status,reviewed_by=auth.uid(),reviewed_at=clock_timestamp()
  where id=p_id and status='pending' and submitted_by<>auth.uid();
  if not found and not exists(select 1 from sectalk_private.st_v6_warning_proposals
    where id=p_id and status=p_status and reviewed_by=auth.uid())
  then raise exception 'Proposal requires a different reviewer and an open decision'; end if;
end
$$;

create function public.st_v6_warning_proposals()
returns table(id uuid,feedback_month date,category text,rule_version text,cohort_size bigint,
  kind text,minimum_confidence integer,status text,can_review boolean)
language sql stable set search_path='' begin atomic
  select * from sectalk_private.st_v6_warning_proposals();
end;

create function public.st_v6_propose_warning_change(
  p_category text,p_rule_version text,p_kind text,p_minimum_confidence integer
)
returns uuid language sql set search_path=''
return sectalk_private.st_v6_propose_warning_change(p_category,p_rule_version,p_kind,p_minimum_confidence);

create function public.st_v6_review_warning_change(p_id uuid,p_status text)
returns void language sql set search_path=''
return sectalk_private.st_v6_review_warning_change(p_id,p_status);

revoke all on function sectalk_private.st_v6_require_warning_reviewer(),
  sectalk_private.st_v6_warning_proposals(),sectalk_private.st_v6_propose_warning_change(text,text,text,integer),
  sectalk_private.st_v6_review_warning_change(uuid,text),public.st_v6_warning_proposals(),
  public.st_v6_propose_warning_change(text,text,text,integer),public.st_v6_review_warning_change(uuid,text)
  from public,anon,authenticated,service_role;
grant execute on function sectalk_private.st_v6_warning_proposals(),
  sectalk_private.st_v6_propose_warning_change(text,text,text,integer),sectalk_private.st_v6_review_warning_change(uuid,text),
  public.st_v6_warning_proposals(),public.st_v6_propose_warning_change(text,text,text,integer),
  public.st_v6_review_warning_change(uuid,text)
  to authenticated;

commit;
