begin;

create table sectalk_private.st_v6_risk_feedback (
  recipient uuid not null references public.st_profiles on delete cascade,
  message_id uuid not null references public.st_messages on delete cascade,
  revision timestamptz not null,
  rule_version text not null,
  category text not null,
  submitted_at timestamptz not null default clock_timestamp(),
  primary key(recipient,message_id,revision,rule_version,category)
);
create index st_v6_risk_feedback_message on sectalk_private.st_v6_risk_feedback(message_id);
create index st_v6_risk_feedback_period on sectalk_private.st_v6_risk_feedback(submitted_at);
create table sectalk_private.st_v6_risk_feedback_review (
  review_month date not null,
  rule_version text not null,
  category text not null,
  reviewed_by uuid references public.st_profiles on delete set null,
  reviewed_at timestamptz not null default clock_timestamp(),
  primary key(review_month,rule_version,category)
);
alter table sectalk_private.st_v6_risk_feedback enable row level security;
alter table sectalk_private.st_v6_risk_feedback_review enable row level security;
revoke all on sectalk_private.st_v6_risk_feedback,sectalk_private.st_v6_risk_feedback_review
  from public,anon,authenticated,service_role;

create function sectalk_private.st_v6_submit_risk_feedback(
  p_message uuid,p_revision timestamptz,p_categories text[]
)
returns void language plpgsql security definer set search_path='' as $$
declare actor uuid:=auth.uid();
begin
  if actor is null or not sectalk_private.st_v2_active(actor)
    or array_ndims(p_categories) is distinct from 1 or cardinality(p_categories) not between 1 and 7
    or array_position(p_categories,null) is not null or not p_categories<@array[
      'credential_harvesting','payment_fraud','harassment','threat','sexual_coercion','spam','suspicious_link'
    ]::text[]
    or not exists(
      select 1 from public.st_messages m where m.id=p_message and m.sender<>actor and m.revoked_at is null
        and p_revision=coalesce(m.edited_at,m.created_at) and sectalk_private.st_v2_chat_write(m.chat_id,actor)
        and not exists(
          select 1 from public.st_v5_hidden_messages h where h.user_id=actor and h.message_id=m.id
        )
    ) then raise exception 'Feedback unavailable'; end if;

  perform sectalk_private.limit_action('v6_risk_feedback',12);
  insert into sectalk_private.st_v6_risk_feedback(recipient,message_id,revision,rule_version,category)
    select actor,p_message,p_revision,'message-rules-1',category from unnest(p_categories) category
    on conflict do nothing;
end
$$;

create function sectalk_private.st_v6_risk_feedback_summary()
returns table(category text,rule_version text,accounts bigint,reviewed boolean)
language plpgsql stable security definer set search_path='' as $$
declare period date:=date_trunc('month',now() at time zone 'UTC')::date;
begin
  if public.st_staff_status()<>'verified' then raise exception 'Staff MFA required'; end if;
  return query
    select f.category,f.rule_version,(count(distinct f.recipient)/5)*5,r.review_month is not null
    from sectalk_private.st_v6_risk_feedback f
    left join sectalk_private.st_v6_risk_feedback_review r
      on r.review_month=period and r.rule_version=f.rule_version and r.category=f.category
    where f.submitted_at>=period::timestamp at time zone 'UTC'
    group by f.category,f.rule_version,r.review_month
    having count(distinct f.recipient)>=5
    order by count(distinct f.recipient) desc,f.category;
end
$$;

create function sectalk_private.st_v6_review_risk_feedback(p_category text,p_rule_version text)
returns void language plpgsql security definer set search_path='' as $$
begin
  if not exists(select 1 from sectalk_private.st_v6_risk_feedback_summary() s
    where s.category=p_category and s.rule_version=p_rule_version)
  then raise exception 'Feedback cohort unavailable'; end if;
  perform sectalk_private.limit_action('v6_risk_feedback_review',20);
  insert into sectalk_private.st_v6_risk_feedback_review(review_month,rule_version,category,reviewed_by)
    values(date_trunc('month',now() at time zone 'UTC')::date,p_rule_version,p_category,auth.uid())
    on conflict do nothing;
end
$$;

create function public.st_v6_submit_risk_feedback(p_message uuid,p_revision timestamptz,p_categories text[])
returns void language sql set search_path=''
return sectalk_private.st_v6_submit_risk_feedback(p_message,p_revision,p_categories);

create function public.st_v6_risk_feedback_summary()
returns table(category text,rule_version text,accounts bigint,reviewed boolean)
language sql stable set search_path='' begin atomic
  select * from sectalk_private.st_v6_risk_feedback_summary();
end;

create function public.st_v6_review_risk_feedback(p_category text,p_rule_version text)
returns void language sql set search_path=''
return sectalk_private.st_v6_review_risk_feedback(p_category,p_rule_version);

revoke all on function public.st_v6_submit_risk_feedback(uuid,timestamptz,text[]),
  public.st_v6_risk_feedback_summary(), public.st_v6_review_risk_feedback(text,text),
  sectalk_private.st_v6_submit_risk_feedback(uuid,timestamptz,text[]),
  sectalk_private.st_v6_risk_feedback_summary(), sectalk_private.st_v6_review_risk_feedback(text,text)
  from public,anon,authenticated,service_role;
grant execute on function public.st_v6_submit_risk_feedback(uuid,timestamptz,text[]),
  public.st_v6_risk_feedback_summary(), public.st_v6_review_risk_feedback(text,text),
  sectalk_private.st_v6_submit_risk_feedback(uuid,timestamptz,text[]),
  sectalk_private.st_v6_risk_feedback_summary(), sectalk_private.st_v6_review_risk_feedback(text,text)
  to authenticated;

commit;
