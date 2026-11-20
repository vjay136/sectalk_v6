\set ON_ERROR_STOP on
begin;

insert into auth.users(id,email)
select format('6a000003-0000-4000-8000-%s',lpad(n::text,12,'0'))::uuid,
  format('threat-trends-%s@example.invalid',n) from generate_series(1,13) n;
insert into public.st_profiles(id,handle,name)
select id,'threattrends_'||split_part(split_part(email,'@',1),'-',3),'Threat trend fixture'
  from auth.users where email like 'threat-trends-%@example.invalid';
insert into sectalk_private.staff(user_id) values('6a000003-0000-4000-8000-000000000001');

insert into public.st_chats(id,member_a,member_b,requester,status)
select format('6a000003-0001-4000-8000-%s',lpad(n::text,12,'0'))::uuid,
  format('6a000003-0000-4000-8000-%s',lpad(n::text,12,'0'))::uuid,
  format('6a000003-0000-4000-8000-%s',lpad((n+6)::text,12,'0'))::uuid,
  format('6a000003-0000-4000-8000-%s',lpad(n::text,12,'0'))::uuid,
  'accepted' from generate_series(2,7) n;

with groups(weeks_ago,copies) as (values (0,1),(5,1),(6,1),(7,2),(9,1))
insert into public.st_reports(reporter,subject,chat_id,category,details,evidence,status,created_at)
select c.member_a,c.member_b,c.id,'sexual_content','Private report notes','Private attached excerpt','resolved',
  date_trunc('week',now(),'UTC')-make_interval(weeks=>g.weeks_ago)+make_interval(secs=>copy)
from groups g cross join lateral generate_series(1,g.copies) copy cross join public.st_chats c
where c.id::text like '6a000003-0001-%'
  and (g.weeks_ago<>5 or c.id='6a000003-0001-4000-8000-000000000002');

-- Twice-enforced reports still count only once. A resolved report or restoration alone contributes no enforcement.
insert into sectalk_private.audit(actor,report_id,action,note,created_at)
select '6a000003-0000-4000-8000-000000000001',r.id,s.action,'Private moderation reason',r.created_at+interval '1 day'
from public.st_reports r cross join (values ('warn'),('suspend'),('resolved'),('restore')) s(action)
where r.chat_id::text like '6a000003-0001-%' and r.created_at<date_trunc('week',now(),'UTC')
  and (s.action in ('resolved','restore') or (
    extract(second from r.created_at)=1
    and (r.created_at>=date_trunc('week',now(),'UTC')-interval '5 weeks'
      or r.created_at<date_trunc('week',now(),'UTC')-interval '6 weeks')
    and r.chat_id<>'6a000003-0001-4000-8000-000000000007'));

set local role authenticated;
do $$
declare
  staffer constant uuid := '6a000003-0000-4000-8000-000000000001';
  reporter_id constant uuid := '6a000003-0000-4000-8000-000000000002';
  cutoff date := date_trunc('week',now() at time zone 'UTC')::date;
  sample jsonb;
begin
  if has_function_privilege('anon','public.st_v6_threat_trends(text)','execute') then
    raise exception 'Anonymous users may call the threat trends function';
  end if;
  perform set_config('request.jwt.claims',jsonb_build_object('sub',reporter_id,'aal','aal2')::text,true);
  begin
    perform public.st_v6_threat_trends('sexual_content');
    raise exception 'Ordinary reporter could read global trends';
  exception when insufficient_privilege then null; end;
  perform set_config('request.jwt.claims',jsonb_build_object('sub',staffer,'aal','aal1')::text,true);
  begin
    perform public.st_v6_threat_trends('sexual_content');
    raise exception 'Staff could fetch trends without MFA';
  exception when insufficient_privilege then null; end;
  perform set_config('request.jwt.claims',jsonb_build_object('sub',staffer,'aal','aal2')::text,true);
  begin
    perform public.st_v6_threat_trends('invalid');
    raise exception 'The trends RPC accepted an arbitrary category';
  exception when invalid_parameter_value then null; end;

  if (select count(*) from public.st_v6_threat_trends('sexual_content'))<>8
    or exists(select 1 from public.st_v6_threat_trends('sexual_content') t
      where t.week_start>=cutoff or t.week_start<cutoff-56)
  then raise exception 'Fixed eight-week bounds were not enforced'; end if;

  select to_jsonb(t)-'week_start' into sample
    from public.st_v6_threat_trends('sexual_content') t where t.week_start=cutoff-49;
  if sample is distinct from '{"reports":10,"actioned":5}'::jsonb then
    raise exception 'Expected rounded report counts and deduplicated staff enforcement';
  end if;
  select to_jsonb(t)-'week_start' into sample
    from public.st_v6_threat_trends('sexual_content') t where t.week_start=cutoff-42;
  if sample is distinct from '{"reports":5,"actioned":null}'::jsonb then
    raise exception 'Resolved or restored reports incorrectly counted as staff enforcement';
  end if;
  select to_jsonb(t)-'week_start' into sample
    from public.st_v6_threat_trends('sexual_content') t where t.week_start=cutoff-35;
  if sample is distinct from '{"reports":null,"actioned":null}'::jsonb then
    raise exception 'The endpoint disclosed a below-threshold cohort';
  end if;
end
$$;
reset role;

insert into sectalk_private.suspensions(user_id,until_at)
  values('6a000003-0000-4000-8000-000000000001',now()+interval '1 day');
set local role authenticated;
do $$
begin
  perform public.st_v6_threat_trends('sexual_content');
  raise exception 'Suspended staff could fetch threat trends';
exception when insufficient_privilege then null;
end
$$;
reset role;

select 'passed: eight weekly cohorts, rounded and suppressed trends, deduplicated enforcement and staff-only MFA' as result;
rollback;
