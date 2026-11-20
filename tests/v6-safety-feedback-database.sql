begin;
-- Keep exact cohort thresholds independent of prior browser fixtures in the
-- disposable database. This entire fixture rolls back.
delete from sectalk_private.st_v6_warning_proposals
  where rule_version='message-rules-1' and category in ('credential_harvesting','spam')
    and feedback_month=date_trunc('month',now() at time zone 'UTC')::date;
delete from sectalk_private.st_v6_risk_feedback_review
  where rule_version='message-rules-1' and category in ('credential_harvesting','spam')
    and review_month=date_trunc('month',now() at time zone 'UTC')::date;
delete from sectalk_private.st_v6_risk_feedback
  where rule_version='message-rules-1' and category in ('credential_harvesting','spam')
    and submitted_at>=date_trunc('month',now() at time zone 'UTC') at time zone 'UTC';
insert into auth.users(id,email)
  select ('99200000-0000-4000-8000-'||lpad(n::text,12,'0'))::uuid,'feedback-'||n||'@example.invalid'
  from generate_series(1,8) n;
insert into public.st_profiles(id,name,handle)
  select ('99200000-0000-4000-8000-'||lpad(n::text,12,'0'))::uuid,'Feedback '||n,'feedback_'||n
  from generate_series(1,8) n;
insert into sectalk_private.staff(user_id) values
  ('99200000-0000-4000-8000-000000000007'),('99200000-0000-4000-8000-000000000008');

do $$
declare
  sender constant uuid:='99200000-0000-4000-8000-000000000006';
  staff constant uuid:='99200000-0000-4000-8000-000000000007';
  reviewer constant uuid:='99200000-0000-4000-8000-000000000008';
  account uuid;
  chat uuid;
  message uuid;
  revision timestamptz;
  proposal uuid;
  included text[]:=array['credential_harvesting','credential_harvesting'];
begin
  set local role authenticated;
  for n in 1..5 loop
    account:=('99200000-0000-4000-8000-'||lpad(n::text,12,'0'))::uuid;
    perform set_config('request.jwt.claims',json_build_object('sub',sender,'role','authenticated')::text,true);
    chat:=public.st_request('feedback_'||n);
    perform set_config('request.jwt.claims',json_build_object('sub',account,'role','authenticated')::text,true);
    perform public.st_respond(chat,true);
    perform set_config('request.jwt.claims',json_build_object('sub',sender,'role','authenticated')::text,true);
    message:=gen_random_uuid();
    perform public.st_send(chat,message,'Share an account code for this fixture');
    select m.created_at into revision from public.st_messages m where m.id=message;
    if n=1 then
      begin
        perform public.st_v6_submit_risk_feedback(message,revision,included);
        raise exception 'Sender submitted feedback on own message' using errcode='P0100';
      exception when raise_exception then null; end;
      perform set_config('request.jwt.claims',json_build_object('sub',staff,'role','authenticated','aal','aal2')::text,true);
      begin
        perform public.st_v6_submit_risk_feedback(message,revision,included);
        raise exception 'Unrelated staff submitted recipient feedback' using errcode='P0100';
      exception when raise_exception then null; end;
    end if;
    perform set_config('request.jwt.claims',json_build_object('sub',account,'role','authenticated')::text,true);
    begin
      perform public.st_v6_submit_risk_feedback(message,revision-interval '1 second',included);
      raise exception 'Feedback accepted stale content' using errcode='P0100';
    exception when raise_exception then null; end;
    perform public.st_v6_submit_risk_feedback(message,revision,included);
    perform public.st_v6_submit_risk_feedback(message,revision,included);
    if n=1 then
      perform public.st_v6_submit_risk_feedback(message,revision,array['spam']);
      perform public.st_v5_message_action(message,'hide');
      begin
        perform public.st_v6_submit_risk_feedback(message,revision,included);
        raise exception 'Hidden message accepted feedback' using errcode='P0100';
      exception when raise_exception then null; end;
    end if;
  end loop;

  begin
    perform * from public.st_v6_risk_feedback_summary();
    raise exception 'Ordinary account read the cohorts' using errcode='P0100';
  exception when raise_exception then null; end;
  perform set_config('request.jwt.claims',json_build_object('sub',staff,'role','authenticated','aal','aal1')::text,true);
  begin
    perform * from public.st_v6_risk_feedback_summary();
    raise exception 'Staff feedback review skipped MFA' using errcode='P0100';
  exception when raise_exception then null; end;
  begin
    perform * from public.st_v6_warning_proposals();
    raise exception 'AAL1 staff read warning proposals';
  exception when insufficient_privilege then null; end;
  perform set_config('request.jwt.claims',json_build_object('sub',staff,'role','authenticated','aal','aal2')::text,true);
  if (select count(*) from public.st_v6_risk_feedback_summary() where category in ('spam','credential_harvesting'))<>1
    or not exists(select 1 from public.st_v6_risk_feedback_summary()
      where category='credential_harvesting' and accounts=5 and not reviewed)
  then raise exception 'Feedback privacy or group minimum is incorrect'; end if;
  perform public.st_v6_review_risk_feedback('credential_harvesting','message-rules-1');
  perform public.st_v6_review_risk_feedback('credential_harvesting','message-rules-1');
  if not exists(select 1 from public.st_v6_risk_feedback_summary() where reviewed)
  then raise exception 'Review did not persist'; end if;

  begin
    perform public.st_v6_propose_warning_change('spam','message-rules-1','rule_review',null);
    raise exception 'A cohort below the minimum was used' using errcode='P0100';
  exception when raise_exception then null; end;
  begin
    perform public.st_v6_propose_warning_change('credential_harvesting','message-rules-1','threshold_review',20);
    raise exception 'Proposed threshold outside allowed bounds' using errcode='P0100';
  exception when raise_exception then null; end;
  proposal:=public.st_v6_propose_warning_change('credential_harvesting','message-rules-1','threshold_review',75);
  if proposal is distinct from public.st_v6_propose_warning_change('credential_harvesting','message-rules-1','threshold_review',75)
    or not exists(select 1 from public.st_v6_warning_proposals() p where p.id=proposal and not p.can_review
      and p.cohort_size=5 and p.status='pending')
  then raise exception 'Proposal replay, aggregate projection, or separation failed'; end if;
  begin
    perform public.st_v6_review_warning_change(proposal,'approved');
    raise exception 'A proposer approved their own proposal' using errcode='P0100';
  exception when raise_exception then null; end;
  perform set_config('request.jwt.claims',json_build_object('sub',reviewer,'role','authenticated','aal','aal2')::text,true);
  if not exists(select 1 from public.st_v6_warning_proposals() p where p.id=proposal and p.can_review)
  then raise exception 'Second reviewer could not see the pending action'; end if;
  perform public.st_v6_review_warning_change(proposal,'approved');
  perform public.st_v6_review_warning_change(proposal,'approved');
  begin
    perform public.st_v6_review_warning_change(proposal,'declined');
    raise exception 'A finalized decision was reclassified' using errcode='P0100';
  exception when raise_exception then null; end;
  if not exists(select 1 from public.st_v6_warning_proposals() p where p.id=proposal and not p.can_review
    and p.status='approved' and p.minimum_confidence=75)
  then raise exception 'Approval did not persist'; end if;

  reset role;
  if has_table_privilege('authenticated','sectalk_private.st_v6_risk_feedback','SELECT') then
    raise exception 'Raw feedback was granted to authenticated accounts';
  end if;
  if (select count(*) from sectalk_private.st_v6_risk_feedback where rule_version='message-rules-1'
    and recipient::text like '99200000-%')<>6
    then raise exception 'Feedback replay created duplicate records'; end if;
end $$;

select 'passed: content-free feedback, cohort suppression, MFA, bounded proposals, and independent review' as result;
rollback;
