begin;
insert into auth.users(id,email)
  select ('99200000-0000-4000-8000-'||lpad(n::text,12,'0'))::uuid,'feedback-'||n||'@example.invalid'
  from generate_series(1,7) n;
insert into public.st_profiles(id,name,handle)
  select ('99200000-0000-4000-8000-'||lpad(n::text,12,'0'))::uuid,'Feedback '||n,'feedback_'||n
  from generate_series(1,7) n;
insert into sectalk_private.staff(user_id) values('99200000-0000-4000-8000-000000000007');

do $$
declare
  sender constant uuid:='99200000-0000-4000-8000-000000000006';
  staff constant uuid:='99200000-0000-4000-8000-000000000007';
  account uuid;
  chat uuid;
  message uuid;
  revision timestamptz;
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
  perform set_config('request.jwt.claims',json_build_object('sub',staff,'role','authenticated','aal','aal2')::text,true);
  if (select count(*) from public.st_v6_risk_feedback_summary())<>1
    or not exists(select 1 from public.st_v6_risk_feedback_summary()
      where category='credential_harvesting' and accounts=5 and not reviewed)
  then raise exception 'Feedback privacy or group minimum is incorrect'; end if;
  perform public.st_v6_review_risk_feedback('credential_harvesting','message-rules-1');
  perform public.st_v6_review_risk_feedback('credential_harvesting','message-rules-1');
  if not exists(select 1 from public.st_v6_risk_feedback_summary() where reviewed)
  then raise exception 'Review did not persist'; end if;

  reset role;
  if has_table_privilege('authenticated','sectalk_private.st_v6_risk_feedback','SELECT') then
    raise exception 'Raw feedback was granted to authenticated accounts';
  end if;
  if (select count(*) from sectalk_private.st_v6_risk_feedback where rule_version='message-rules-1'
    and recipient::text like '99200000-%')<>6
    then raise exception 'Feedback replay created duplicate records'; end if;
end $$;

select 'passed: content-free feedback, access, replay, MFA, suppression, and review' as result;
rollback;
