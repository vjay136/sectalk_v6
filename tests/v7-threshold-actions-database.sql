begin;

do $$
declare
  sender uuid:=gen_random_uuid();
  recipient uuid:=gen_random_uuid();
  staff uuid:=gen_random_uuid();
  factor uuid:=gen_random_uuid();
  sid uuid:=gen_random_uuid();
  chat uuid;
  message uuid:=gen_random_uuid();
  changed uuid:=gen_random_uuid();
  hidden uuid:=gen_random_uuid();
  timed uuid:=gen_random_uuid();
  revision timestamptz:=clock_timestamp();
  report uuid;
  plain uuid;
begin
  insert into auth.users(id,email) values
    (sender,'priority-sender@example.invalid'),(recipient,'priority-recipient@example.invalid'),(staff,'priority-reviewer@example.invalid');
  insert into public.st_profiles(id,handle,name) values
    (sender,'priority_fixture_sender','Test sender'),(recipient,'priority_fixture_peer','Test recipient'),(staff,'priority_fixture_staff','Test staff');
  insert into sectalk_private.staff(user_id) values(staff);
  insert into auth.mfa_factors(id,user_id,factor_type,status,created_at,updated_at) values(factor,staff,'totp','verified',now(),now());
  insert into auth.sessions(id,user_id,aal,factor_id) values(sid,staff,'aal2',factor);
  insert into public.st_chats(member_a,member_b,requester,status) values(least(sender,recipient),greatest(sender,recipient),sender,'accepted') returning id into chat;
  insert into public.st_messages(id,chat_id,sender,body,created_at,edited_at,expires_at) values
    (message,chat,sender,'Synthetic reportable message.',revision,null,null),
    (hidden,chat,sender,'Synthetic hidden message.',revision,null,null),
    (changed,chat,sender,'Synthetic changed message.',revision,revision+interval '1 second',null),
    (timed,chat,sender,'Synthetic disappearing message.',revision,null,revision+interval '60 seconds');

  insert into public.st_v5_hidden_messages(message_id,user_id) values(hidden,recipient);

  perform set_config('request.jwt.claims',jsonb_build_object('sub',sender,'aal','aal1')::text,true);
  set local role authenticated;
  begin
    perform public.st_v7_request_priority_message_review(chat,message,revision,'threat','');
    raise exception 'Sender prioritized own message';
  exception when insufficient_privilege then null; end;
  reset role;
  perform set_config('request.jwt.claims',jsonb_build_object('sub',recipient,'aal','aal1')::text,true);
  set local role authenticated;
  begin
    perform public.st_v7_request_priority_message_review(chat,changed,revision,'threat','');
    raise exception 'Out-of-date message could be prioritized';
  exception when insufficient_privilege then null; end;
  begin
    perform public.st_v7_request_priority_message_review(chat,timed,revision,'threat','');
    raise exception 'Timed message could be used as priority evidence';
  exception when insufficient_privilege then null; end;
  begin
    perform public.st_v7_request_priority_message_review(chat,message,revision,'scam','');
    raise exception 'An unrelated category was prioritized';
  exception when invalid_parameter_value then null; end;
  begin
    perform public.st_v7_request_priority_message_review(chat,hidden,revision,'threat','');
    raise exception 'Hidden message could be prioritized';
  exception when insufficient_privilege then null; end;
  plain:=public.st_v5_report(chat,changed,'threat','Ordinary report.',false);
  report:=public.st_v7_request_priority_message_review(chat,message,revision,'threat','Recipient requested review.');
  if report is null or public.st_v7_request_priority_message_review(chat,message,revision,'threat','Repeated') is distinct from report then
    raise exception 'Priority submission did not stay idempotent';
  end if;
  begin
    perform public.st_v7_priority_abuse_queue();
    raise exception 'Ordinary user accessed the priority queue';
  exception when insufficient_privilege then null; end;
  reset role;

  if not exists(select 1 from public.st_reports r where r.id=report and r.status='open' and r.requested_priority)
    or exists(select 1 from public.st_reports r where r.id=plain and r.requested_priority)
    or exists(select 1 from sectalk_private.suspensions where user_id=sender) then
    raise exception 'Priority was inferred automatically or changed account standing';
  end if;
  perform set_config('request.jwt.claims',jsonb_build_object('sub',staff,'aal','aal2','session_id',sid)::text,true);
  set local role authenticated;
  if not exists(select 1 from public.st_v7_priority_abuse_queue('threat') q where q.id=report and q.requested_priority and not (to_jsonb(q) ?| array['details','evidence','reporter']))
    or not exists(select 1 from public.st_v7_priority_abuse_queue('threat') q where q.id=plain and not q.requested_priority) then
    raise exception 'MFA queue lost priority or exposed private case content';
  end if;
  reset role;
end
$$;

select 'passed: deliberate priority with live recipient and revision checks, bounded duplicate, no automatic punishment, MFA-only queue' as result;
rollback;
