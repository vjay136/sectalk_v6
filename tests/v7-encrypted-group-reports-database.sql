begin;

insert into auth.users(id,email)
select ('5e260000-0000-4000-8000-'||lpad(n::text,12,'0'))::uuid,'group-report-'||n||'@example.invalid'
from generate_series(1,3) n;
insert into public.st_profiles(id,handle,name)
select ('5e260000-0000-4000-8000-'||lpad(n::text,12,'0'))::uuid,'group_report_'||n,'Group report fixture'
from generate_series(1,3) n;
insert into auth.sessions(id,user_id,aal)
select ('5e260001-0000-4000-8000-'||lpad(n::text,12,'0'))::uuid,
  ('5e260000-0000-4000-8000-'||lpad(n::text,12,'0'))::uuid,'aal1'
from generate_series(1,3) n;
insert into auth.mfa_amr_claims(id,session_id,authentication_method,created_at,updated_at)
select gen_random_uuid(),('5e260001-0000-4000-8000-'||lpad(n::text,12,'0'))::uuid,'password',now(),now()
from generate_series(1,3) n;
insert into public.st_chats(id,member_a,member_b,requester,status)
values (gen_random_uuid(),'5e260000-0000-4000-8000-000000000001','5e260000-0000-4000-8000-000000000002',
  '5e260000-0000-4000-8000-000000000001','accepted');
insert into sectalk_private.st_v7_devices(id,owner,state,signing_key,agreement_key,bundle_signature)
select ('5e260002-0000-4000-8000-'||lpad(n::text,12,'0'))::uuid,
  ('5e260000-0000-4000-8000-'||lpad(n::text,12,'0'))::uuid,
  case when n=2 then 'managed' else 'trusted' end,
  repeat(chr(65+n),87),repeat(chr(75+n),87),repeat(chr(85+n),86)
from generate_series(1,3) n;
insert into sectalk_private.st_v7_device_sessions(session_id,owner,device_id)
select ('5e260001-0000-4000-8000-'||lpad(n::text,12,'0'))::uuid,
  ('5e260000-0000-4000-8000-'||lpad(n::text,12,'0'))::uuid,
  ('5e260002-0000-4000-8000-'||lpad(n::text,12,'0'))::uuid
from generate_series(1,3) n;


do $$
declare
  author constant uuid:='5e260000-0000-4000-8000-000000000001';
  peer constant uuid:='5e260000-0000-4000-8000-000000000002';
  reviewer constant uuid:='5e260000-0000-4000-8000-000000000003';
  peer_device constant uuid:='5e260002-0000-4000-8000-000000000002';
  peer_claims constant text:=jsonb_build_object('sub',peer,'session_id','5e260001-0000-4000-8000-000000000002','aal','aal1')::text;
  g constant uuid:=gen_random_uuid();
  other_group constant uuid:=gen_random_uuid();
  first_msg constant uuid:=gen_random_uuid();
  second_msg constant uuid:=gen_random_uuid();
  direct uuid;
  meta uuid;
  shared uuid;
  review jsonb;
  expected constant text:='Synthetic text explicitly disclosed by reporter.';
begin
  if has_function_privilege('anon','public.st_report_group_message(uuid,uuid,text,boolean,text)','execute')
     or has_table_privilege('authenticated','public.st_reports','insert') then
    raise exception 'Non-reporting paths can write evidence';
  end if;
  insert into sectalk_private.st_group_chats(id,owner,name,epoch,member_cap)
    values(g,author,'Report fixture',1,4),(other_group,author,'Different fixture',1,4);
  insert into sectalk_private.st_group_members(group_id,actor) values(g,author),(g,peer);
  insert into sectalk_private.st_group_envelopes(group_id,epoch,device,sealed,ephemeral)
    values(g,1,peer_device,repeat('A',80),repeat('B',87));
  insert into sectalk_private.st_group_messages(group_id,id,epoch,actor,device,signing,payload,signature)
    select g,m,1,author,'5e260002-0000-4000-8000-000000000001',repeat('K',87),repeat('T',48),repeat('P',86)
    from unnest(array[first_msg,second_msg]) m;

  perform set_config('request.jwt.claims',peer_claims,true);
  begin
    perform public.st_report_group_message(g,first_msg,'scam',false,expected);
    raise exception 'Evidence accepted without affirmative choice';
  exception when invalid_parameter_value then null; end;
  begin
    perform public.st_report_group_message(other_group,first_msg,'scam',true,expected);
    raise exception 'Cross-group disclosure accepted';
  exception when insufficient_privilege then null; end;
  direct:=public.st_v5_report((select id from public.st_chats where (member_a,member_b)=(author,peer)),
    null,'other','Existing direct reporting still works.',false);
  if direct is null or not exists(select 1 from public.st_reports where id=direct
    and chat_id is not null and group_chat_id is null) then raise exception 'Direct reporting changed'; end if;
  meta:=public.st_report_group_message(g,first_msg,'scam',false);
  shared:=public.st_report_group_message(g,second_msg,'scam',true,expected);
  if meta is null or shared is null or shared=meta then raise exception 'Reports did not enter Safety'; end if;
  if public.st_report_group_message(g,first_msg,'scam',true,expected)<>meta
    or exists(select 1 from public.st_reports where id=meta and evidence is not null) then
    raise exception 'A retry overwrote an earlier report without evidence';
  end if;

  perform set_config('request.jwt.claims',jsonb_build_object('sub',reviewer,
    'session_id','5e260001-0000-4000-8000-000000000003','aal','aal1')::text,true);
  begin
    perform public.st_report_group_message(g,first_msg,'scam',false);
    raise exception 'Outsider report accepted';
  exception when insufficient_privilege then null; end;
  insert into sectalk_private.staff(user_id) values(reviewer);
  begin
    perform public.st_v5_case(shared);
    raise exception 'Evidence accessed without staff MFA' using errcode='99999';
  exception when raise_exception then null; end;

  perform set_config('request.jwt.claims',jsonb_build_object('sub',reviewer,
    'session_id','5e260001-0000-4000-8000-000000000003','aal','aal2')::text,true);
  review:=public.st_v5_case(shared);
  if (review->>'evidence') is distinct from expected or review->>'details' not like '%cannot be verified%'
    or (public.st_v5_case(meta)->'evidence') is distinct from 'null'::jsonb then
    raise exception 'Existing Safety case lost the shared text, disclosure limit, or unverified provenance';
  end if;
  delete from sectalk_private.st_group_members where group_id=g and actor=peer;
  perform set_config('request.jwt.claims',peer_claims,true);
  begin
    perform public.st_report_group_message(g,second_msg,'scam',true,expected);
    raise exception 'Removed member submitted a report';
  exception when insufficient_privilege then null; end;
end $$;

select 'passed: group-side authorization, opt-in evidence only, existing MFA Safety review and cross-group denial' as result;
rollback;
