begin;

insert into auth.users(id,email,aud,role) values
 ('60000000-0000-4000-8000-000000000001','st-v6-alex@example.invalid','authenticated','authenticated'),
 ('60000000-0000-4000-8000-000000000002','st-v6-billie@example.invalid','authenticated','authenticated'),
 ('60000000-0000-4000-8000-000000000003','st-v6-casey@example.invalid','authenticated','authenticated');
insert into public.st_profiles(id,handle,name) values
 ('60000000-0000-4000-8000-000000000001','sectalk_v6_alex','Fixture Alex'),
 ('60000000-0000-4000-8000-000000000002','sectalk_v6_billie','Fixture Billie'),
 ('60000000-0000-4000-8000-000000000003','sectalk_v6_casey','Fixture Casey');

set local role anon;
select public.st_v6_ready() as anon_ready;
reset role;

set local role authenticated;
do $$
declare
  sender constant uuid:='60000000-0000-4000-8000-000000000001';
  receiver constant uuid:='60000000-0000-4000-8000-000000000002';
  outside_user constant uuid:='60000000-0000-4000-8000-000000000003';
  m constant uuid:=gen_random_uuid();
  m2 constant uuid:=gen_random_uuid();
  source constant uuid:=gen_random_uuid();
  reply constant uuid:=gen_random_uuid();
  chat uuid;
  target uuid;
begin
  perform set_config('request.jwt.claims',json_build_object('sub',sender,'role','authenticated')::text,true);
  chat:=public.st_request('sectalk_v6_billie');
  perform set_config('request.jwt.claims',json_build_object('sub',receiver,'role','authenticated')::text,true);
  perform public.st_respond(chat,true);
  perform set_config('request.jwt.claims',json_build_object('sub',sender,'role','authenticated')::text,true);
  perform public.st_send(chat,m,'First saved sample');
  perform public.st_send(chat,m2,'Second saved sample');
  perform public.st_v2_pin(chat,m);
  perform public.st_send(chat,source,repeat('x',240)||' [SecTalk-QA] <b>plain text</b>');
  perform public.st_v2_send_reply(chat,reply,'Quoted reply',m);
  if not exists(select 1 from public.st_v6_reply_quotes(chat,array[m]) q where q.id=m and q.sender=auth.uid() and q.body='First saved sample')
    then raise exception 'Visible quote was not returned'; end if;
  if not exists(select 1 from public.st_v6_search('[sectalk-qa]','direct') s
    where s.id=source and s.snippet like '…%[SecTalk-QA] <b>plain text</b>')
    then raise exception 'Search did not center the snippet around the matched term'; end if;
  insert into public.st_v6_saved_messages(message_id) values(m),(m2) on conflict(user_id,message_id) do nothing;
  insert into public.st_v6_saved_messages(message_id) values(m) on conflict(user_id,message_id) do nothing;
  if (select count(*) from public.st_v6_saved_messages)<>2 then raise exception 'Save failed or duplicated'; end if;
  insert into public.st_v6_saved_searches(query,kind) values('Saved sample','direct') on conflict(user_id,query,kind) do nothing;
  insert into public.st_v6_saved_searches(query,kind) values('Saved sample','direct') on conflict(user_id,query,kind) do nothing;
  if (select count(*) from public.st_v6_saved_searches)<>1 then raise exception 'Saved query duplicated'; end if;
  perform set_config('request.jwt.claims',json_build_object('sub',receiver,'role','authenticated')::text,true);
  if exists(select 1 from public.st_v6_saved_messages) then raise exception 'Another participant saw these bookmarks'; end if;
  if exists(select 1 from public.st_v6_saved_searches) then raise exception 'Another participant saw private search terms'; end if;
  insert into public.st_v6_saved_searches(query,kind) values('Saved sample','direct');
  delete from public.st_v6_saved_searches where query='Saved sample';
  insert into public.st_v6_saved_messages(message_id) values(m) on conflict(user_id,message_id) do nothing;
  delete from public.st_v6_saved_messages where message_id=m;
  if exists(select 1 from public.st_v6_saved_messages) then raise exception 'Remove saved message failed'; end if;
  perform set_config('request.jwt.claims',json_build_object('sub',outside_user,'role','authenticated')::text,true);
  if exists(select 1 from public.st_v6_search('[sectalk-qa]','direct')) then raise exception 'Search leaked a private snippet'; end if;
  if exists(select 1 from public.st_v6_reply_quotes(chat,array[m,m2])) then raise exception 'Quote API leaked a private message'; end if;
  begin
    perform public.st_v2_pin(chat,m);
    raise exception 'Outside account pinned a message' using errcode='P0004';
  exception when raise_exception then null; end;
  begin
    insert into public.st_v6_saved_messages(message_id) values(m);
    raise exception 'Outside account saved an inaccessible message' using errcode='P0004';
  exception when insufficient_privilege then null;
  end;
  perform set_config('request.jwt.claims',json_build_object('sub',sender,'role','authenticated')::text,true);
  if not exists(select 1 from public.st_v6_saved_searches where query='Saved sample') then raise exception 'Other account removed owner saved search'; end if;
  perform public.st_v5_message_action(m,'revoke');
  perform public.st_v5_message_action(m2,'hide');
  if exists(select 1 from public.st_v2_pins where chat_id=chat) then raise exception 'Revocation kept the pin'; end if;
  perform public.st_v2_send_reply(chat,reply,'Quoted reply',m);
  if exists(select 1 from public.st_v6_reply_quotes(chat,array[m,m2]))
    or not exists(select 1 from public.st_messages where id=reply and reply_to=m and body='Quoted reply')
    then raise exception 'Revocation or hiding leaked the quote or broke the reply'; end if;
  for target in select unnest(array[m,m2]) loop
    begin
      perform public.st_v2_pin(chat,target);
      raise exception 'Unavailable source was pinned' using errcode='P0004';
    exception when raise_exception then null; end;
    begin
      perform public.st_v2_send_reply(chat,gen_random_uuid(),'New reply to unavailable message',target);
      raise exception 'New reply was accepted for an unavailable source' using errcode='P0004';
    exception when raise_exception then null; end;
  end loop;
  if exists(select 1 from public.st_v6_search('saved sample','direct'))
    or exists(select 1 from public.st_v6_search('Message removed','direct') s where s.id=m)
    or exists(select 1 from public.st_v3_search('saved sample','direct'))
    then raise exception 'Hidden or revoked data appeared in an API search'; end if;
  if exists(select 1 from public.st_v6_saved_messages) then raise exception 'Hidden or revoked content remained visible'; end if;
  begin
    insert into public.st_v6_saved_messages(message_id) values(m);
    raise exception 'Revoked content could be saved again' using errcode='P0004';
  exception when insufficient_privilege then null;
  end;
  perform set_config('request.jwt.claims',json_build_object('sub',receiver,'role','authenticated')::text,true);
  if (select array_agg(s.id) from public.st_v6_search('saved sample','direct') s) is distinct from array[m2]
    then raise exception 'Search hide was not private to the acting account'; end if;
  perform public.st_v2_pin(chat,m2);
  perform public.st_v2_pin(chat,null);
  if exists(select 1 from public.st_v2_pins where chat_id=chat) then raise exception 'Contact failed to unpin'; end if;
end $$;
reset role;
select 'passed: private saves and searches, idempotent writes, removal, inaccessible chats, hide, revoke, readiness' as result;
rollback;
