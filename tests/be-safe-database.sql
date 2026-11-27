begin;

do $$
declare
  caller uuid := gen_random_uuid();
  subject uuid := gen_random_uuid();
  other_operator uuid := gen_random_uuid();
  session_id uuid := gen_random_uuid();
  handle text := 'safety_'||left(subject::text,8);
  blocked text := 'https://be-safe-fixture.example/known';
  block_response uuid;
  chat uuid;
  message uuid := gen_random_uuid();
  result jsonb;
begin
  if has_function_privilege('anon','public.st_be_safe_lookup(text,text[],text)','EXECUTE')
    or not has_function_privilege('authenticated','public.st_be_safe_lookup(text,text[],text)','EXECUTE') then
    raise exception 'Unexpected Be Safe API access';
  end if;
  insert into auth.users(id,email) values(caller,caller||'@example.invalid'),(subject,subject||'@example.invalid');
  insert into auth.sessions(id,user_id,aal) values(session_id,caller,'aal1');
  insert into public.st_profiles(id,handle,name) values
    (caller,'safety_'||left(caller::text,8),'Lookup participant'),(subject,handle,'Lookup subject');
  insert into sectalk_private.suspensions(user_id,until_at) values(subject,now()+interval '1 day');
  insert into sectalk_private.st_v7_soc_responses(action,domain,requester,reason,decider,decision,decision_reason,decided_at)
    values('block_url',blocked,caller,'Synthetic safety check',other_operator,'executed','Synthetic approval',now())
    returning id into block_response;
  insert into sectalk_private.st_v7_soc_url_blocks(url_key,response,expires_at) values(blocked,block_response,now()+interval '1 day');

  set local role authenticated;
  perform set_config('request.jwt.claims',jsonb_build_object('sub',caller,'role','authenticated','session_id',session_id,'aal','aal1')::text,true);
  result := public.st_be_safe_lookup(null,array[blocked||'?secret=fixture#text','https://be-safe-fixture.example/other'],handle);
  if result is distinct from jsonb_build_object('restricted',false,'categories','[]'::jsonb,'links',jsonb_build_array(
      jsonb_build_object('address',blocked,'restricted',true),
      jsonb_build_object('address','https://be-safe-fixture.example/other','restricted',false))) then
    raise exception 'URL matching disclosed input or account lookup disclosed a private profile: %', result;
  end if;
  reset role;

  insert into public.st_chats(member_a,member_b,requester,status)
    values(least(caller,subject),greatest(caller,subject),caller,'pending') returning id into chat;
  set local role authenticated;
  if (public.st_be_safe_lookup(null,null,handle)->>'restricted')::boolean is distinct from false then
    raise exception 'An unapproved chat exposed an account restriction';
  end if;
  reset role;

  update public.st_chats set status='accepted' where requester=caller;
  insert into public.st_messages(id,chat_id,sender,body) values(message,chat,caller,'See [details]('||blocked||'?fixture=1)');
  set local role authenticated;
  if (public.st_be_safe_lookup(null,null,handle)->>'restricted')::boolean is distinct from true then
    raise exception 'An approved contact could not see an active account restriction';
  end if;
  if not exists(select from public.st_direct_message_advisories(chat,array[message]) where verdict='blocked_link') then
    raise exception 'A restricted URL was not flagged in chat';
  end if;
  reset role;

  update sectalk_private.suspensions set until_at=now()-interval '1 second' where user_id=subject;
  update sectalk_private.st_v7_soc_url_blocks set expires_at=now()-interval '1 second' where response=block_response;
  set local role authenticated;
  result := public.st_be_safe_lookup(null,array[blocked],handle);
  if (result->>'restricted')::boolean is distinct from false
    or (result->'links'->0->>'restricted')::boolean is distinct from false
    or exists(select from public.st_direct_message_advisories(chat,array[message]) where verdict='blocked_link') then
    raise exception 'Expired actions are still visible as warnings';
  end if;
end $$;

rollback;
