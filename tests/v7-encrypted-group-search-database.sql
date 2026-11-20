begin;

insert into auth.users(id,email)
select ('6e270000-0000-4000-8000-'||lpad(n::text,12,'0'))::uuid,'group-search-'||n||'@example.invalid'
from generate_series(1,3) n;
insert into public.st_profiles(id,handle,name)
select ('6e270000-0000-4000-8000-'||lpad(n::text,12,'0'))::uuid,'group_search_'||n,'Group search fixture'
from generate_series(1,3) n;
insert into auth.sessions(id,user_id,aal)
select ('6e270001-0000-4000-8000-'||lpad(n::text,12,'0'))::uuid,
  ('6e270000-0000-4000-8000-'||lpad(n::text,12,'0'))::uuid,'aal1'
from generate_series(1,3) n;
insert into auth.mfa_amr_claims(id,session_id,authentication_method,created_at,updated_at)
select gen_random_uuid(),('6e270001-0000-4000-8000-'||lpad(n::text,12,'0'))::uuid,'password',now(),now()
from generate_series(1,3) n;
insert into public.st_chats(id,member_a,member_b,requester,status)
values (gen_random_uuid(),'6e270000-0000-4000-8000-000000000001','6e270000-0000-4000-8000-000000000002',
  '6e270000-0000-4000-8000-000000000001','accepted');
insert into sectalk_private.st_v7_devices(id,owner,state,signing_key,agreement_key,bundle_signature)
select ('6e270002-0000-4000-8000-'||lpad(n::text,12,'0'))::uuid,
  ('6e270000-0000-4000-8000-'||lpad(n::text,12,'0'))::uuid,
  case when n=2 then 'managed' else 'trusted' end,
  repeat(chr(65+n),87),repeat(chr(75+n),87),repeat(chr(85+n),86)
from generate_series(1,3) n;
insert into sectalk_private.st_v7_device_sessions(session_id,owner,device_id)
select ('6e270001-0000-4000-8000-'||lpad(n::text,12,'0'))::uuid,
  ('6e270000-0000-4000-8000-'||lpad(n::text,12,'0'))::uuid,
  ('6e270002-0000-4000-8000-'||lpad(n::text,12,'0'))::uuid
from generate_series(1,3) n;


do $$
declare
  owner constant uuid:='6e270000-0000-4000-8000-000000000001';
  peer constant uuid:='6e270000-0000-4000-8000-000000000002';
  outsider constant uuid:='6e270000-0000-4000-8000-000000000003';
  peer_device constant uuid:='6e270002-0000-4000-8000-000000000002';
  outsider_device constant uuid:='6e270002-0000-4000-8000-000000000003';
  owner_device constant uuid:='6e270002-0000-4000-8000-000000000001';
  peer_claims constant text:=jsonb_build_object('sub',peer,'session_id','6e270001-0000-4000-8000-000000000002','aal','aal1')::text;
  new_device_session uuid:=gen_random_uuid();
  g constant uuid:=gen_random_uuid();
  unrelated constant uuid:=gen_random_uuid();
  old_msg constant uuid:=gen_random_uuid();
  current_msg constant uuid:=gen_random_uuid();
  reply jsonb;
begin
  if has_function_privilege('anon','public.st_group_search_metadata(uuid)','execute')
    or has_table_privilege('authenticated','sectalk_private.st_group_messages','select')
    or has_table_privilege('authenticated','sectalk_private.st_group_envelopes','select') then
    raise exception 'Group search bypasses the metadata-only boundary';
  end if;
  insert into sectalk_private.st_group_chats(id,owner,name,epoch,member_cap)
     values(g,owner,'Search fixture',2,4),(unrelated,owner,'Different fixture',1,4);
  insert into sectalk_private.st_group_members(group_id,actor) values(g,owner),(g,peer);
  insert into sectalk_private.st_group_envelopes(group_id,epoch,device,sealed,ephemeral)
    values(g,1,owner_device,repeat('A',80),repeat('B',87)),(g,2,peer_device,repeat('C',80),repeat('B',87));
  insert into sectalk_private.st_group_messages(group_id,id,epoch,actor,device,signing,payload,signature,sent)
    values(g,old_msg,1,owner,owner_device,repeat('K',87),repeat('T',48),repeat('P',86),now()-interval '1 day'),
      (g,current_msg,2,owner,owner_device,repeat('K',87),repeat('T',48),repeat('P',86),now());

  perform set_config('request.jwt.claims',peer_claims,true);
  reply:=public.st_group_search_metadata(g);
  if (reply->>'device')::uuid is distinct from peer_device
    or jsonb_array_length(reply->'messages')<>1
    or (reply#>>'{messages,0,id}')::uuid is distinct from current_msg
    or (select array_agg(k order by k) from jsonb_object_keys(reply->'messages'->0) k) <> array['epoch','id','sent']::text[]
    or (select array_agg(k order by k) from jsonb_object_keys(reply) k) <> array['device','messages']::text[] then
    raise exception 'Group search leaked historical/nonmetadata fields or missed the authorized message';
  end if;
  begin
    perform public.st_group_search_metadata(unrelated);
    raise exception 'Cross-group metadata was returned';
  exception when insufficient_privilege then null; end;
  insert into auth.sessions(id,user_id,aal) values(new_device_session,peer,'aal1');
  perform set_config('request.jwt.claims',jsonb_build_object('sub',peer,'session_id',new_device_session,'aal','aal1')::text,true);
  begin
    perform public.st_group_search_metadata(g);
    raise exception 'Unbound session read group metadata';
  exception when insufficient_privilege then null; end;
  perform set_config('request.jwt.claims',jsonb_build_object('sub',outsider,
     'session_id','6e270001-0000-4000-8000-000000000003','aal','aal1')::text,true);
  begin
    perform public.st_group_search_metadata(g);
    raise exception 'Outsider read group metadata';
  exception when insufficient_privilege then null; end;

  perform set_config('request.jwt.claims',peer_claims,true);
  insert into sectalk_private.st_group_messages(group_id,id,epoch,actor,device,signing,payload,signature,sent)
    select g,gen_random_uuid(),2,owner,owner_device,repeat('K',87),repeat('T',48),repeat('P',86),now()-n*interval '1 second'
    from generate_series(1,202) n;
  if jsonb_array_length(public.st_group_search_metadata(g)->'messages')<>200 then
    raise exception 'Metadata window is unbounded';
  end if;
  delete from sectalk_private.st_group_members m where m.group_id=g and m.actor=peer;
  begin
    perform public.st_group_search_metadata(g);
    raise exception 'A removed member read metadata';
  exception when insufficient_privilege then null; end;
end $$;

select 'passed: search metadata window, private payloads, exact device epochs, and revoked access' as result;
rollback;
