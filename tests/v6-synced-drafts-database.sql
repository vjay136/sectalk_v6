begin;
insert into auth.users(id,email) values
  ('99600000-0000-4000-8000-000000000001','draft-author@example.invalid'),
  ('99600000-0000-4000-8000-000000000002','draft-peer@example.invalid'),
  ('99600000-0000-4000-8000-000000000003','draft-outside@example.invalid');
insert into public.st_profiles(id,handle,name) values
  ('99600000-0000-4000-8000-000000000001','draft_author','Draft author'),
  ('99600000-0000-4000-8000-000000000002','draft_peer','Draft peer'),
  ('99600000-0000-4000-8000-000000000003','draft_outside','Outside account');

do $$
declare
  writer constant uuid:='99600000-0000-4000-8000-000000000001';
  peer constant uuid:='99600000-0000-4000-8000-000000000002';
  outsider constant uuid:='99600000-0000-4000-8000-000000000003';
  workspace uuid;
  chat uuid;
  room uuid:=gen_random_uuid();
  thread uuid:=gen_random_uuid();
  result jsonb;
begin
  set local role authenticated;
  perform set_config('request.jwt.claims',json_build_object('sub',writer,'role','authenticated')::text,true);
  chat:=public.st_request('draft_peer');
  workspace:=public.st_v2_create_workspace('Draft isolation fixture');
  perform public.st_v6_room_create(room,workspace,'Draft room','public','blank');
  perform public.st_v6_room_post(room,thread,'Thread source');
  perform set_config('request.jwt.claims',json_build_object('sub',peer,'role','authenticated')::text,true);
  perform public.st_respond(chat,true);
  perform set_config('request.jwt.claims',json_build_object('sub',writer,'role','authenticated')::text,true);
  result:=public.st_v6_save_draft(writer,'chat',chat,null,0,'Private draft alpha');
  if result<>jsonb_build_object('saved',true,'revision',1,'body','Private draft alpha')
  then raise exception 'Initial draft revision failed'; end if;
  result:=public.st_v6_save_draft(writer,'chat',chat,null,0,'Stale overwrite');
  if result<>jsonb_build_object('saved',false,'revision',1,'body','Private draft alpha')
  then raise exception 'Stale write did not return the current revision'; end if;
  perform public.st_v6_save_draft(writer,'room',room,null,0,'Root draft value');
  perform public.st_v6_save_draft(writer,'room',room,thread,0,'Thread draft value');
  if public.st_v6_read_draft(writer,'room',room,null)->>'body'<>'Root draft value'
    or public.st_v6_read_draft(writer,'room',room,thread)->>'body'<>'Thread draft value'
  then raise exception 'Root and thread drafts overlapped'; end if;

  perform set_config('request.jwt.claims',json_build_object('sub',peer,'role','authenticated')::text,true);
  if public.st_v6_read_draft(peer,'chat',chat,null)->>'body'<>'' then raise exception 'Peer saw another draft'; end if;
  begin
    perform public.st_v6_save_draft(writer,'chat',chat,null,1,'Caller mixup');
    raise exception 'Save accepted a different expected actor';
  exception when insufficient_privilege then null; end;
  perform set_config('request.jwt.claims',json_build_object('sub',outsider,'role','authenticated')::text,true);
  begin
    perform public.st_v6_read_draft(outsider,'room',room,null);
    raise exception 'An outsider could read room drafts';
  exception when insufficient_privilege then null; end;
  reset role;
  if not exists(select 1 from sectalk_private.st_v6_drafts d where d.actor=writer and d.conversation=chat
      and octet_length(d.ciphertext)>24 and position(convert_to('Private draft alpha','UTF8') in d.ciphertext)=0)
    or has_table_privilege('authenticated','sectalk_private.st_v6_drafts','SELECT')
    or has_function_privilege('authenticated','sectalk_private.st_v6_draft_secret()','EXECUTE')
  then raise exception 'Draft at-rest protection did not hold'; end if;
  if not exists(select 1 from realtime.messages m where m.topic='st:account:'||writer and m.event='draft_change'
    and m.payload->>'conversation'=chat::text and m.private)
    or exists(select 1 from realtime.messages m where m.event='draft_change'
      and m.payload->>'conversation'=chat::text and (m.payload?'body' or m.topic<>'st:account:'||writer))
  then raise exception 'Draft hint disclosed data'; end if;

  set local role authenticated;
  perform set_config('request.jwt.claims',json_build_object('sub',writer,'role','authenticated')::text,true);
  perform public.st_v6_save_draft(writer,'chat',chat,null,1,'');
  result:=public.st_v6_save_draft(writer,'chat',chat,null,1,'Resurrected draft');
  if result<>jsonb_build_object('saved',false,'revision',2,'body','')
  then raise exception 'Cleared draft was resurrected'; end if;
end $$;
select 'passed: encrypted draft storage, actor and scope isolation, compare-and-swap, private sync and clears' as result;
rollback;
