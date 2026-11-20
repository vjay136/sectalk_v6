begin;
insert into auth.users(id,email) values
 ('6bc7036a-2a92-4cda-8229-c32ca4792e01','fts-owner@example.invalid'),
 ('6bc7036a-2a92-4cda-8229-c32ca4792e02','fts-peer@example.invalid'),
 ('6bc7036a-2a92-4cda-8229-c32ca4792e03','fts-outside@example.invalid');
insert into public.st_profiles(id,handle,name) values
 ('6bc7036a-2a92-4cda-8229-c32ca4792e01','search_fixture_one','Glyphword Owner'),
 ('6bc7036a-2a92-4cda-8229-c32ca4792e02','search_fixture_two','Glyphword Peer'),
 ('6bc7036a-2a92-4cda-8229-c32ca4792e03','search_fixture_three','Outside account');
insert into public.st_chats(id,member_a,member_b,requester,status) values
 ('6bc7036a-2a92-4cda-8229-c32ca4792e10','6bc7036a-2a92-4cda-8229-c32ca4792e01',
  '6bc7036a-2a92-4cda-8229-c32ca4792e02','6bc7036a-2a92-4cda-8229-c32ca4792e01','accepted');
insert into public.st_messages(id,chat_id,sender,body) values
 ('6bc7036a-2a92-4cda-8229-c32ca4792e11','6bc7036a-2a92-4cda-8229-c32ca4792e10',
  '6bc7036a-2a92-4cda-8229-c32ca4792e01','Glyphword private, context 18%'),
 ('6bc7036a-2a92-4cda-8229-c32ca4792e12','6bc7036a-2a92-4cda-8229-c32ca4792e10',
  '6bc7036a-2a92-4cda-8229-c32ca4792e01','Glyphword private context 180');
insert into public.st_v5_files(id,chat_id,uploader,message_id,filename,size_bytes) values
 ('6bc7036a-2a92-4cda-8229-c32ca4792e13','6bc7036a-2a92-4cda-8229-c32ca4792e10',
  '6bc7036a-2a92-4cda-8229-c32ca4792e01','6bc7036a-2a92-4cda-8229-c32ca4792e11','Glyphword_18%.txt',12);

do $$
declare
  owner_id constant uuid:='6bc7036a-2a92-4cda-8229-c32ca4792e01';
  peer_id constant uuid:='6bc7036a-2a92-4cda-8229-c32ca4792e02';
  outside_id constant uuid:='6bc7036a-2a92-4cda-8229-c32ca4792e03';
  chat constant uuid:='6bc7036a-2a92-4cda-8229-c32ca4792e10';
  source constant uuid:='6bc7036a-2a92-4cda-8229-c32ca4792e11';
  room uuid:=gen_random_uuid();
  room_post uuid:=gen_random_uuid();
  workspace uuid;
begin
  set local role authenticated;
  perform set_config('request.jwt.claims',json_build_object('sub',owner_id,'role','authenticated')::text,true);
  workspace:=public.st_v2_create_workspace('Search fixture workspace');
  perform public.st_v6_room_create(room,workspace,'Glyphword room','private','blank');
  perform public.st_v6_room_post(room,room_post,'Glyphword room post');
  perform public.st_v6_task_create(gen_random_uuid(),room,null,'Glyphword task');
  if (select count(distinct kind) from public.st_v6_search('glyphword',null,'{}'))<>6
    or (select count(*) from public.st_v6_search('18%','direct','{}'))<>1
    or (select count(*) from public.st_v6_search('private context','direct','{}'))<>2
    or not exists(select 1 from public.st_v6_search('lyphwor','file','{}'))
    then raise exception 'Search categories, escaped fragments or token search differ'; end if;

  perform set_config('request.jwt.claims',json_build_object('sub',outside_id,'role','authenticated')::text,true);
  if exists(select 1 from public.st_v6_search('glyphword',null,'{}'))
    or exists(select 1 from public.st_v6_search_people where id=owner_id)
    then raise exception 'Outsider could search private content or profiles'; end if;
  perform set_config('request.jwt.claims',json_build_object('sub',peer_id,'role','authenticated')::text,true);
  if exists(select 1 from public.st_v6_search('glyphword','room_name','{}'))
    or exists(select 1 from public.st_v6_search('glyphword','task','{}'))
    or not exists(select 1 from public.st_v6_search('glyphword','file','{}'))
    or not exists(select 1 from public.st_v6_search('glyphword owner','person','{}'))
    then raise exception 'Chat and room scopes were not isolated'; end if;
  perform public.st_set_block(chat,true);
  if exists(select 1 from public.st_v6_search('glyphword owner','person','{}'))
    then raise exception 'A blocked profile appeared in people search'; end if;
  reset role;
  insert into public.st_v5_hidden_messages(user_id,message_id) values(peer_id,source);
  set local role authenticated;
  if exists(select 1 from public.st_v6_search('glyphword','file','{}'))
    then raise exception 'A hidden attachment was indexed for the viewer'; end if;
  perform set_config('request.jwt.claims',json_build_object('sub',owner_id,'role','authenticated')::text,true);
  perform public.st_v6_room_post_action(room,room_post,'delete');
  if exists(select 1 from public.st_v6_search('glyphword','room','{}'))
    then raise exception 'Removed text remained searchable'; end if;
end $$;
select 'passed: token and fragment matching, six result types, escaped wildcards and tenant ACL' as result;
rollback;
