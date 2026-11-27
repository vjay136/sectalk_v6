begin;

do $test$
declare
  viewer uuid:=gen_random_uuid();
  public_peer uuid:=gen_random_uuid();
  private_peer uuid:=gen_random_uuid();
  shared_chat uuid;
  viewer_handle text:='online_'||left(replace(viewer::text,'-',''),12);
  public_handle text:='online_'||left(replace(public_peer::text,'-',''),12);
  private_handle text:='online_'||left(replace(private_peer::text,'-',''),12);
  category text:='interest-online-test-'||left(viewer::text,8);
begin
  insert into auth.users(id,email) select id,id||'@example.invalid' from unnest(array[viewer,public_peer,private_peer]) id;
  insert into public.st_profiles(id,handle,name) values
    (viewer,viewer_handle,'Online searcher'),(public_peer,public_handle,'Odessa Online'),(private_peer,private_handle,'Pia Personal');

  if has_function_privilege('anon','public.st_v6_find_friends(text,text,text,boolean,integer)','execute') then
    raise exception 'Anonymous clients can enumerate online discovery';
  end if;

  perform set_config('request.jwt.claims',json_build_object('sub',public_peer,'role','authenticated')::text,true);
  perform public.st_v6_save_discovery('professional',array[category],true,true,true);
  perform public.st_v3_ping();
  if not exists(select 1 from public.st_v3_presence where user_id=public_peer and state='online' and expires_at>now()) then
    raise exception 'First foreground activity did not seed online presence';
  end if;

  perform set_config('request.jwt.claims',json_build_object('sub',private_peer,'role','authenticated')::text,true);
  perform public.st_v6_save_discovery('professional',array[category],true,true,false);
  perform public.st_v3_ping();
  if exists(select 1 from public.st_v3_presence where user_id=private_peer) then
    raise exception 'Discovery membership without online consent seeded presence';
  end if;
  perform public.st_v3_set_presence('online');

  perform set_config('request.jwt.claims',json_build_object('sub',viewer,'role','authenticated')::text,true);
  begin
    perform public.st_v6_find_friends('',null,category,true,0);
    raise exception 'Discovery was accessible before the viewer opted in';
  exception when sqlstate 'PT403' then null;
  end;
  perform public.st_v6_save_discovery('professional',array[category],true,true,false);
  if (select array_agg(handle) from public.st_v6_find_friends('',null,category,true,0)) is distinct from array[public_handle] then
    raise exception 'Online category directory ignored a presence privacy preference';
  end if;
  if not exists(select 1 from public.st_v6_find_friends('O',null,category,false,0) where handle=public_handle and online) then
    raise exception 'Discovery dropped live single-letter search';
  end if;
  if not exists(select 1 from public.st_v5_find_friends('O',null,category) where handle=public_handle) then
    raise exception 'Old-client single-letter search regressed';
  end if;
  if exists(select 1 from public.st_v6_find_friends('',null,category,true,1)) then
    raise exception 'A later result page repeated earlier entries';
  end if;

  insert into public.st_chats(member_a,member_b,requester,status)
    values(least(viewer,public_peer),greatest(viewer,public_peer),viewer,'accepted') returning id into shared_chat;
  if not exists(select 1 from public.st_v6_find_friends('',null,category,true,0) where chat_id=shared_chat) then
    raise exception 'Online directory omitted an approved contact’s open conversation';
  end if;
  insert into public.st_blocks(actor,target) values(public_peer,viewer);
  if exists(select 1 from public.st_v6_find_friends('',null,category,true,0)) then
    raise exception 'Online directory leaked a blocked profile';
  end if;
  delete from public.st_blocks where actor=public_peer and target=viewer;

  perform set_config('request.jwt.claims',json_build_object('sub',public_peer,'role','authenticated')::text,true);
  perform public.st_v6_set_presence_privacy(false);
  perform set_config('request.jwt.claims',json_build_object('sub',viewer,'role','authenticated')::text,true);
  if exists(select 1 from public.st_v6_find_friends('',null,category,true,0)) then
    raise exception 'Online listing ignored availability privacy';
  end if;
  perform set_config('request.jwt.claims',json_build_object('sub',public_peer,'role','authenticated')::text,true);
  perform public.st_v6_set_presence_privacy(true);
  perform public.st_v3_set_presence('invisible');
  perform public.st_v3_ping();
  if not exists(select 1 from public.st_v3_presence where user_id=public_peer and state='invisible' and expires_at<=now()) then
    raise exception 'Foreground heartbeat changed explicit Invisible status';
  end if;
  perform public.st_v3_set_presence('offline');
  perform public.st_v3_ping();
  if not exists(select 1 from public.st_v3_presence where user_id=public_peer and state='offline' and expires_at<=now()) then
    raise exception 'Foreground heartbeat changed explicit Offline status';
  end if;
  perform public.st_v3_set_presence('online');
  update public.st_v3_presence set expires_at=now()-interval '1 second' where user_id=public_peer;
  perform set_config('request.jwt.claims',json_build_object('sub',viewer,'role','authenticated')::text,true);
  if exists(select 1 from public.st_v6_find_friends('',null,category,true,0)) then
    raise exception 'An expired heartbeat remained public';
  end if;

  perform set_config('request.jwt.claims',json_build_object('sub',public_peer,'role','authenticated')::text,true);
  perform public.st_v5_save_discovery('professional',array[category],false,true);
  perform public.st_v5_save_discovery('professional',array[category],true,true);
  if exists(select 1 from public.st_v5_discovery where user_id=public_peer and online_discoverable) then
    raise exception 'An old-client discovery opt-out retained prior online consent';
  end if;
end $test$;

rollback;
