begin;
do $$
declare
  actors uuid[]:=array(select gen_random_uuid() from generate_series(1,6));
  devices uuid[]:=array(select gen_random_uuid() from generate_series(1,6));
  sessions text[]:=array(select gen_random_uuid()::text from generate_series(1,6));
  group_id uuid;
  response jsonb;
  i integer;
begin
  if has_function_privilege('anon','public.st_v6_group_call_ice(uuid,uuid)','execute')
    or has_function_privilege('service_role','public.st_v6_group_call_ice(uuid,uuid)','execute')
    or not has_function_privilege('authenticated','public.st_v6_group_call_ice(uuid,uuid)','execute')
    then raise exception 'Unexpected group relay admission grants'; end if;
  if has_function_privilege('anon','public.st_v6_group_promotion_failed(uuid,uuid,integer)','execute')
    or has_function_privilege('service_role','public.st_v6_group_promotion_failed(uuid,uuid,integer)','execute')
    or not has_function_privilege('authenticated','public.st_v6_group_promotion_failed(uuid,uuid,integer)','execute')
    then raise exception 'Unexpected group rollback grants'; end if;
  for i in 1..6 loop
    insert into auth.users(id,email) values(actors[i],'group-'||i||'@example.invalid');
    insert into auth.sessions(id,user_id,aal,created_at,updated_at)
      values(sessions[i]::uuid,actors[i],'aal1',now(),now());
    insert into public.st_profiles(id,handle,name) values(actors[i],'group_rollback_'||i,'Group actor '||i);
    if i between 2 and 5 then
      insert into public.st_chats(member_a,member_b,requester,status)
        values(least(actors[i],actors[1]),greatest(actors[i],actors[1]),actors[1],'accepted');
    end if;
  end loop;
  perform set_config('request.jwt.claims',json_build_object('sub',actors[1],'session_id',sessions[1])::text,true);
  begin
    perform public.st_v6_group_call('create',p_device=>devices[1],p_targets=>actors[6:6]);
    raise exception 'Unaccepted contact invited' using errcode='P0004';
  exception when insufficient_privilege then null; end;
  response:=public.st_v6_group_call('create',p_device=>devices[1],p_targets=>actors[2:5],p_video=>true);
  group_id:=(response->>'id')::uuid;
  if group_id is null or response->>'topology'<>'mesh' or response->>'video'<>'true'
    then raise exception 'Video group did not start in mesh'; end if;
  for i in 2..5 loop
    perform set_config('request.jwt.claims',json_build_object('sub',actors[i],'session_id',sessions[i])::text,true);
    response:=public.st_v6_group_call('accept',group_id,devices[i]);
    if response is null then raise exception 'Group join failed for slot %',i; end if;
  end loop;
  if response->>'topology'<>'promoting' or jsonb_array_length(response->'mesh')<>4 or response->'mesh' ? actors[5]::text
    then raise exception 'Fifth endpoint received mesh scope or handoff did not start'; end if;
  if public.st_v6_group_call('state',group_id,gen_random_uuid()) is not null then raise exception 'Unowned group endpoint accepted'; end if;
  perform set_config('request.jwt.claims',json_build_object('sub',actors[6],'session_id',sessions[6])::text,true);
  if public.st_v6_group_call('sfu',group_id,devices[6]) is not null then raise exception 'Outsider acquired provider scope'; end if;
  if public.st_v6_group_call_ice(group_id,devices[6]) is not null then raise exception 'Outsider acquired relay scope'; end if;
  if public.st_v6_group_promotion_failed(group_id,devices[6],1) then raise exception 'Outsider rolled back group media'; end if;
  perform set_config('request.jwt.claims',json_build_object('sub',actors[1],'session_id',sessions[1])::text,true);
  perform public.st_v6_group_call('ready',group_id,devices[1],p_generation=>1);
  update sectalk_private.st_v6_group_call set deadline=clock_timestamp()-interval '1 second' where id=group_id;
  response:=public.st_v6_group_call('state',group_id,devices[1]);
  if response->>'topology'<>'mesh' or jsonb_array_length(response->'joined')<>4 then raise exception 'Failed handoff did not preserve four mesh members'; end if;
  perform set_config('request.jwt.claims',json_build_object('sub',actors[5],'session_id',sessions[5])::text,true);
  response:=public.st_v6_group_call('accept',group_id,devices[5]);
  if response->>'generation'<>'2' then raise exception 'Retry reused prior provider generation'; end if;
  if public.st_v6_group_promotion_failed(group_id,devices[5],1)
    or public.st_v6_group_promotion_failed(group_id,gen_random_uuid(),2) then
    raise exception 'Stale generation or unrelated device rolled back group media'; end if;
  if public.st_v6_group_promotion_failed(group_id,devices[5],2) is not true then
    raise exception 'Current participant could not report failed promotion'; end if;
  if public.st_v6_group_promotion_failed(group_id,devices[5],2) then raise exception 'Rollback was repeated'; end if;
  perform set_config('request.jwt.claims',json_build_object('sub',actors[1],'session_id',sessions[1])::text,true);
  response:=public.st_v6_group_call('state',group_id,devices[1]);
  if response->>'topology'<>'mesh' or jsonb_array_length(response->'mesh')<>4 then
    raise exception 'Immediate rollback did not retain original mesh peers'; end if;
  perform set_config('request.jwt.claims',json_build_object('sub',actors[5],'session_id',sessions[5])::text,true);
  response:=public.st_v6_group_call('accept',group_id,devices[5]);
  if response->>'generation'<>'3' then raise exception 'Immediate rollback did not permit retry'; end if;
  for i in 1..5 loop
    perform set_config('request.jwt.claims',json_build_object('sub',actors[i],'session_id',sessions[i])::text,true);
    response:=public.st_v6_group_call('ready',group_id,devices[i],p_generation=>3);
  end loop;
  if response->>'topology'<>'sfu' or jsonb_array_length(response->'mesh')<>0
    or public.st_v6_group_call_ice(group_id,devices[5]) is not null
    then raise exception 'Mesh stayed enabled after provider handoff'; end if;
  if public.st_v6_group_call('sfu',group_id,devices[5])->>'video'<>'true' then raise exception 'Video provider scope missing'; end if;
  perform public.st_v6_group_call('leave',group_id,devices[5]);
  perform set_config('request.jwt.claims',json_build_object('sub',actors[1],'session_id',sessions[1])::text,true);
  response:=public.st_v6_group_call('state',group_id,devices[1]);
  if response->>'topology'<>'demoting' or response->>'sfuGeneration'<>'3' then raise exception 'Reverse handoff lost the existing provider room'; end if;
  update sectalk_private.st_v6_group_call set deadline=clock_timestamp()-interval '1 second' where id=group_id;
  response:=public.st_v6_group_call('state',group_id,devices[1]);
  if response->>'topology'<>'sfu' or response->>'sfuGeneration'<>'3' then raise exception 'Reverse rollback lost existing audio'; end if;
  update sectalk_private.st_v6_group_call set deadline=clock_timestamp()-interval '1 second' where id=group_id;
  response:=public.st_v6_group_call('state',group_id,devices[1]);
  if response->>'topology'<>'demoting' or response->>'generation'<>'5' then raise exception 'Reverse retry failed'; end if;
  for i in 1..4 loop
    perform set_config('request.jwt.claims',json_build_object('sub',actors[i],'session_id',sessions[i])::text,true);
    response:=public.st_v6_group_call('ready',group_id,devices[i],p_generation=>5);
  end loop;
  if response->>'topology'<>'mesh' or jsonb_array_length(response->'mesh')<>4
    then raise exception 'Reverse handoff did not return the four surviving mesh endpoints'; end if;
  perform set_config('request.jwt.claims',json_build_object('sub',actors[1],'session_id',sessions[2])::text,true);
  if public.st_v6_group_call_ice(group_id,devices[1]) is not null then raise exception 'Unbound session acquired relay scope'; end if;
  perform set_config('request.jwt.claims',json_build_object('sub',actors[1],'session_id',sessions[1])::text,true);
  for i in 2..12 loop
    response:=public.st_v6_group_call_ice(group_id,devices[1]);
    if response->>'expires_at' is null then raise exception 'Admitted endpoint did not receive a relay lease deadline'; end if;
  end loop;
  begin
    perform public.st_v6_group_call_ice(group_id,devices[1]);
    raise exception 'Group relay limit did not reject the next request' using errcode='P0004';
  exception when sqlstate 'PT429' then null; end;
end
$$;
rollback;
