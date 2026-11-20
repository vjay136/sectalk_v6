begin;
insert into auth.users(id,email) values
  ('79100000-0000-4000-8000-000000000001','edit-alex@example.invalid'),
  ('79100000-0000-4000-8000-000000000002','edit-billie@example.invalid'),
  ('79100000-0000-4000-8000-000000000003','edit-casey@example.invalid');
insert into public.st_profiles(id,name,handle) values
  ('79100000-0000-4000-8000-000000000001','Edit Alex','edit_alex'),
  ('79100000-0000-4000-8000-000000000002','Edit Billie','edit_billie'),
  ('79100000-0000-4000-8000-000000000003','Edit Casey','edit_casey');

do $$
declare
  alex constant uuid:='79100000-0000-4000-8000-000000000001';
  billie constant uuid:='79100000-0000-4000-8000-000000000002';
  casey constant uuid:='79100000-0000-4000-8000-000000000003';
  subject constant uuid:='79100001-0000-4000-8000-000000000001';
  peer_post constant uuid:='79100001-0000-4000-8000-000000000002';
  expired constant uuid:='79100001-0000-4000-8000-000000000003';
  hidden_post constant uuid:='79100001-0000-4000-8000-000000000004';
  conversation uuid;
begin
  set local role authenticated;
  perform set_config('request.jwt.claims',json_build_object('sub',alex,'role','authenticated')::text,true);
  conversation:=public.st_request('edit_billie');
  perform set_config('request.jwt.claims',json_build_object('sub',billie,'role','authenticated')::text,true);
  perform public.st_respond(conversation,true);
  perform public.st_send(conversation,peer_post,'Peer original');
  perform public.st_v2_edit_message(peer_post,'Peer revised');

  perform set_config('request.jwt.claims',json_build_object('sub',alex,'role','authenticated')::text,true);
  perform public.st_send(conversation,subject,'First version');
  perform public.st_send(conversation,expired,'Expired message');
  perform public.st_send(conversation,hidden_post,'Author will hide this');
  perform public.st_v2_edit_message(subject,'Second version');
  perform public.st_v2_edit_message(subject,'Second version');
  if (select count(*) from public.st_v2_message_edits where message_id=subject)<>1
    or not exists(select 1 from public.st_messages where id=subject and edited_at is not null and body='Second version')
    then raise exception 'Edit did not add exactly one revision and mark the current message'; end if;
  perform public.st_v6_set_edit_history(conversation,false);
  if not exists(select 1 from public.st_v2_message_edits where message_id=subject)
    or not exists(select 1 from public.st_v2_message_edits where message_id=peer_post)
    then raise exception 'A private author lost their own history or changed the peer policy'; end if;

  perform set_config('request.jwt.claims',json_build_object('sub',billie,'role','authenticated')::text,true);
  perform public.st_v6_set_edit_history(conversation,true);
  if exists(select 1 from public.st_v2_message_edits where message_id=subject)
    or public.st_v2_chat_status(conversation)->>'share_peer_edit_history' is distinct from 'false'
    or not exists(select 1 from public.st_messages where id=subject and edited_at is not null)
    then raise exception 'Raw history bypassed the author privacy policy or hid the edited marker'; end if;
  begin
    perform public.st_v2_edit_message(subject,'A peer cannot edit this');
    raise exception 'A peer edited another account message' using errcode='P0004';
  exception when raise_exception then null; end;

  perform set_config('request.jwt.claims',json_build_object('sub',casey,'role','authenticated')::text,true);
  begin
    perform public.st_v6_set_edit_history(conversation,true);
    raise exception 'An outsider changed the history policy' using errcode='P0004';
  exception when raise_exception then null; end;
  if exists(select 1 from public.st_v2_message_edits where message_id in (subject,peer_post))
    then raise exception 'An outsider read message revisions'; end if;

  perform set_config('request.jwt.claims',json_build_object('sub',alex,'role','authenticated')::text,true);
  perform public.st_v6_set_edit_history(conversation,true);
  perform public.st_v5_message_action(hidden_post,'hide');
  begin
    perform public.st_v2_edit_message(hidden_post,'Hidden content cannot be edited');
    raise exception 'A hidden post was edited' using errcode='P0004';
  exception when raise_exception then null; end;
  reset role;
  update public.st_messages set created_at=clock_timestamp()-interval '24 hours 1 minute' where id=expired;
  set local role authenticated;
  begin
    perform public.st_v2_edit_message(expired,'Expired content cannot be edited');
    raise exception 'An expired message was edited' using errcode='P0004';
  exception when raise_exception then null; end;

  perform set_config('request.jwt.claims',json_build_object('sub',billie,'role','authenticated')::text,true);
  if not exists(select 1 from public.st_v2_message_edits where message_id=subject and body='First version')
    then raise exception 'The shared setting did not restore eligible history'; end if;
  perform public.st_v5_message_action(subject,'hide');
  if exists(select 1 from public.st_v2_message_edits where message_id=subject)
    then raise exception 'The viewer could query revision history after hiding the message'; end if;
  perform set_config('request.jwt.claims',json_build_object('sub',alex,'role','authenticated')::text,true);
  perform public.st_v5_message_action(subject,'revoke');
  if exists(select 1 from public.st_v2_message_edits where message_id=subject)
    then raise exception 'Revoked history remained accessible'; end if;
  begin
    perform public.st_v2_edit_message(subject,'Revoked content cannot be edited');
    raise exception 'A revoked message was edited' using errcode='P0004';
  exception when raise_exception then null; end;
  reset role;
end
$$;

select 'passed: edit window, author privacy and raw revision denial, retained edited marker, hide and revoke safety' as result;
rollback;
