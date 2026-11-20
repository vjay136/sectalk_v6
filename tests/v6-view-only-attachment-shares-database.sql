\set ON_ERROR_STOP on
begin;
do $$
declare
  owner_id uuid:=gen_random_uuid();
  peer_id uuid:=gen_random_uuid();
  outsider uuid:=gen_random_uuid();
  source_chat uuid:=gen_random_uuid();
  destination uuid:=gen_random_uuid();
  attachment uuid:=gen_random_uuid();
  token text;
  expiring text;
  revoked text;
  link_id uuid;
  pass text:='synthetic-view-only-password';
begin
  insert into auth.users(id,email) select id,id||'@example.invalid' from unnest(array[owner_id,peer_id,outsider]) id;
  insert into public.st_profiles(id,handle,name) select id,'viewq_'||left(id::text,8),'View-only QA'
    from unnest(array[owner_id,peer_id,outsider]) id;
  insert into public.st_chats(id,member_a,member_b,requester,status) values
    (source_chat,least(owner_id,peer_id),greatest(owner_id,peer_id),owner_id,'accepted'),
    (destination,least(owner_id,outsider),greatest(owner_id,outsider),owner_id,'accepted');
  insert into public.st_messages(id,chat_id,sender,body) values(attachment,source_chat,owner_id,'Restricted attachment');
  insert into public.st_v5_files(id,chat_id,uploader,message_id,filename,size_bytes)
    values(attachment,source_chat,owner_id,attachment,'view-only.txt',12);

  set local role authenticated;
  perform set_config('request.jwt.claims',jsonb_build_object('sub',peer_id,'aal','aal1')::text,true);
  begin
    perform public.st_v6_create_file_share(attachment,pass,900,1,true,true);
    raise exception 'Attachment recipient created an owner-only link';
  exception when insufficient_privilege then null; end;
  perform set_config('request.jwt.claims',jsonb_build_object('sub',owner_id,'aal','aal1')::text,true);
  begin
    perform public.st_v6_forward_direct(source_chat,attachment,destination,gen_random_uuid());
    raise exception 'Attachment message unexpectedly forwarded' using errcode='P0004';
  exception when raise_exception then null; end;
  token:=public.st_v6_create_file_share(attachment,pass,900,1,true,true);
  expiring:=public.st_v6_create_file_share(attachment,pass,900,3,true,false);
  revoked:=public.st_v6_create_file_share(attachment,pass,900,3,true,false);
  if (select count(*) from public.st_v6_list_file_shares(attachment) s where s.view_only)<>3
    or not exists(select 1 from public.st_v6_list_file_shares(attachment) s where s.watermark)
  then raise exception 'Owner controls did not persist'; end if;
  reset role;
  update sectalk_private.st_v6_file_share_links set expires_at=now()-interval '1 second'
    where token_hash=extensions.digest(expiring,'sha256');
  select s.id into link_id from sectalk_private.st_v6_file_share_links s where s.token_hash=extensions.digest(revoked,'sha256');
  set local role authenticated;
  perform public.st_v6_revoke_file_share(attachment,link_id);

  set local role service_role;
  if public.st_v6_access_file_share(token,pass,'peek') is not null
    or public.st_v6_access_file_share(token,pass,'download') is not null
    or public.st_v6_access_file_share(expiring,pass,'preview_peek') is not null
    or public.st_v6_access_file_share(revoked,pass,'preview_peek') is not null
    or public.st_v6_access_file_share(token,pass,'preview_peek')->>'view_only' is distinct from 'true'
    or public.st_v6_access_file_share(token,pass,'preview')->>'watermark' is distinct from 'true'
    or public.st_v6_access_file_share(token,pass,'preview') is not null
  then raise exception 'A view-only grant bypassed a mode, expiry, revocation, or maximum preview'; end if;
  set local role authenticated;
  if (select count(*) from public.st_v6_file_access_history(attachment) h
    where h.event='link_preview' and h.participant='link_visitor')<>1
  then raise exception 'A successful preview did not create a visitor audit event'; end if;
  reset role;
end
$$;
select 'passed: exact owner scope, no forwarding, preview-only grant, watermark metadata, expiry, revoke and atomic cap' as result;
rollback;
