\set ON_ERROR_STOP on
begin;

do $$
declare
  owner_id uuid:=gen_random_uuid();
  peer_id uuid:=gen_random_uuid();
  chat uuid:=gen_random_uuid();
  attachment uuid:=gen_random_uuid();
  token text;
  reversible text;
  expiring text;
  link uuid;
  password text:='local-synthetic-share-password';
begin
  insert into auth.users(id,email) values(owner_id,owner_id||'@example.invalid'),(peer_id,peer_id||'@example.invalid');
  insert into public.st_profiles(id,handle,name) values
    (owner_id,'shareq_'||left(owner_id::text,8),'Share fixture uploader'),
    (peer_id,'shareq_'||left(peer_id::text,8),'Share fixture recipient');
  insert into public.st_chats(id,member_a,member_b,requester,status)
    values(chat,least(owner_id,peer_id),greatest(owner_id,peer_id),owner_id,'accepted');
  insert into public.st_messages(id,chat_id,sender,body) values(attachment,chat,owner_id,'Attachment fixture');
  insert into public.st_v5_files(id,chat_id,uploader,message_id,filename,size_bytes)
    values(attachment,chat,owner_id,attachment,'share.txt',12);

  set local role authenticated;
  perform set_config('request.jwt.claims',jsonb_build_object('sub',peer_id,'aal','aal1')::text,true);
  begin
    perform public.st_v6_create_file_share(attachment,password,900,1);
    raise exception 'A recipient created an uploader share link';
  exception when insufficient_privilege then null; end;
  if has_function_privilege('public.st_v6_access_file_share(text,text,text)','execute')
    then raise exception 'Browser could directly redeem without the server byte check'; end if;
  perform set_config('request.jwt.claims',jsonb_build_object('sub',owner_id,'aal','aal1')::text,true);
  token:=public.st_v6_create_file_share(attachment,password,900,1);
  reversible:=public.st_v6_create_file_share(attachment,password,900,4);
  expiring:=public.st_v6_create_file_share(attachment,password,900,4);
  if token !~ '^[a-f0-9]{64}$' or (select count(*) from public.st_v6_list_file_shares(attachment))<>3
    then raise exception 'Expected one-time high-entropy tokens with private management metadata'; end if;
  reset role;
  if not exists(select 1 from sectalk_private.st_v6_file_share_links s
    where s.file_id=attachment and s.token_hash=extensions.digest(token,'sha256')
      and s.password_hash<>password and s.password_hash=extensions.crypt(password,s.password_hash))
    then raise exception 'Share secrets were not stored as expected hashes'; end if;
  update sectalk_private.st_v6_file_share_links set expires_at=now()-interval '1 second'
    where token_hash=extensions.digest(expiring,'sha256');
  select s.id into link from sectalk_private.st_v6_file_share_links s where s.token_hash=extensions.digest(reversible,'sha256');

  set local role service_role;
  if public.st_v6_access_file_share(token,'incorrect-password','view') is not null
    or public.st_v6_access_file_share(expiring,password,'view') is not null
    or public.st_v6_access_file_share(token,password,'view')->>'filename' is distinct from 'share.txt'
    or public.st_v6_access_file_share(token,password,'peek')->>'file' is distinct from attachment::text
    or public.st_v6_access_file_share(token,password,'download')->>'file' is distinct from attachment::text
    or public.st_v6_access_file_share(token,password,'download') is not null
  then raise exception 'Password, expiry, view, or atomic maximum download failed'; end if;
  reset role;

  set local role authenticated;
  perform public.st_v6_revoke_file_share(attachment,link);
  perform public.st_v6_revoke_file_share(attachment,link);
  if (select count(*) from public.st_v6_file_access_history(attachment) h where h.event='link_created' and h.participant='owner')<>3
    or (select count(*) from public.st_v6_file_access_history(attachment) h where h.event='link_revoked' and h.participant='owner')<>1
    or (select count(*) from public.st_v6_file_access_history(attachment) h where h.event in ('link_view','link_download') and h.participant='link_visitor')<>2
    then raise exception 'Share activity did not reach owner history with correct disclosure'; end if;
  reset role;

  set local role service_role;
  if public.st_v6_access_file_share(reversible,password,'view') is not null
    then raise exception 'A revoked link still granted access'; end if;
  reset role;
  token:=public.st_v6_create_file_share(attachment,password,900,5);
  insert into public.st_blocks(actor,target) values(peer_id,owner_id);
  if public.st_v6_access_file_share(token,password,'peek') is not null
    then raise exception 'A link bypassed a direct-chat block'; end if;
  delete from public.st_blocks where actor=peer_id and target=owner_id;
  update public.st_messages set revoked_at=now() where id=attachment;
  if public.st_v6_access_file_share(token,password,'peek') is not null
    then raise exception 'A link survived revocation of the original attachment'; end if;
end
$$;
select 'passed: direct ownership, hashes, password, expiry, atomic cap, revocation, source recheck and history' as result;
rollback;
