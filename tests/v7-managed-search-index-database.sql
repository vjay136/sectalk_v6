begin;

do $$
declare
  author uuid:=gen_random_uuid();
  recipient uuid:=gen_random_uuid();
  outsider uuid:=gen_random_uuid();
  conversation uuid;
  item uuid:=gen_random_uuid();
  ephemeral_item uuid:=gen_random_uuid();
  orphan uuid:=gen_random_uuid();
  old_text constant text:='A queue-managed alpha, lantern phrase.';
  new_text constant text:='A queue-managed beta, window phrase.';
  job_result jsonb;
  original_tid tid;
  retry integer;
begin
  insert into auth.users(id,email) values
    (author,'search-queue-owner@example.invalid'),(recipient,'search-queue-peer@example.invalid'),(outsider,'search-queue-other@example.invalid');
  insert into public.st_profiles(id,handle,name) values
    (author,'search_queue_owner','Search queue author'),(recipient,'search_queue_peer','Search queue recipient'),
    (outsider,'search_queue_other','Search queue outsider');
  insert into public.st_chats(member_a,member_b,requester,status)
    values(least(author,recipient),greatest(author,recipient),author,'accepted') returning id into conversation;
  insert into public.st_messages(id,chat_id,sender,body) values(item,conversation,author,old_text);
  insert into public.st_messages(id,chat_id,sender,body,expires_at)
    values(ephemeral_item,conversation,author,'Temporary lantern excluded.',clock_timestamp()+interval '1 minute');
  update public.st_messages set body='Discarded intermediate state.' where id=item;
  update public.st_messages set body=old_text where id=item;
  if (select count(*) from sectalk_private.st_v7_search_pending where kind='direct' and object_id=item)<>1 then
    raise exception 'Source changes did not coalesce';
  end if;
  if has_table_privilege('authenticated','sectalk_private.st_v7_search_document','select')
    or has_table_privilege('authenticated','sectalk_private.st_v7_search_pending','select')
    or has_function_privilege('authenticated','sectalk_private.st_v7_search_work(integer)','execute')
    or has_function_privilege('anon','public.st_v7_search_index_operation(text)','execute') then
    raise exception 'Private search worker, content cache or queue is exposed';
  end if;
  job_result:=sectalk_private.st_v7_search_work(1);
  if (job_result->>'processed')::integer<>1 or (job_result->>'scanned')::integer>1 then
    raise exception 'Worker exceeded its run bound';
  end if;
  for retry in 1..15 loop
    perform sectalk_private.st_v7_search_work(500);
    exit when not exists(select 1 from sectalk_private.st_v7_search_pending where object_id in (item,ephemeral_item));
  end loop;
  if not exists(select 1 from sectalk_private.st_v7_search_document where (kind,object_id)=('direct',item)
      and first_terms @@ phraseto_tsquery('simple','alpha lantern'))
    or exists(select 1 from sectalk_private.st_v7_search_document where object_id=ephemeral_item) then
    raise exception 'Worker did not index only the eligible source';
  end if;

  perform set_config('request.jwt.claims',jsonb_build_object('sub',recipient,'aal','aal1')::text,true);
  set local role authenticated;
  if not exists(select 1 from public.st_v6_search('alpha lantern','direct','{}') where id=item and snippet=old_text) then
    raise exception 'Cached phrase failed through normal search';
  end if;
  begin
    perform public.st_v7_search_index_operation('rebuild');
    raise exception 'Ordinary user rebuilt the index';
  exception when insufficient_privilege then null; end;
  reset role;

  update public.st_messages set body=new_text where id=item;
  perform set_config('request.jwt.claims',jsonb_build_object('sub',recipient,'aal','aal1')::text,true);
  set local role authenticated;
  if exists(select 1 from public.st_v6_search('alpha lantern','direct','{}') where id=item)
    or not exists(select 1 from public.st_v6_search('beta window','direct','{}') where id=item and snippet=new_text) then
    raise exception 'Stale index suppressed current results or revealed old content';
  end if;
  reset role;

  perform set_config('request.jwt.claims',jsonb_build_object('sub',outsider,'aal','aal1')::text,true);
  set local role authenticated;
  if exists(select 1 from public.st_v6_search('beta window','direct','{}') where id=item) then
    raise exception 'Index bypassed live source RLS';
  end if;
  reset role;

  -- Rebuild verifies live source, repairs stale/orphaned cache, and preserves an unchanged document version on retries.
  insert into sectalk_private.st_v7_search_document(kind,object_id,fingerprint,first_terms,second_terms)
    values('direct',orphan,decode('aa','hex'),''::tsvector,''::tsvector);
  update sectalk_private.st_v7_search_scan set mode='rebuild',source_no=1,after_id=null,finished_at=null where singleton;
  for retry in 1..35 loop
    perform sectalk_private.st_v7_search_work(500);
    exit when exists(select 1 from sectalk_private.st_v7_search_scan where mode is null)
      and not exists(select 1 from sectalk_private.st_v7_search_pending);
  end loop;
  if exists(select 1 from sectalk_private.st_v7_search_document where object_id=orphan)
    or not exists(select 1 from sectalk_private.st_v7_search_document where object_id=item
      and first_terms @@ phraseto_tsquery('simple','beta window')) then
    raise exception 'Rebuild did not repair the document and remove the orphan';
  end if;
  select ctid into original_tid from sectalk_private.st_v7_search_document where object_id=item;
  insert into sectalk_private.st_v7_search_pending(kind,object_id) values('direct',item) on conflict do nothing;
  perform sectalk_private.st_v7_search_work(500);
  if (select ctid from sectalk_private.st_v7_search_document where object_id=item) is distinct from original_tid
    or exists(select 1 from sectalk_private.st_v7_search_pending where object_id=item) then
    raise exception 'Retry rewrote the same document or failed to drain';
  end if;

  delete from sectalk_private.st_v7_search_document where object_id=item;
  update sectalk_private.st_v7_search_scan set mode='backfill',source_no=1,after_id=null,finished_at=null where singleton;
  for retry in 1..20 loop
    perform sectalk_private.st_v7_search_work(500);
    exit when exists(select 1 from sectalk_private.st_v7_search_document where object_id=item);
  end loop;
  if not exists(select 1 from sectalk_private.st_v7_search_document where object_id=item) then
    raise exception 'Backfill failed to recover a missing document';
  end if;

  update public.st_messages set revoked_at=clock_timestamp(),body='Message removed' where id=item;
  perform set_config('request.jwt.claims',jsonb_build_object('sub',recipient,'aal','aal1')::text,true);
  set local role authenticated;
  if exists(select 1 from public.st_v6_search('beta window','direct','{}') where id=item) then
    raise exception 'Revoked content was visible while removal was pending';
  end if;
  reset role;
  perform sectalk_private.st_v7_search_work(500);
  if exists(select 1 from sectalk_private.st_v7_search_document where object_id=item) then
    raise exception 'Worker retained revoked content';
  end if;
  if exists(select 1 from pg_trigger
    where tgrelid='sectalk_private.st_group_messages'::regclass and tgname like 'st_v7_search_%') then
    raise exception 'Encrypted group source was attached to the managed queue';
  end if;
end $$;

select 'passed: member-only read, timed exclusion, coalescing, stale edit/removal, backfill, rebuild and bounded replay' as result;
rollback;
