-- Run against a disposable local database after the discovery migration.
begin;

insert into auth.users(id,email,aud,role) values
 ('66000000-0000-4000-8000-000000000001','discover-a@example.invalid','authenticated','authenticated'),
 ('66000000-0000-4000-8000-000000000002','discover-b@example.invalid','authenticated','authenticated'),
 ('66000000-0000-4000-8000-000000000003','discover-c@example.invalid','authenticated','authenticated');
insert into public.st_profiles(id,handle,name) values
 ('66000000-0000-4000-8000-000000000001','discover_alpha','Alpha Tester'),
 ('66000000-0000-4000-8000-000000000002','discover_birch','Birch Zinnia'),
 ('66000000-0000-4000-8000-000000000003','discover_zed','Zed Tester');
insert into public.st_v5_discovery(user_id,stage,categories,discoverable) values
 ('66000000-0000-4000-8000-000000000001','professional',array['study-data-science'],true),
 ('66000000-0000-4000-8000-000000000002','professional',array['study-cybersecurity'],true),
 ('66000000-0000-4000-8000-000000000003','professional',array['study-cybersecurity'],false);

set local role authenticated;
do $$
declare
  alpha constant uuid:='66000000-0000-4000-8000-000000000001';
  birch constant uuid:='66000000-0000-4000-8000-000000000002';
  zed constant uuid:='66000000-0000-4000-8000-000000000003';
begin
  if has_function_privilege('anon','public.st_v5_find_friends(text,text,text)','EXECUTE') then
    raise exception 'Anonymous callers can execute discovery';
  end if;
  perform set_config('request.jwt.claims',json_build_object('sub',zed,'role','authenticated')::text,true);
  begin
    perform public.st_v5_find_friends('z',null,null);
    raise exception 'An account with discovery off browsed the directory' using errcode='P0004';
  exception when sqlstate 'PT403' then null;
  end;
  perform set_config('request.jwt.claims',json_build_object('sub',alpha,'role','authenticated')::text,true);
  if not exists(select 1 from public.st_v5_find_friends('z',null,null) where handle='discover_birch')
    or exists(select 1 from public.st_v5_find_friends('z',null,null) where handle='discover_zed') then
    raise exception 'One-letter name search missed the published profile or exposed a private profile';
  end if;
  if not exists(select 1 from public.st_v5_find_friends('  @DISCOVER_B  ',null,null) where handle='discover_birch')
    or not exists(select 1 from public.st_v5_find_friends('innia',null,null) where handle='discover_birch') then
    raise exception 'Handle prefix or name keyword search failed';
  end if;
  if not exists(select 1 from public.st_v5_find_friends('','professional','study-cybersecurity') where handle='discover_birch')
    or exists(select 1 from public.st_v5_find_friends('z','student','study-cybersecurity') where handle='discover_birch')
    or exists(select 1 from public.st_v5_find_friends('','professional',null) where handle='discover_alpha') then
    raise exception 'Stage, category, or self filtering failed';
  end if;
  set local role postgres;
  insert into public.st_blocks(actor,target) values(birch,alpha);
  set local role authenticated;
  if exists(select 1 from public.st_v5_find_friends('z',null,null) where handle='discover_birch') then
    raise exception 'Reverse block did not hide discovery result';
  end if;
  set local role postgres;
  delete from public.st_blocks where actor=birch and target=alpha;
  insert into public.st_chats(member_a,member_b,requester) values(alpha,birch,birch);
  set local role authenticated;
  if exists(select 1 from public.st_v5_find_friends('z',null,null) where handle='discover_birch') then
    raise exception 'Existing request appeared as a new discovery result';
  end if;
end $$;

rollback;
