begin;
do $$
declare person uuid:=gen_random_uuid(); sid uuid:=gen_random_uuid(); n integer;
begin
  insert into auth.users(id,email) values(person,'url-check-fixture@example.invalid');
  insert into public.st_profiles(id,handle,name) values(person,'url_inspection_fixture','URL inspection fixture');
  insert into auth.sessions(id,user_id,aal) values(sid,person,'aal1');
  if has_function_privilege('anon','public.st_v7_authorize_url_inspection()','execute') then
    raise exception 'Anonymous callers can reserve URL inspections';
  end if;
  perform set_config('request.jwt.claims',jsonb_build_object('sub',person,'session_id',gen_random_uuid(),'aal','aal1')::text,true);
  set local role authenticated;
  if public.st_v7_authorize_url_inspection() then raise exception 'Invalid session reserved a URL inspection'; end if;
  perform set_config('request.jwt.claims',jsonb_build_object('sub',person,'session_id',sid,'aal','aal1')::text,true);
  for n in 1..6 loop
    if not public.st_v7_authorize_url_inspection() then raise exception 'Valid session was not authorized'; end if;
  end loop;
  begin
    perform public.st_v7_authorize_url_inspection();
    raise exception 'Unbounded inspection quota';
  exception when sqlstate 'PT429' then null; end;
  reset role;
end
$$;
select 'passed: active authentication and account quota' as result;
rollback;
