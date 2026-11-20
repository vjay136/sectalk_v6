begin;
do $$
declare
  stamp text:=translate(substr(encode(extensions.gen_random_bytes(8),'hex'),1,12),'0123456789','abcdefghij');
  ordinary text:='ordinary_'||stamp||'@example.invalid';
  elevated text:='signup123456_'||stamp||'@example.invalid';
  other text:='other_'||stamp||'@example.invalid';
  velocity text:='velocity_'||stamp||'@example.invalid';
  first jsonb;
  work text;
  answer integer;
  permit text;
  event jsonb;
  flag jsonb;
begin
  if has_function_privilege('anon','public.st_v7_signup_admission(text,inet,text,text,integer,boolean)','execute')
    or has_function_privilege('service_role','public.st_v7_before_signup(jsonb)','execute')
    or has_table_privilege('supabase_auth_admin','sectalk_private.st_v7_signup_proofs','select') then
    raise exception 'Private admission state or native hook grant was exposed'; end if;
  set local role service_role;
  first:=public.st_v7_signup_admission(ordinary,'203.0.113.12');
  if first->>'status'<>'allow' then raise exception 'Ordinary email was challenged'; end if;
  if (public.st_v7_signup_admission(velocity,'192.0.2.90'))->>'status'<>'allow' then
    raise exception 'Ordinary first request for the velocity fixture was challenged'; end if;
  if (public.st_v7_signup_admission(velocity,'192.0.2.90'))->>'status'<>'challenge' then
    raise exception 'Repeated account signup did not require proof'; end if;
  flag:=public.st_v7_signup_admission(other,'198.51.100.72',repeat('a',48));
  if flag->>'status'<>'challenge' then raise exception 'Unmatched invite context was admitted silently'; end if;
  flag:=public.st_v7_signup_admission(elevated,'198.51.100.72');
  if flag->>'status'<>'challenge' then raise exception 'Automated-looking identifier was admitted silently'; end if;
  work:=flag->>'challenge';
  reset role;
  select n into answer from generate_series(0,249999) n
    cross join lateral (select extensions.digest('sectalk-signup-v1:'||work||':'||n,'sha256') as bytes) c
    where get_byte(c.bytes,0)=0 and get_byte(c.bytes,1)<4 limit 1;
  if answer is null then raise exception 'Fixture could not calculate a bounded nonce'; end if;

  set local role service_role;
  if (public.st_v7_signup_admission(other,'198.51.100.72',null,work,answer))->>'status'<>'invalid'
    or (public.st_v7_signup_admission(elevated,'192.0.2.12',null,work,answer))->>'status'<>'invalid' then
    raise exception 'Proof crossed challenge account or trusted network'; end if;
  flag:=public.st_v7_signup_admission(elevated,'198.51.100.73',null,work,answer);
  permit:=flag->>'permit';
  if flag->>'status'<>'allow' or permit is null then raise exception 'Real bounded proof was denied'; end if;
  if (public.st_v7_signup_admission(elevated,'198.51.100.73',null,work,answer))->>'status'<>'invalid' then
    raise exception 'Signup proof replayed'; end if;
  reset role;

  event:=jsonb_build_object('user',jsonb_build_object('email',elevated,'app_metadata',jsonb_build_object('provider','email'),
    'user_metadata',jsonb_build_object('sectalk_signup_gate',permit)));
  if not has_function_privilege('supabase_auth_admin','public.st_v7_before_signup(jsonb)','execute') then
    raise exception 'Native Auth cannot execute its restricted hook'; end if;
  if not public.st_v7_before_signup(jsonb_set(event,'{user,email}',to_jsonb(other))) ? 'error' then
    raise exception 'Native permit crossed its account scope'; end if;
  if public.st_v7_before_signup(event)<>'{}'::jsonb then raise exception 'Native hook rejected valid ticket'; end if;
  if not public.st_v7_before_signup(event) ? 'error' then raise exception 'Native hook accepted permit replay'; end if;
  insert into auth.users(id,email,raw_user_meta_data) values(gen_random_uuid(),other,jsonb_build_object('sectalk_signup_gate',permit,'test',true));
  if exists(select 1 from auth.users where email=other and raw_user_meta_data ? 'sectalk_signup_gate') then
    raise exception 'Native permit was retained in user metadata'; end if;
end $$;
rollback;
