begin;

create function public.st_v8_signup_service_ready()
returns boolean language sql stable security invoker set search_path='' as $$
  select current_user='service_role'
    and has_function_privilege(current_user,
      'public.st_v7_signup_admission(text,inet,text,text,integer,boolean)', 'EXECUTE')
    and has_function_privilege(current_user,
      'public.st_v8_consume_password_signup_permit(text,text)', 'EXECUTE');
$$;
revoke all on function public.st_v8_signup_service_ready() from public,anon,authenticated,service_role;
grant execute on function public.st_v8_signup_service_ready() to service_role;

notify pgrst,'reload schema';
commit;
