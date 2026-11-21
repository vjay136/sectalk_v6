begin;

create function public.st_v8_release_ready(p_surface text)
returns boolean language sql stable security invoker set search_path='' as $$
  select public.st_v6_ready() and case p_surface
    when 'web' then
      to_regprocedure('public.st_v7_signup_admission(text,inet,text,text,integer,boolean)') is not null and
      to_regprocedure('public.st_v8_consume_password_signup_permit(text,text)') is not null
    when 'admin' then
      to_regprocedure('public.st_v7_account_operator_access()') is not null and
      to_regprocedure('public.st_v6_operational_report_settings()') is not null and
      to_regprocedure('public.st_v8_disclosure_access()') is not null and
      exists(select 1 from pg_catalog.pg_class c join pg_catalog.pg_namespace n on n.oid=c.relnamespace
        where n.nspname='sectalk_private' and c.relname='st_v8_operator_provisioning_audit' and c.relrowsecurity)
    when 'workers' then
      to_regprocedure('public.st_v6_claim_webhooks()') is not null and
      to_regprocedure('public.st_v6_claim_notification_email(uuid)') is not null and
      to_regprocedure('public.st_v8_due_tenant_key_rotations()') is not null
    else false
  end
$$;
revoke all on function public.st_v8_release_ready(text) from public,anon,authenticated,service_role;
grant execute on function public.st_v8_release_ready(text) to anon,authenticated;

notify pgrst,'reload schema';
commit;
