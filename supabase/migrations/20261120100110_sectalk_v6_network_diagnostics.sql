begin;

create function public.st_v6_network_diagnostic_run()
returns boolean language plpgsql security definer set search_path = '' as $$
begin
  if auth.uid() is null or not sectalk_private.st_v2_active(auth.uid()) then return false; end if;
  perform sectalk_private.limit_action('v6_network_diagnostics', 3);
  return true;
end
$$;
revoke all on function public.st_v6_network_diagnostic_run() from public, anon, authenticated;
grant execute on function public.st_v6_network_diagnostic_run() to authenticated;

commit;
