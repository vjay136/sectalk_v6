begin;

create function public.st_v6_group_call_ice(p_call uuid, p_device uuid)
returns jsonb language plpgsql security definer set search_path='' as $$
begin
  perform sectalk_private.limit_action('v6_group_call_ice', 12);
  return public.st_v6_group_call(p_action=>'ice', p_call=>p_call, p_device=>p_device);
end;
$$;

revoke all on function public.st_v6_group_call_ice(uuid, uuid) from public, anon, authenticated, service_role;
grant execute on function public.st_v6_group_call_ice(uuid, uuid) to authenticated;

commit;
