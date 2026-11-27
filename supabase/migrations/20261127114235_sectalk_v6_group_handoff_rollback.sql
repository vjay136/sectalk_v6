begin;

create function public.st_v6_group_promotion_failed(p_call uuid,p_device uuid,p_generation integer)
returns boolean language plpgsql security definer set search_path='' as $$
declare
  actor_id uuid := auth.uid();
  session_key text := auth.jwt()->>'session_id';
  call_row sectalk_private.st_v6_group_call;
begin
  if actor_id is null or p_device is null or p_generation is null or nullif(session_key,'') is null
    or public.st_v7_current_session_valid() is not true
    or public.st_v7_step_up_pending() or public.st_v7_account_data_unavailable()
    or sectalk_private.st_v2_active(actor_id) is not true then return false; end if;

  select c.* into call_row
    from sectalk_private.st_v6_group_call c
    join sectalk_private.st_v6_group_member m on m.call_id=c.id and m.actor=actor_id
    where c.id=p_call and c.topology='promoting' and c.promotion=p_generation
      and not c.ended and c.expires_at>statement_timestamp()
      and m.state='joined' and m.device=p_device and m.auth_session=session_key
      and sectalk_private.open_pair(c.owner,actor_id)
      and sectalk_private.st_v2_active(c.owner) is true
    for update of c;
  if not found or not exists(select 1 from sectalk_private.st_v6_group_member m
    where m.call_id=p_call and m.actor=actor_id and m.state='joined' and m.device=p_device
      and m.auth_session=session_key and m.ready<>p_generation) then return false; end if;

  -- Existing mesh participants keep their devices, peers, and signaling state.
  update sectalk_private.st_v6_group_member set state='invited',device=null,auth_session=null
    where call_id=p_call and state='joined' and not(actor=any(call_row.mesh_roster));
  update sectalk_private.st_v6_group_call set topology='mesh',deadline=null where id=p_call;
  return true;
end $$;

revoke all on function public.st_v6_group_promotion_failed(uuid,uuid,integer) from public,anon,authenticated,service_role;
grant execute on function public.st_v6_group_promotion_failed(uuid,uuid,integer) to authenticated;
notify pgrst,'reload schema';
commit;
