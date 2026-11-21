begin;

create function sectalk_private.st_v8_run_offboarding_root_rehearsal(
  p_workspace uuid,p_confirmation text,p_reconciliation uuid,p_sha256 text
) returns jsonb language plpgsql security definer set search_path='' set lock_timeout='1s' as $$
begin
  if auth.uid() is null or sectalk_private.st_v8_offboarding_role(p_workspace,auth.uid()) is distinct from 'owner'
    or not coalesce(sectalk_private.st_v7_billing_admin_session(),false) then
    raise insufficient_privilege;
  end if;
  perform sectalk_private.limit_action('v8_offboarding_root_rehearsal',4);
  return sectalk_private.st_v8_offboarding_root_rehearse(p_workspace,p_confirmation,p_reconciliation,p_sha256);
end $$;

-- Resolve the internal function at definition time. Its schema stays private and this API runs as the caller.
create function public.st_v8_offboarding_root_rehearsal(
  p_workspace uuid,p_confirmation text,p_reconciliation uuid,p_sha256 text
) returns jsonb language sql security invoker set search_path=''
begin atomic
  select sectalk_private.st_v8_run_offboarding_root_rehearsal(p_workspace,p_confirmation,p_reconciliation,p_sha256);
end;

revoke all on function sectalk_private.st_v8_run_offboarding_root_rehearsal(uuid,text,uuid,text),
  public.st_v8_offboarding_root_rehearsal(uuid,text,uuid,text) from public,anon,authenticated,service_role;
grant execute on function sectalk_private.st_v8_run_offboarding_root_rehearsal(uuid,text,uuid,text),
  public.st_v8_offboarding_root_rehearsal(uuid,text,uuid,text) to authenticated;

commit;
