begin;

create function sectalk_private.st_v8_guard_residency_history_link()
returns trigger language plpgsql security invoker set search_path='' as $$
declare workspace_id uuid;
begin
  if current_setting('transaction_isolation') not in ('read committed','read uncommitted') then
    raise exception 'Regional history link changes require a fresh database snapshot.' using errcode='25000';
  end if;
  if tg_op='UPDATE' and new.workspace is distinct from old.workspace then
    raise exception 'A regional history link cannot change workspace.' using errcode='23514';
  end if;
  workspace_id:=case when tg_op='DELETE' then old.workspace else new.workspace end;
  -- Native root removal holds the same workspace lock through its last census and receipt.
  if not pg_try_advisory_xact_lock(hashtextextended('sectalk-workspace-hold:'||workspace_id::text,0)) then
    raise exception 'Workspace preservation or offboarding is in progress. Retry the link change.'
      using errcode='55P03';
  end if;
  if tg_op='DELETE' then return old; end if;
  if exists(select 1 from sectalk_private.st_v8_offboarding_native_root_receipts r where r.workspace=workspace_id) then
    raise exception 'The workspace has an existing native removal receipt.' using errcode='PT409';
  end if;
  return new;
end $$;

create function sectalk_private.st_v8_guard_native_root_receipt_snapshot()
returns trigger language plpgsql security invoker set search_path='' as $$
begin
  if current_setting('transaction_isolation') not in ('read committed','read uncommitted') then
    raise exception 'Native root removal requires a fresh database snapshot.' using errcode='25000';
  end if;
  return new;
end $$;

revoke all on function sectalk_private.st_v8_guard_residency_history_link(),
  sectalk_private.st_v8_guard_native_root_receipt_snapshot() from public,anon,authenticated,service_role;

create trigger st_v8_guard_residency_history_link before insert or update or delete
  on sectalk_private.st_v8_residency_history_links
  for each row execute function sectalk_private.st_v8_guard_residency_history_link();
create trigger st_v8_guard_native_root_receipt_snapshot before insert
  on sectalk_private.st_v8_offboarding_native_root_receipts
  for each row execute function sectalk_private.st_v8_guard_native_root_receipt_snapshot();

commit;
