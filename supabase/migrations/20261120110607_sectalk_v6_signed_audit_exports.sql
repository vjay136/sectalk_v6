begin;

create function public.st_v6_audit_integrity_status(p_workspace uuid,p_rows jsonb)
returns jsonb language plpgsql stable security definer set search_path=''
set timezone='UTC' set datestyle='ISO, YMD' as $$
declare requested jsonb;
declare source_table text;
declare source_ref bigint;
declare current_hash bytea;
declare matched boolean:=true;
declare anchored timestamptz;
begin
  if not coalesce(sectalk_private.st_v2_role(p_workspace,auth.uid()) in ('owner','admin'),false)
    or sectalk_private.st_v2_active(auth.uid()) is not true
  then raise exception 'Workspace audit verification is unavailable' using errcode='42501'; end if;
  if p_rows is null or jsonb_typeof(p_rows)<>'array' or jsonb_array_length(p_rows)>100
  then raise exception 'Choose a valid audit result set' using errcode='22023'; end if;
  for requested in select value from jsonb_array_elements(p_rows)
  loop
    if requested->>'source' not in ('workspace','room') or requested->>'source' is null
      or coalesce(requested->>'id','')!~'^[0-9]{1,18}$' then
      raise exception 'Choose valid audit references' using errcode='22023';
    end if;
    source_ref:=(requested->>'id')::bigint;
    if requested->>'source'='workspace' then
      source_table:='public.st_v2_workspace_audit';
      select sectalk_private.st_v6_audit_row_hash(to_jsonb(a)) into current_hash
      from public.st_v2_workspace_audit a where a.workspace_id=p_workspace and a.id=source_ref;
    else
      source_table:='public.st_v6_room_audit';
      select sectalk_private.st_v6_audit_row_hash(to_jsonb(a)) into current_hash
      from public.st_v6_room_audit a join public.st_v6_rooms r on r.id=a.room_id
      where r.workspace_id=p_workspace and a.id=source_ref
        and sectalk_private.st_v6_room_role(a.room_id) in ('owner','moderator');
    end if;
    if current_hash is null or not exists(
      select 1 from (
        select c.row_hash,c.operation from sectalk_private.st_v6_audit_chain c
        where c.source=source_table and c.source_id=source_ref order by c.entry_no desc limit 1
      ) proof where proof.row_hash=current_hash and proof.operation<>'DELETE'
    ) then matched:=false; exit; end if;
  end loop;
  select max(a.anchored_at) into anchored from sectalk_private.st_v6_audit_anchors a;
  return jsonb_build_object('state',case
    when jsonb_array_length(p_rows)=0 then 'empty' when matched then 'matched' else 'unavailable' end,
    'last_local_checkpoint',anchored,'can_export',sectalk_private.st_v6_holds_access(p_workspace)='verified');
end $$;

create function public.st_v6_record_audit_export(p_workspace uuid)
returns void language plpgsql security definer set search_path='' as $$
begin
  if sectalk_private.st_v6_holds_access(p_workspace)<>'verified' then
    raise exception 'Verified workspace audit export access is required' using errcode='42501';
  end if;
  perform sectalk_private.limit_action('v6_audit_export',10);
  insert into public.st_v2_workspace_audit(workspace_id,actor,event)
    values(p_workspace,auth.uid(),'workspace.audit_export_requested');
end $$;

revoke all on function public.st_v6_audit_integrity_status(uuid,jsonb),public.st_v6_record_audit_export(uuid)
  from public,anon,authenticated;
grant execute on function public.st_v6_audit_integrity_status(uuid,jsonb),public.st_v6_record_audit_export(uuid) to authenticated;

commit;
