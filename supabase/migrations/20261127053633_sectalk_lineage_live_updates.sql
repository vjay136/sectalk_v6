begin;

create index st_forward_lineage_root_scope
  on sectalk_private.st_forward_lineage(root_id,scope_id) where root_id is not null and kind='direct';

create function sectalk_private.st_signal_forward_lineage(p_root uuid,p_new_scope uuid)
returns void language plpgsql set search_path='' as $$
declare
  member_record record;
begin
  for member_record in
    with scopes as (
      select n.scope_id from sectalk_private.st_forward_lineage n where n.id=p_root and n.kind='direct'
      union
      select n.scope_id from sectalk_private.st_forward_lineage n where n.root_id=p_root and n.kind='direct'
    ), active_scopes as (
      select s.scope_id from scopes s
      order by (s.scope_id is not distinct from p_new_scope) desc,s.scope_id
      limit 32
    )
    select c.id as chat_id, participant.id as account
    from active_scopes s join public.st_chats c on c.id=s.scope_id
    cross join lateral (values(c.member_a),(c.member_b)) participant(id)
    where c.status='accepted'
  loop
    perform realtime.send(jsonb_build_object('chat_id',member_record.chat_id),
      'forward_lineage','st:account:'||member_record.account::text,true);
  end loop;
end;
$$;

create function sectalk_private.st_emit_forward_copy()
returns trigger language plpgsql security definer set search_path='' as $$
begin
  perform sectalk_private.st_signal_forward_lineage(new.root_id,new.scope_id);
  return new;
end;
$$;
create trigger st_forward_lineage_copy_after_insert after insert on sectalk_private.st_forward_lineage
  for each row when(new.kind='direct' and new.root_id is not null)
  execute function sectalk_private.st_emit_forward_copy();

create function sectalk_private.st_emit_advisory_change()
returns trigger language plpgsql security definer set search_path='' as $$
begin
  perform sectalk_private.st_signal_forward_lineage(coalesce(new.root,old.root),null);
  return null;
end;
$$;
create trigger st_message_advisory_after_change after insert or update or delete on sectalk_private.st_message_advisories
  for each row execute function sectalk_private.st_emit_advisory_change();

create function sectalk_private.st_emit_report_marker()
returns trigger language plpgsql security definer set search_path='' as $$
declare
  owner_record record;
begin
  select r.chat_id,r.reporter into owner_record from public.st_reports r where r.id=new.report;
  if found then
    perform realtime.send(jsonb_build_object('chat_id',owner_record.chat_id),
      'forward_lineage','st:account:'||owner_record.reporter::text,true);
  end if;
  return new;
end;
$$;
create trigger st_report_lineage_marker_after_insert after insert on sectalk_private.st_report_lineage
  for each row execute function sectalk_private.st_emit_report_marker();

revoke all on function sectalk_private.st_signal_forward_lineage(uuid,uuid),
  sectalk_private.st_emit_forward_copy(),sectalk_private.st_emit_advisory_change(),
  sectalk_private.st_emit_report_marker() from public,anon,authenticated,service_role;
commit;
