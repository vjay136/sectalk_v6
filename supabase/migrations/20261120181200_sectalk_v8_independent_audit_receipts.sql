begin;

do $$
begin
  if not exists (select 1 from pg_roles where rolname='sectalk_audit_anchor_reader') then
    create role sectalk_audit_anchor_reader nologin;
  end if;
end;
$$;

create function sectalk_private.st_v8_audit_checkpoint(p_entry text default null,p_digest text default null)
returns jsonb language plpgsql stable security definer set search_path='' as $$
declare verified record;
begin
  if (p_entry is null)<>(p_digest is null) or
    (p_entry is not null and (p_entry !~ '^(0|[1-9][0-9]{0,18})$' or p_digest !~ '^[a-f0-9]{64}$')) then
    raise exception using errcode='22023',message='Invalid audit receipt';
  end if;
  select * into strict verified from sectalk_private.st_v6_audit_verify(p_entry::bigint,decode(p_digest,'hex'));
  return jsonb_build_object('entry',verified.entry_no::text,'sha256',encode(verified.entry_hash,'hex'));
end;
$$;

revoke all on function sectalk_private.st_v8_audit_checkpoint(text,text) from public,anon,authenticated,service_role;
grant usage on schema sectalk_private to sectalk_audit_anchor_reader;
grant execute on function sectalk_private.st_v8_audit_checkpoint(text,text) to sectalk_audit_anchor_reader;

commit;
