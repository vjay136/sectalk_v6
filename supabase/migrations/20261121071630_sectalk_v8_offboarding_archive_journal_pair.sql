begin;

create index st_v8_retired_channel_posts_by_plan
  on sectalk_private.st_v8_offboarding_retired_channel_posts(plan,post);

create or replace function sectalk_private.st_v8_offboarding_has_archive_journal(p_source text,p_row jsonb)
returns boolean language sql stable set search_path='' as $$
  select case when p_row->>'id' ~ '^[0-9]{1,18}$' then
    (select count(*)=2
      and coalesce(bool_and(j.row_hash=sectalk_private.st_v6_audit_row_hash(p_row)),false)
      and coalesce(min(j.entry_no) filter(where j.operation='INSERT')<min(j.entry_no) filter(where j.operation='DELETE'),false)
      from sectalk_private.st_v6_audit_chain j
      where (j.source,j.source_id)=(p_source,(p_row->>'id')::bigint))
    else false end;
$$;

commit;
