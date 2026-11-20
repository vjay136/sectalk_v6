begin;

-- SEC-06. Preserve the existing sources and retention behavior. The journal
-- retains commitments to row contents, including rows removed by cascades.
create table sectalk_private.st_v6_audit_chain_head (
  singleton boolean primary key default true check (singleton),
  entry_no bigint not null check (entry_no >= 0),
  entry_hash bytea not null check (octet_length(entry_hash) = 32)
);

create table sectalk_private.st_v6_audit_chain (
  entry_no bigint primary key check (entry_no > 0),
  source text not null,
  source_id bigint not null,
  operation text not null check (operation in ('INSERT', 'UPDATE', 'DELETE')),
  row_hash bytea not null check (octet_length(row_hash) = 32),
  entry_hash bytea not null check (octet_length(entry_hash) = 32)
);
create index st_v6_audit_chain_source on sectalk_private.st_v6_audit_chain
  (source, source_id, entry_no desc) include (operation, row_hash);

create table sectalk_private.st_v6_audit_anchors (
  entry_no bigint primary key check (entry_no >= 0),
  entry_hash bytea not null check (octet_length(entry_hash) = 32),
  anchored_at timestamptz not null default clock_timestamp()
);

alter table sectalk_private.st_v6_audit_chain_head enable row level security;
alter table sectalk_private.st_v6_audit_chain enable row level security;
alter table sectalk_private.st_v6_audit_anchors enable row level security;
revoke all on sectalk_private.st_v6_audit_chain_head,
  sectalk_private.st_v6_audit_chain, sectalk_private.st_v6_audit_anchors
  from public, anon, authenticated, service_role;

insert into sectalk_private.st_v6_audit_chain_head(entry_no, entry_hash)
values (0, decode(repeat('00', 32), 'hex'));

create function sectalk_private.st_v6_audit_row_hash(p_row jsonb)
returns bytea language sql immutable strict set search_path = '' as $$
  select sha256(convert_to(p_row::text, 'UTF8'))
$$;

create function sectalk_private.st_v6_audit_entry_hash(
  p_previous bytea, p_entry bigint, p_source text, p_id bigint, p_operation text, p_row bytea
)
returns bytea language sql immutable strict set search_path = '' as $$
  select sha256(convert_to(jsonb_build_array('sectalk-audit-v1', encode(p_previous, 'hex'),
    p_entry, p_source, p_id, p_operation, encode(p_row, 'hex'))::text, 'UTF8'))
$$;

create function sectalk_private.st_v6_audit_append(
  p_source text, p_id bigint, p_operation text, p_row bytea, p_before bytea
)
returns void language plpgsql set search_path = '' as $$
declare
  head sectalk_private.st_v6_audit_chain_head%rowtype;
  previous sectalk_private.st_v6_audit_chain%rowtype;
  next_entry bigint;
  next_hash bytea;
begin
  select * into strict head from sectalk_private.st_v6_audit_chain_head
    where singleton for update;
  select * into previous from sectalk_private.st_v6_audit_chain
    where source = p_source and source_id = p_id order by entry_no desc limit 1;
  if (case when p_operation = 'INSERT'
       then previous.entry_no is not null and previous.operation <> 'DELETE'
       else previous.entry_no is null or previous.operation = 'DELETE'
         or previous.row_hash is distinct from p_before
     end)
  then
    raise exception 'SecTalk audit source history mismatch for %/%', p_source, p_id;
  end if;

  next_entry := head.entry_no + 1;
  next_hash := sectalk_private.st_v6_audit_entry_hash(head.entry_hash, next_entry,
    p_source, p_id, p_operation, p_row);
  insert into sectalk_private.st_v6_audit_chain
    (entry_no, source, source_id, operation, row_hash, entry_hash)
  values (next_entry, p_source, p_id, p_operation, p_row, next_hash);
  update sectalk_private.st_v6_audit_chain_head
    set entry_no = next_entry, entry_hash = next_hash where singleton;
end
$$;

create function sectalk_private.st_v6_audit_capture()
returns trigger language plpgsql security definer set search_path = ''
set timezone = 'UTC' set datestyle = 'ISO, YMD' as $$
declare
  before_hash bytea;
  row_hash bytea;
  row_id bigint;
begin
  if tg_op <> 'INSERT' then
    before_hash := sectalk_private.st_v6_audit_row_hash(to_jsonb(old));
  end if;
  if tg_op = 'DELETE' then
    row_id := old.id;
    row_hash := before_hash;
  else
    row_id := new.id;
    row_hash := sectalk_private.st_v6_audit_row_hash(to_jsonb(new));
  end if;
  if tg_op = 'UPDATE' and old.id is distinct from new.id then
    raise exception 'SecTalk audit source IDs are immutable';
  end if;
  perform sectalk_private.st_v6_audit_append(
    tg_table_schema || '.' || tg_table_name, row_id, tg_op, row_hash, before_hash);
  return null;
end
$$;

-- One snapshot covers all sources, journal entries and anchors. A receipt
-- retained independently can also be supplied to detect history rewrites.
create function sectalk_private.st_v6_audit_verify(
  p_receipt_no bigint default null, p_receipt_hash bytea default null
)
returns table(entry_no bigint, entry_hash bytea)
language plpgsql stable set search_path = ''
set timezone = 'UTC' set datestyle = 'ISO, YMD' as $$
declare
  genesis constant bytea := decode(repeat('00', 32), 'hex');
  first_bad bigint;
  head_no bigint;
  head_hash bytea;
begin
  select coalesce(c.entry_no, 0), coalesce(c.entry_hash, genesis)
    into head_no, head_hash
  from (select 1) as chain
    left join lateral (select j.entry_no, j.entry_hash from sectalk_private.st_v6_audit_chain j
      order by j.entry_no desc limit 1) c on true;

  if not exists (select 1 from sectalk_private.st_v6_audit_chain_head h
    where h.singleton and h.entry_no = head_no and h.entry_hash = head_hash)
  then
    raise exception 'SecTalk audit chain head mismatch';
  end if;

  select min(c.entry_no) into first_bad from (
    select j.*, lag(j.entry_no, 1, 0::bigint) over (order by j.entry_no) as previous_no,
      lag(j.entry_hash, 1, genesis) over (order by j.entry_no) as previous_hash
    from sectalk_private.st_v6_audit_chain j
  ) c
  where c.entry_no <> c.previous_no + 1
    or c.entry_hash <> sectalk_private.st_v6_audit_entry_hash(c.previous_hash,
      c.entry_no, c.source, c.source_id, c.operation, c.row_hash);
  if first_bad is not null then
    raise exception 'SecTalk audit chain mismatch at entry %', first_bad;
  end if;

  select min(a.entry_no) into first_bad
  from (
    select x.entry_no, x.entry_hash from sectalk_private.st_v6_audit_anchors x
    union all select p_receipt_no, p_receipt_hash where p_receipt_no is not null or p_receipt_hash is not null
  ) a
  left join sectalk_private.st_v6_audit_chain c on c.entry_no = a.entry_no
  where a.entry_hash is distinct from case when a.entry_no = 0 then genesis else c.entry_hash end
    or a.entry_no is null or a.entry_hash is null;
  if first_bad is not null or (p_receipt_no is null and p_receipt_hash is not null) then
    raise exception 'SecTalk audit anchor mismatch at entry %', first_bad;
  end if;

  if exists (
    with current_rows as (
      select 'sectalk_private.audit' as source, a.id, to_jsonb(a) as row_data from sectalk_private.audit a
      union all select 'public.st_v2_workspace_audit', a.id, to_jsonb(a) from public.st_v2_workspace_audit a
      union all select 'public.st_v6_room_audit', a.id, to_jsonb(a) from public.st_v6_room_audit a
      union all select 'public.st_v6_task_audit', a.id, to_jsonb(a) from public.st_v6_task_audit a
      union all select 'sectalk_private.st_v6_channel_audit', a.id, to_jsonb(a) from sectalk_private.st_v6_channel_audit a
      union all select 'sectalk_private.st_v6_flag_audit', a.id, to_jsonb(a) from sectalk_private.st_v6_flag_audit a
    ), latest as (
      select distinct on (c.source, c.source_id) c.source, c.source_id, c.row_hash, c.operation
      from sectalk_private.st_v6_audit_chain c order by c.source, c.source_id, c.entry_no desc
    )
    select 1 from current_rows r full join (select * from latest where operation <> 'DELETE') j
      on r.source = j.source and r.id = j.source_id
    where sectalk_private.st_v6_audit_row_hash(r.row_data) is distinct from j.row_hash
  ) then
    raise exception 'SecTalk audit source rows do not match the journal';
  end if;

  return query select head_no, head_hash;
end
$$;

create function sectalk_private.st_v6_audit_anchor()
returns void language plpgsql set search_path = '' as $$
declare
  verified record;
begin
  insert into sectalk_private.st_v6_audit_anchors(entry_no, entry_hash)
    select * from sectalk_private.st_v6_audit_verify()
    on conflict (entry_no) do nothing
    returning entry_no, entry_hash into verified;
  if found then
    -- Forward these digest-only receipts to independently retained log
    -- storage to cover compromise of this database and its local anchors.
    raise log 'SecTalk audit anchor v1 database=% entry=% sha256=%',
      current_database(), verified.entry_no, encode(verified.entry_hash, 'hex');
  end if;
end
$$;

revoke execute on function sectalk_private.st_v6_audit_row_hash(jsonb),
  sectalk_private.st_v6_audit_entry_hash(bytea, bigint, text, bigint, text, bytea),
  sectalk_private.st_v6_audit_append(text, bigint, text, bytea, bytea),
  sectalk_private.st_v6_audit_capture(),
  sectalk_private.st_v6_audit_verify(bigint, bytea),
  sectalk_private.st_v6_audit_anchor() from public, anon, authenticated, service_role;

-- Lock all audited sources through backfill and trigger installation. Legacy
-- rows establish the first baseline in source/ID order.
do $$
declare
  source text;
  audit_row record;
begin
  perform set_config('TimeZone', 'UTC', true);
  perform set_config('DateStyle', 'ISO, YMD', true);
  lock table sectalk_private.audit, public.st_v2_workspace_audit,
    public.st_v6_room_audit, public.st_v6_task_audit, sectalk_private.st_v6_channel_audit,
    sectalk_private.st_v6_flag_audit
    in share row exclusive mode;
  foreach source in array array[
    'sectalk_private.audit', 'public.st_v2_workspace_audit', 'public.st_v6_room_audit',
    'public.st_v6_task_audit', 'sectalk_private.st_v6_channel_audit', 'sectalk_private.st_v6_flag_audit'
  ] loop
    for audit_row in execute format('select a.id, to_jsonb(a) as row_data from %s a order by a.id',
      source::regclass)
    loop
      perform sectalk_private.st_v6_audit_append(source, audit_row.id, 'INSERT',
        sectalk_private.st_v6_audit_row_hash(audit_row.row_data), null);
    end loop;
    execute format('create trigger st_v6_audit_capture after insert or update or delete on %s
      for each row execute function sectalk_private.st_v6_audit_capture()', source::regclass);
  end loop;
end
$$;

select sectalk_private.st_v6_audit_anchor();
select cron.schedule('sectalk-v6-audit-verify-and-anchor', '17 * * * *',
  'select sectalk_private.st_v6_audit_anchor()');

commit;
