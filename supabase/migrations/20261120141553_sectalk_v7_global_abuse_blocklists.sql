begin;

create table sectalk_private.st_v7_abuse_blocklist_operators (
  user_id uuid primary key references auth.users on delete cascade
);
create table sectalk_private.st_v7_abuse_blocks (
  id uuid primary key default gen_random_uuid(),
  kind text not null check(kind in ('domain','sha256','cidr')),
  value text not null,
  network cidr,
  created_by uuid not null,
  reason text not null check(char_length(reason) between 10 and 240),
  created_at timestamptz not null default clock_timestamp(),
  expires_at timestamptz not null,
  revoked_by uuid,
  revoked_at timestamptz,
  revocation_reason text check(char_length(revocation_reason) between 10 and 240),
  check((kind='cidr')=(network is not null)),
  check(expires_at>created_at),
  check((revoked_by is null)=(revoked_at is null) and (revoked_at is null)=(revocation_reason is null))
);
create index st_v7_abuse_rule_lookup on sectalk_private.st_v7_abuse_blocks(kind,value,expires_at) where revoked_at is null;
create index st_v7_abuse_network_lookup on sectalk_private.st_v7_abuse_blocks using gist(network inet_ops)
  where kind='cidr' and revoked_at is null;
create index st_v7_abuse_rule_history on sectalk_private.st_v7_abuse_blocks(created_at desc,id desc);
alter table sectalk_private.st_v7_abuse_blocklist_operators enable row level security;
alter table sectalk_private.st_v7_abuse_blocks enable row level security;
revoke all on sectalk_private.st_v7_abuse_blocklist_operators,sectalk_private.st_v7_abuse_blocks
  from public,anon,authenticated,service_role;

create function public.st_v7_abuse_blocklist_access()
returns text language sql stable security definer set search_path='' as $$
  select coalesce((select case when sectalk_private.st_v7_admin_fresh() then 'verified' else 'mfa' end
    from sectalk_private.st_v7_abuse_blocklist_operators o
    where o.user_id=auth.uid() and public.st_v7_current_session_valid() and sectalk_private.st_v2_active(o.user_id)),'none');
$$;

create function sectalk_private.st_v7_domain_blocked(p_host text)
returns boolean language sql stable set search_path='' as $$
  with labels as (select string_to_array(lower(rtrim(p_host,'.')),'.') as parts)
  select exists(select 1 from labels l cross join lateral generate_subscripts(l.parts,1) n
    join sectalk_private.st_v7_abuse_blocks b
      on b.kind='domain' and b.value=array_to_string(l.parts[n:cardinality(l.parts)],'.')
    where b.revoked_at is null and b.expires_at>statement_timestamp());
$$;

create function sectalk_private.st_v7_normalize_network_address(p_ip inet)
returns inet language sql immutable set search_path='' as $$
  select case when p_ip <<= inet '::ffff:0.0.0.0/96'
    then inet '0.0.0.0'+(p_ip-inet '::ffff:0.0.0.0') else p_ip end;
$$;

create function sectalk_private.st_v7_network_blocked(p_ip inet)
returns boolean language sql stable set search_path='' as $$
  select exists(select 1 from sectalk_private.st_v7_abuse_blocks b where b.kind='cidr'
    and b.revoked_at is null and b.expires_at>statement_timestamp()
    and b.network >>= sectalk_private.st_v7_normalize_network_address(p_ip));
$$;

create function public.st_v7_upload_digest_blocked(p_hash text)
returns boolean language sql stable security definer set search_path='' as $$
  select exists(select 1 from sectalk_private.st_v7_abuse_blocks b where b.kind='sha256' and b.value=p_hash
    and b.revoked_at is null and b.expires_at>statement_timestamp());
$$;

create function public.st_v7_abuse_blocks(p_kind text default 'all',p_state text default 'active',
  p_before timestamptz default null,p_before_id uuid default null)
returns table(id uuid,kind text,value text,reason text,created_by uuid,created_at timestamptz,
  expires_at timestamptz,revoked_by uuid,revoked_at timestamptz,revocation_reason text)
language plpgsql stable security definer set search_path='' as $$
begin
  if public.st_v7_abuse_blocklist_access()<>'verified' then
    raise exception 'Fresh operator verification required' using errcode='42501';
  end if;
  if p_kind is null or p_kind not in ('all','domain','sha256','cidr')
    or p_state is null or p_state not in ('all','active','closed')
    or (p_before is null)<>(p_before_id is null) then
    raise exception 'Invalid blocklist filter' using errcode='22023';
  end if;
  return query select b.id,b.kind,b.value,b.reason,b.created_by,b.created_at,b.expires_at,b.revoked_by,b.revoked_at,b.revocation_reason
    from sectalk_private.st_v7_abuse_blocks b where (p_kind='all' or b.kind=p_kind)
    and (p_state='all' or (p_state='active')=(b.revoked_at is null and b.expires_at>statement_timestamp()))
    and (p_before is null or (b.created_at,b.id)<(p_before,p_before_id))
    order by b.created_at desc,b.id desc limit 41;
end $$;

create function public.st_v7_add_abuse_block(p_kind text,p_value text,p_reason text,p_days integer)
returns uuid language plpgsql security definer set search_path='' as $$
declare actor_id uuid:=auth.uid(); normalized text; note text:=btrim(p_reason); range_value cidr;
  self_ip inet; rule_id uuid; stamp timestamptz;
begin
  if public.st_v7_abuse_blocklist_access()<>'verified' then
    raise exception 'Fresh operator verification required' using errcode='42501';
  end if;
  if p_kind is null or p_kind not in ('domain','sha256','cidr') or char_length(coalesce(p_value,'')) not between 1 and 255
    or note is null or char_length(note) not between 10 and 240 or p_days is null or p_days not between 1 and 30 then
    raise exception 'Enter an indicator, case reference and reason, and duration from 1 to 30 days' using errcode='22023';
  end if;
  normalized:=lower(btrim(p_value));
  if p_kind='domain' then
    normalized:=rtrim(normalized,'.');
    if char_length(normalized)>253 or normalized !~ '^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?([.][a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$'
      or normalized !~ '[.][a-z][a-z0-9-]*$' then
      raise exception 'Enter a domain name without a scheme, path or wildcard' using errcode='22023';
    end if;
  elsif p_kind='sha256' then
    if normalized !~ '^[0-9a-f]{64}$' then
      raise exception 'Enter a 64-character SHA-256 digest' using errcode='22023';
    end if;
  else
    begin
      if normalized !~ '^[0-9a-f:.]+/[0-9]{1,3}$' then raise invalid_text_representation; end if;
      range_value:=normalized::cidr;
    exception when invalid_text_representation then
      raise exception 'Enter a CIDR network with its prefix length and no host bits' using errcode='22023';
    end;
    if (family(range_value)=4 and masklen(range_value)<16)
      or (family(range_value)=6 and (masklen(range_value)<32 or range_value <<= inet '::ffff:0.0.0.0/96')) then
      raise exception 'Use IPv4 /16 or narrower, or native IPv6 /32 or narrower' using errcode='22023';
    end if;
    select sectalk_private.st_v7_normalize_network_address(s.ip) into self_ip from auth.sessions s
      where s.user_id=actor_id and s.id::text=auth.jwt()->>'session_id';
    if self_ip <<= range_value then
      raise exception 'This network includes your current session' using errcode='22023';
    end if;
    normalized:=range_value::text;
  end if;
  perform sectalk_private.limit_action('v7_global_abuse_blocklist',12);
  perform pg_advisory_xact_lock(hashtextextended('sectalk-global-abuse-blocklist',0));
  perform 1 from sectalk_private.st_v7_abuse_blocklist_operators o where o.user_id=actor_id for share;
  if not found then raise exception 'Operator access changed' using errcode='42501'; end if;
  stamp:=clock_timestamp();
  if exists(select 1 from sectalk_private.st_v7_abuse_blocks b where b.kind=p_kind and b.value=normalized
    and b.revoked_at is null and b.expires_at>stamp) then
    raise exception 'This indicator is already blocked' using errcode='PT409';
  end if;
  if (select count(*) from sectalk_private.st_v7_abuse_blocks b where b.kind=p_kind
      and b.revoked_at is null and b.expires_at>stamp)>=1000 then
    raise exception 'This blocklist has reached its active limit' using errcode='PT409';
  end if;
  insert into sectalk_private.st_v7_abuse_blocks(kind,value,network,created_by,reason,created_at,expires_at)
    values(p_kind,normalized,range_value,actor_id,note,stamp,stamp+make_interval(days=>p_days)) returning id into rule_id;
  return rule_id;
end $$;

create function public.st_v7_revoke_abuse_block(p_id uuid,p_reason text)
returns boolean language plpgsql security definer set search_path='' as $$
declare actor_id uuid:=auth.uid(); note text:=btrim(p_reason);
begin
  if public.st_v7_abuse_blocklist_access()<>'verified' then
    raise exception 'Fresh operator verification required' using errcode='42501';
  end if;
  if p_id is null or note is null or char_length(note) not between 10 and 240 then
    raise exception 'Enter the case reference and reason to release this block' using errcode='22023';
  end if;
  perform sectalk_private.limit_action('v7_global_abuse_blocklist',12);
  perform 1 from sectalk_private.st_v7_abuse_blocklist_operators o where o.user_id=actor_id for share;
  if not found then raise exception 'Operator access changed' using errcode='42501'; end if;
  update sectalk_private.st_v7_abuse_blocks b set revoked_by=actor_id,revoked_at=clock_timestamp(),revocation_reason=note
    where b.id=p_id and b.revoked_at is null and b.expires_at>statement_timestamp();
  return found;
end $$;

create function sectalk_private.st_v7_check_auth_network()
returns trigger language plpgsql security definer set search_path='' as $$
begin
  if sectalk_private.st_v7_network_blocked(new.ip) then
    raise exception 'This sign-in network is temporarily restricted' using errcode='42501';
  end if;
  return new;
end $$;
create trigger st_v7_check_auth_network before insert or update of ip,refreshed_at on auth.sessions
  for each row execute function sectalk_private.st_v7_check_auth_network();

create function sectalk_private.st_v7_webhook_host(p_destination text)
returns text language sql immutable set search_path='' as $$
  select substring(lower(p_destination) from '^https?://([a-z0-9.-]+)(?::[0-9]+)?(?:/|$)');
$$;

create function sectalk_private.st_v7_guard_webhook_domain()
returns trigger language plpgsql set search_path='' as $$
declare target_host text:=sectalk_private.st_v7_webhook_host(new.destination);
begin
  if target_host is null then raise exception 'Use a valid webhook hostname' using errcode='22023'; end if;
  if sectalk_private.st_v7_domain_blocked(target_host) then
    raise exception 'This webhook destination is unavailable under the platform abuse policy' using errcode='22023';
  end if;
  return new;
end $$;
create trigger st_v7_guard_webhook_domain before insert or update of destination on sectalk_private.st_v6_webhooks
  for each row execute function sectalk_private.st_v7_guard_webhook_domain();

create or replace function sectalk_private.st_v6_webhook_entitled(e sectalk_private.st_v6_webhooks)
returns boolean language sql stable set search_path='' as $$
  select e.revoked_at is null and not sectalk_private.st_v7_domain_blocked(sectalk_private.st_v7_webhook_host(e.destination))
    and exists(select 1 from public.st_v2_workspaces w
      where (w.id,w.owner)=(e.workspace_id,e.owner) and sectalk_private.st_v2_active(w.owner)
        and sectalk_private.st_v2_effective_plan(w.owner) in ('business','enterprise'));
$$;

create or replace function sectalk_private.st_v6_link_domain_allowed(p_workspace uuid,p_email text)
returns boolean language sql stable set search_path='' as $$
  select not sectalk_private.st_v7_domain_blocked(split_part(p_email,'@',2)) and case
    when coalesce(cardinality(lp.domains),0)>0 then split_part(p_email,'@',2)=any(lp.domains)
    else not coalesce(cp.require_domains,false)
  end
  from (values(p_workspace)) target(workspace_id)
  left join sectalk_private.st_v6_workspace_link_policy lp using(workspace_id)
  left join public.st_v6_workspace_policy wp using(workspace_id)
  left join public.st_v6_compliance_profiles cp on cp.id=wp.compliance_profile;
$$;

-- Keep existing service-only storage authorization and publication logic behind the live hash gate.
alter function public.st_v7_publish_hashed_file(uuid,uuid,text,text) set schema sectalk_private;
alter function public.st_v6_workspace_file_command(uuid,uuid,text,uuid,text,integer,text) set schema sectalk_private;
revoke all on function sectalk_private.st_v7_publish_hashed_file(uuid,uuid,text,text),
  sectalk_private.st_v6_workspace_file_command(uuid,uuid,text,uuid,text,integer,text)
  from public,anon,authenticated,service_role;

create function public.st_v7_publish_hashed_file(p_file uuid,p_actor uuid,p_caption text,p_hash text)
returns jsonb language plpgsql security definer set search_path='' as $$
begin
  if public.st_v7_upload_digest_blocked(p_hash) then
    raise exception 'The attachment was blocked by platform policy' using errcode='PT422';
  end if;
  return sectalk_private.st_v7_publish_hashed_file(p_file,p_actor,p_caption,p_hash);
end $$;

create function public.st_v6_workspace_file_command(p_workspace uuid,p_actor uuid,p_action text,p_id uuid,
  p_filename text,p_bytes integer,p_hash text)
returns jsonb language plpgsql security definer set search_path='' as $$
begin
  if p_action in ('reserve','publish') and public.st_v7_upload_digest_blocked(p_hash) then
    raise exception 'The workspace file was blocked by platform policy' using errcode='PT422';
  end if;
  return sectalk_private.st_v6_workspace_file_command(p_workspace,p_actor,p_action,p_id,p_filename,p_bytes,p_hash);
end $$;

revoke all on function sectalk_private.st_v7_domain_blocked(text),sectalk_private.st_v7_normalize_network_address(inet),
  sectalk_private.st_v7_network_blocked(inet),sectalk_private.st_v7_check_auth_network(),
  sectalk_private.st_v7_webhook_host(text),sectalk_private.st_v7_guard_webhook_domain(),
  public.st_v7_upload_digest_blocked(text),public.st_v7_abuse_blocklist_access(),
  public.st_v7_abuse_blocks(text,text,timestamptz,uuid),public.st_v7_add_abuse_block(text,text,text,integer),
  public.st_v7_revoke_abuse_block(uuid,text),public.st_v7_publish_hashed_file(uuid,uuid,text,text),
  public.st_v6_workspace_file_command(uuid,uuid,text,uuid,text,integer,text)
  from public,anon,authenticated,service_role;
grant execute on function public.st_v7_abuse_blocklist_access(),public.st_v7_abuse_blocks(text,text,timestamptz,uuid),
  public.st_v7_add_abuse_block(text,text,text,integer),public.st_v7_revoke_abuse_block(uuid,text) to authenticated;
grant execute on function public.st_v7_upload_digest_blocked(text),public.st_v7_publish_hashed_file(uuid,uuid,text,text),
  public.st_v6_workspace_file_command(uuid,uuid,text,uuid,text,integer,text) to service_role;

notify pgrst,'reload schema';
commit;
