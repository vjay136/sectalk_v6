begin;

create table sectalk_private.st_v7_signup_proofs (
  token_hash bytea primary key check(octet_length(token_hash)=32),
  email_key bytea not null,
  context_key bytea,
  kind text not null check(kind in ('work','permit')),
  expires_at timestamptz not null
);
create index on sectalk_private.st_v7_signup_proofs(expires_at);
alter table sectalk_private.st_v7_signup_proofs enable row level security;
revoke all on sectalk_private.st_v7_signup_proofs from public,anon,authenticated,service_role,supabase_auth_admin;

create function public.st_v7_signup_admission(
  p_email text,p_ip inet default null,p_invite text default null,
  p_challenge text default null,p_solution integer default null,p_resend boolean default false
) returns jsonb language plpgsql security definer set search_path='' as $$
declare
  address text:=lower(btrim(p_email));
  network text:=sectalk_private.st_v7_login_network(p_ip)::text;
  address_key bytea;
  network_key bytea;
  request_context bytea;
  network_capacity integer:=case when network is null then 200 else 12 end;
  dimensions jsonb;
  budget integer;
  need_work boolean;
  token text;
  answer bytea;
begin
  if address is null or length(address)>254 or address !~ '^[^@[:space:]]+@[^@[:space:]]+[.][^@[:space:]]+$'
    or p_invite is not null and p_invite !~ '^[a-f0-9]{48}$' or p_resend is null
    or (p_challenge is null)<>(p_solution is null) then return '{"status":"invalid"}'; end if;
  if sectalk_private.st_v7_domain_blocked(split_part(address,'@',2)) then return '{"status":"invalid"}'; end if;
  network:=coalesce(network,'trusted-network-unavailable');
  address_key:=sectalk_private.st_v7_rate_bucket('signup_address',address);
  network_key:=sectalk_private.st_v7_rate_bucket('network',network);
  request_context:=sectalk_private.st_v7_rate_bucket('signup_context',network||':'||coalesce(p_invite,''));
  dimensions:=jsonb_build_array(
    jsonb_build_object('dimension','signup_address','id',address,'capacity',5,'seconds',600),
    jsonb_build_object('dimension','network','id',network,'capacity',network_capacity,'seconds',60));

  if p_resend then
    budget:=sectalk_private.st_v7_rate_take('signup_resend',dimensions);
    return case when budget>0 then jsonb_build_object('status','limited','retry',budget) else '{"status":"allow"}' end;
  end if;

  if p_challenge is not null then
    if p_challenge !~ '^[a-f0-9]{64}$' or p_solution not between 0 and 249999 then return '{"status":"invalid"}'; end if;
    budget:=sectalk_private.st_v7_rate_take('signup_proof',dimensions);
    if budget>0 then return jsonb_build_object('status','limited','retry',budget); end if;
    answer:=extensions.digest('sectalk-signup-v1:'||p_challenge||':'||p_solution,'sha256');
    if get_byte(answer,0)<>0 or get_byte(answer,1)>=4 then return '{"status":"invalid"}'; end if;
    delete from sectalk_private.st_v7_signup_proofs as work
      where work.token_hash=extensions.digest(p_challenge,'sha256') and work.email_key=address_key
        and work.context_key=request_context and work.kind='work' and work.expires_at>clock_timestamp();
    if not found then return '{"status":"invalid"}'; end if;
  else
    budget:=sectalk_private.st_v7_rate_take('signup',dimensions);
    if budget>0 then return jsonb_build_object('status','limited','retry',budget); end if;
    need_work:=split_part(address,'@',1) ~ '[0-9]{6}'
      or exists(select 1 from sectalk_private.st_v7_rate_buckets b where b.action='signup'
        and ((b.dimension='signup_address' and b.bucket=address_key and b.tokens<=3.1)
          or (b.dimension='network' and b.bucket=network_key and b.tokens<=network_capacity-case when network_capacity=12 then 4 else 30 end)))
      or (p_invite is not null and not exists(
        select 1 from sectalk_private.st_v6_workspace_link_invites i
        where i.token_hash=extensions.digest(p_invite,'sha256') and i.email=address
          and i.consumed_at is null and i.expires_at>clock_timestamp()
          and sectalk_private.st_v6_link_domain_allowed(i.workspace_id,address)));
  end if;

  token:=encode(extensions.gen_random_bytes(32),'hex');
  insert into sectalk_private.st_v7_signup_proofs(token_hash,email_key,context_key,kind,expires_at)
    values(extensions.digest(token,'sha256'),address_key,case when need_work then request_context end,
      case when need_work then 'work' else 'permit' end,clock_timestamp()+interval '2 minutes');
  if need_work then return jsonb_build_object('status','challenge','challenge',token); end if;
  return jsonb_build_object('status','allow','permit',token);
end $$;

-- Configure this function as the native Before User Created hook on the public Auth ingress.
create function public.st_v7_before_signup(event jsonb)
returns jsonb language plpgsql security definer set search_path='' as $$
declare
  candidate text:=event->'user'->'user_metadata'->>'sectalk_signup_gate';
  address text:=lower(btrim(event->'user'->>'email'));
begin
  if event->'user'->'app_metadata'->>'provider' is distinct from 'email' then return '{}'; end if;
  if candidate ~ '^[a-f0-9]{64}$' and address is not null then
    delete from sectalk_private.st_v7_signup_proofs p where p.token_hash=extensions.digest(candidate,'sha256')
      and p.email_key=sectalk_private.st_v7_rate_bucket('signup_address',address)
      and p.kind='permit' and p.expires_at>clock_timestamp();
    if found then return '{}'; end if;
  end if;
  return '{"error":{"http_code":403,"message":"Complete signup in SecTalk."}}';
end $$;

create function sectalk_private.st_v7_scrub_signup_permit()
returns trigger language plpgsql security definer set search_path='' as $$
begin
  new.raw_user_meta_data:=new.raw_user_meta_data-'sectalk_signup_gate';
  return new;
end $$;
create trigger st_v7_scrub_signup_permit before insert or update of raw_user_meta_data on auth.users
  for each row when (new.raw_user_meta_data ? 'sectalk_signup_gate')
  execute function sectalk_private.st_v7_scrub_signup_permit();
create function sectalk_private.st_v7_scrub_signup_identity()
returns trigger language plpgsql security definer set search_path='' as $$
begin
  new.identity_data:=new.identity_data-'sectalk_signup_gate';
  return new;
end $$;
create trigger st_v7_scrub_signup_identity before insert or update of identity_data on auth.identities
  for each row when (new.identity_data ? 'sectalk_signup_gate')
  execute function sectalk_private.st_v7_scrub_signup_identity();
revoke all on function public.st_v7_signup_admission(text,inet,text,text,integer,boolean),public.st_v7_before_signup(jsonb),
  sectalk_private.st_v7_scrub_signup_permit(),sectalk_private.st_v7_scrub_signup_identity()
  from public,anon,authenticated,service_role,supabase_auth_admin;
grant execute on function public.st_v7_signup_admission(text,inet,text,text,integer,boolean) to service_role;
grant execute on function public.st_v7_before_signup(jsonb) to supabase_auth_admin;

select cron.schedule('sectalk-v7-prune-signup-proofs','*/5 * * * *',
  $job$delete from sectalk_private.st_v7_signup_proofs where expires_at<clock_timestamp()$job$);
commit;
