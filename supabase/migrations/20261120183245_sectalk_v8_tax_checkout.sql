begin;
create table sectalk_private.st_v8_tax_profiles (
  account uuid primary key references auth.users on delete cascade,
  revision uuid not null default gen_random_uuid(),
  details jsonb not null,
  updated_at timestamptz not null default now()
);
create table sectalk_private.st_v8_tax_checkout_quotes (
  id uuid primary key default gen_random_uuid(),
  account uuid not null references auth.users on delete cascade,
  profile_revision uuid not null,
  price text not null,
  details jsonb not null,
  expires_at timestamptz not null default now()+interval '10 minutes',
  checkout uuid unique,
  created_at timestamptz not null default now()
);
create index on sectalk_private.st_v8_tax_checkout_quotes(account,expires_at);
alter table sectalk_private.st_v8_tax_profiles enable row level security;
alter table sectalk_private.st_v8_tax_checkout_quotes enable row level security;
revoke all on sectalk_private.st_v8_tax_profiles,sectalk_private.st_v8_tax_checkout_quotes from public,anon,authenticated,service_role;

create function public.st_v8_tax_checkout(p_account uuid,p_action text,p_data jsonb default null)
returns jsonb language plpgsql security definer set search_path='' as $$
declare profile sectalk_private.st_v8_tax_profiles; quote sectalk_private.st_v8_tax_checkout_quotes; lease uuid;
begin
  if not sectalk_private.st_v2_active(p_account) then return null; end if;
  if p_action='profile' then
    select * into profile from sectalk_private.st_v8_tax_profiles where account=p_account;
    if not found then return null; end if;
    return jsonb_build_object('revision',profile.revision,'details',profile.details);
  end if;
  perform pg_advisory_xact_lock(hashtextextended('coupon-checkout:'||p_account::text,0));
  if p_action='save' then
    insert into sectalk_private.st_v8_tax_profiles as p(account,details) values(p_account,p_data)
      on conflict(account) do update set details=excluded.details,revision=case when p.details=excluded.details then p.revision
        else gen_random_uuid() end,updated_at=now() returning * into profile;
    return jsonb_build_object('revision',profile.revision,'details',profile.details);
  elsif p_action='quote' then
    select * into profile from sectalk_private.st_v8_tax_profiles where account=p_account and revision=(p_data->>'revision')::uuid;
    if not found then return null; end if;
    insert into sectalk_private.st_v8_tax_checkout_quotes(account,profile_revision,price,details)
      values(p_account,profile.revision,p_data->>'price',p_data->'estimate') returning * into quote;
    return jsonb_build_object('id',quote.id,'expires_at',quote.expires_at);
  elsif p_action='validate' or p_action='attach' then
    select * into quote from sectalk_private.st_v8_tax_checkout_quotes q where q.account=p_account and q.id=(p_data->>'id')::uuid
      and q.price=p_data->>'price' and (q.checkout is not null or q.expires_at>now());
    if not found then return null; end if;
    select * into profile from sectalk_private.st_v8_tax_profiles where account=p_account and revision=quote.profile_revision;
    if not found then return null; end if;
    if p_action='attach' then
      select id into lease from sectalk_private.st_v2_checkout where user_id=p_account and id=(p_data->>'checkout')::uuid
        and price=quote.price and expires>now();
      if lease is null or (quote.checkout is not null and quote.checkout<>lease) or exists(
        select 1 from sectalk_private.st_v8_tax_checkout_quotes where checkout=lease and id<>quote.id) then return null; end if;
      update sectalk_private.st_v8_tax_checkout_quotes set checkout=lease where id=quote.id;
    end if;
    return jsonb_build_object('id',quote.id,'profile',profile.details,'estimate',quote.details);
  end if;
  return null;
end $$;
revoke all on function public.st_v8_tax_checkout(uuid,text,jsonb) from public,anon,authenticated,service_role;
grant execute on function public.st_v8_tax_checkout(uuid,text,jsonb) to service_role;
commit;
