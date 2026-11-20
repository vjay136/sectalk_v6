create extension if not exists pgcrypto with schema extensions;

create table sectalk_private.account_recovery_sets (
  user_id uuid primary key references auth.users(id) on delete cascade,
  factor_id uuid not null references auth.mfa_factors(id) on delete cascade,
  generated_at timestamptz not null,
  code_hashes bytea[] not null check (cardinality(code_hashes) = 8)
);

alter table sectalk_private.account_recovery_sets enable row level security;
revoke all on sectalk_private.account_recovery_sets from public,anon,authenticated;

create table sectalk_private.account_recovery_events (
  id bigint generated always as identity primary key,
  user_id uuid not null references auth.users(id) on delete cascade,
  recovered_at timestamptz not null default now()
);

alter table sectalk_private.account_recovery_events enable row level security;
revoke all on sectalk_private.account_recovery_events from public,anon,authenticated;

create function public.st_v7_account_recovery_status()
returns text language sql stable security definer set search_path='' as $$
  select case
    when exists(select 1 from sectalk_private.staff where user_id=auth.uid()) then 'staff'
    when exists(select 1 from sectalk_private.account_recovery_sets where user_id=auth.uid()) then 'ready'
    else 'missing'
  end;
$$;

create function public.st_v7_generate_recovery_codes()
returns text[] language plpgsql security definer set search_path='' as $$
declare
  actor uuid := auth.uid();
  claimant_session uuid := (auth.jwt()->>'session_id')::uuid;
  factor uuid;
  verified_at timestamptz;
  previous_generation timestamptz;
  code text;
  codes text[] := '{}';
  hashes bytea[] := '{}';
begin
  if actor is null or auth.jwt()->>'aal' is distinct from 'aal2' then
    raise exception 'Verify your authenticator before generating recovery codes' using errcode='42501';
  end if;
  perform 1 from public.st_profiles p where p.id=actor for update;
  if exists(select 1 from sectalk_private.staff where user_id=actor) then
    raise exception 'Staff authenticator recovery requires administrator assistance' using errcode='42501';
  end if;

  select f.id into factor from auth.mfa_factors f
    where f.user_id=actor and f.status='verified' and f.factor_type='totp'
      and f.id=(select s.factor_id from auth.sessions s where s.id=claimant_session and s.user_id=actor)
    for update;
  if factor is null or (select count(*) from auth.mfa_factors f where f.user_id=actor and f.status='verified')<>1 then
    raise exception 'Recovery codes require exactly one verified authenticator' using errcode='42501';
  end if;

  select a.updated_at into verified_at
    from auth.sessions s join auth.mfa_amr_claims a on a.session_id=s.id
    where s.id=claimant_session and s.user_id=actor and s.aal='aal2' and s.factor_id=factor
      and (s.not_after is null or s.not_after>now()) and a.authentication_method='totp';
  select r.generated_at into previous_generation from sectalk_private.account_recovery_sets r where r.user_id=actor;
  if verified_at is null or verified_at<clock_timestamp()-interval '5 minutes'
      or verified_at<=previous_generation then
    raise exception 'Enter a fresh authenticator code to generate recovery codes' using errcode='42501';
  end if;

  for i in 1..8 loop
    code := upper(encode(extensions.gen_random_bytes(16),'hex'));
    hashes := array_append(hashes,extensions.digest(code,'sha256'));
    codes := array_append(codes,regexp_replace(code,'(.{8})(?=.)','\1-','g'));
  end loop;

  insert into sectalk_private.account_recovery_sets(user_id,factor_id,generated_at,code_hashes)
    values(actor,factor,clock_timestamp(),hashes)
    on conflict(user_id) do update set
      factor_id=excluded.factor_id,generated_at=excluded.generated_at,code_hashes=excluded.code_hashes;
  return codes;
end;
$$;

create function public.st_v7_recover_authenticator(p_code text)
returns boolean language plpgsql security definer set search_path='' as $$
declare
  actor uuid := auth.uid();
  claimant_session uuid := (auth.jwt()->>'session_id')::uuid;
  factor uuid;
  normalized text;
begin
  if actor is null or auth.jwt()->>'aal' is distinct from 'aal1' then
    return false;
  end if;
  perform 1 from public.st_profiles p where p.id=actor for update;
  if exists(select 1 from sectalk_private.staff where user_id=actor) then
    return false;
  end if;
  perform sectalk_private.limit_action('account_authenticator_recovery',5);

  if not exists (
    select 1 from auth.sessions s join auth.mfa_amr_claims a on a.session_id=s.id
    where s.id=claimant_session and s.user_id=actor and coalesce(s.aal,'aal1')='aal1'
      and (s.not_after is null or s.not_after>now()) and a.authentication_method='password'
      and a.updated_at>now()-interval '10 minutes'
  ) then
    return false;
  end if;
  if p_code is null or length(p_code)>64 then return false; end if;
  normalized := upper(regexp_replace(p_code,'[[:space:]-]','','g'));
  if normalized !~ '^[0-9A-F]{32}$' then return false; end if;

  -- Lock the factor before touching its dependent recovery set, as generation does.
  select f.id into factor from auth.mfa_factors f
    join sectalk_private.account_recovery_sets r on r.factor_id=f.id and r.user_id=actor
    where f.user_id=actor and f.status='verified' and f.factor_type='totp'
    for update of f;
  if factor is null or (select count(*) from auth.mfa_factors f where f.user_id=actor and f.status='verified')<>1 then
    return false;
  end if;

  delete from sectalk_private.account_recovery_sets r
    where r.user_id=actor and r.factor_id=factor and extensions.digest(normalized,'sha256')=any(r.code_hashes);
  if not found then return false; end if;

  -- Reset the lost authenticator and all outstanding setup attempts. The same
  -- transaction invalidates the whole code batch and ends existing sessions.
  delete from auth.mfa_factors f where f.user_id=actor and f.factor_type='totp';
  delete from auth.sessions s where s.user_id=actor;
  insert into sectalk_private.account_recovery_events(user_id) values(actor);
  return true;
end;
$$;

revoke all on function public.st_v7_account_recovery_status(),public.st_v7_generate_recovery_codes(),
  public.st_v7_recover_authenticator(text) from public,anon,authenticated;
grant execute on function public.st_v7_account_recovery_status(),public.st_v7_generate_recovery_codes(),
  public.st_v7_recover_authenticator(text) to authenticated;
