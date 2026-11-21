begin;

create table sectalk_private.st_v8_community_rules (
  version text primary key check(version ~ '^[a-z0-9][a-z0-9._-]{1,47}$'),
  effective_at timestamptz not null unique,
  title text not null check(char_length(btrim(title)) between 1 and 96),
  rules jsonb not null check(jsonb_typeof(rules)='array' and jsonb_array_length(rules) between 1 and 20
    and octet_length(rules::text)<=16000)
);
create table sectalk_private.st_v8_community_rules_acceptance (
  actor uuid not null references auth.users on delete cascade,
  version text not null references sectalk_private.st_v8_community_rules on delete restrict,
  accepted_at timestamptz not null default clock_timestamp(),
  primary key(actor,version)
);
alter table sectalk_private.st_v8_community_rules enable row level security;
alter table sectalk_private.st_v8_community_rules_acceptance enable row level security;
revoke all on sectalk_private.st_v8_community_rules,sectalk_private.st_v8_community_rules_acceptance
  from public,anon,authenticated,service_role;
create trigger st_v8_community_rules_immutable before update or delete on sectalk_private.st_v8_community_rules
  for each row execute function sectalk_private.st_v7_immutable_threat_audit();

create function public.st_v8_community_rules_check(p_accept_version text default null)
returns jsonb language plpgsql security definer set search_path='' as $$
declare actor_id uuid:=auth.uid(); policy sectalk_private.st_v8_community_rules; accepted boolean;
begin
  if actor_id is null or not coalesce(public.st_v7_current_session_valid(),false) then raise insufficient_privilege; end if;
  select r.* into policy from sectalk_private.st_v8_community_rules r
    where r.effective_at<=statement_timestamp() order by r.effective_at desc limit 1;
  if not found then return jsonb_build_object('required',false); end if;
  if exists(select 1 from jsonb_array_elements(policy.rules) item
    where jsonb_typeof(item) is distinct from 'string' or char_length(btrim(item#>>'{}')) not between 1 and 1400) then
    raise exception 'Community rules configuration is invalid' using errcode='PT503'; end if;
  if p_accept_version is not null then
    if p_accept_version<>policy.version then raise exception 'The community rules changed. Review the current version.' using errcode='PT409'; end if;
    insert into sectalk_private.st_v8_community_rules_acceptance(actor,version) values(actor_id,policy.version) on conflict do nothing;
  end if;
  select exists(select 1 from sectalk_private.st_v8_community_rules_acceptance a
    where (a.actor,a.version)=(actor_id,policy.version)) into accepted;
  if accepted then return jsonb_build_object('required',false,'version',policy.version); end if;
  return jsonb_build_object('required',true,'version',policy.version,'title',policy.title,'rules',policy.rules);
end $$;
revoke all on function public.st_v8_community_rules_check(text) from public,anon,authenticated,service_role;
grant execute on function public.st_v8_community_rules_check(text) to authenticated;
notify pgrst,'reload schema';
commit;
