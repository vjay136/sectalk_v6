begin;

-- Keep immutable audit attribution when a profile is removed. A live profile
-- is still required to create a new attributed audit event.
create table sectalk_private.st_v8_workspace_audit_actors (
  actor uuid primary key
);
alter table sectalk_private.st_v8_workspace_audit_actors enable row level security;
revoke all on sectalk_private.st_v8_workspace_audit_actors from public,anon,authenticated,service_role;
create trigger st_v8_workspace_audit_actors_immutable before update or delete
  on sectalk_private.st_v8_workspace_audit_actors
  for each row execute function sectalk_private.st_v7_immutable_threat_audit();

lock table public.st_v2_workspaces,sectalk_private.st_v8_offboarding_requests,public.st_v2_workspace_audit
  in share row exclusive mode;
insert into sectalk_private.st_v8_workspace_audit_actors(actor)
  select distinct a.actor from public.st_v2_workspace_audit a;
alter table public.st_v2_workspace_audit
  add constraint st_v8_workspace_audit_retained_actor_fkey foreign key(actor)
    references sectalk_private.st_v8_workspace_audit_actors(actor) on delete restrict,
  drop constraint st_v2_workspace_audit_actor_fkey;

create function sectalk_private.st_v8_workspace_audit_profile_reuse()
returns trigger language plpgsql security definer set search_path='' as $$
begin
  if tg_op='UPDATE' and new.id=old.id then return new; end if;
  if exists(select 1 from sectalk_private.st_v8_workspace_audit_actors a where a.actor=new.id) then
    perform 1 from public.st_profiles p where p.id=new.id for key share;
    if not found then raise exception 'This profile identifier is reserved by retained audit' using errcode='PT409'; end if;
  end if;
  return new;
end $$;
create trigger st_v8_workspace_audit_profile_reuse before insert or update of id on public.st_profiles
  for each row execute function sectalk_private.st_v8_workspace_audit_profile_reuse();

-- Ordinary root removal retains audit through its permanent attribution key.
-- Only the reviewed native offboarding lifecycle requires the live restriction.
update sectalk_private.st_v8_workspace_audit_custody a set live_workspace=null
  where a.live_workspace is not null and not exists(select 1 from sectalk_private.st_v8_offboarding_requests r
    where r.workspace=a.workspace and r.state='read_only');

create function sectalk_private.st_v8_workspace_audit_attach_when_staged()
returns trigger language plpgsql security definer set search_path='' as $$
begin
  if new.state<>'read_only' or (tg_op='UPDATE' and old.state='read_only') then return new; end if;
  perform 1 from public.st_v2_workspaces a where a.id=new.workspace for update nowait;
  update sectalk_private.st_v8_workspace_audit_custody a set live_workspace=new.workspace
    where a.workspace=new.workspace and a.live_workspace is null;
  return new;
end $$;
create trigger st_v8_workspace_audit_attach_when_staged after insert or update of state
  on sectalk_private.st_v8_offboarding_requests
  for each row execute function sectalk_private.st_v8_workspace_audit_attach_when_staged();

create or replace function sectalk_private.st_v8_workspace_audit_custody_write()
returns trigger language plpgsql security definer set search_path='' as $$
declare w uuid:=case when tg_op='DELETE' then old.workspace_id else new.workspace_id end;
        staged boolean;
begin
  if tg_op='UPDATE' and old.workspace_id is distinct from new.workspace_id then
    raise exception 'Original workspace audit attribution is immutable' using errcode='PT409';
  end if;
  perform 1 from public.st_v2_workspaces a where a.id=w for key share;
  if not found then raise exception 'Retained workspace audit is immutable' using errcode='PT409'; end if;
  if tg_op='INSERT' or (tg_op='UPDATE' and old.actor is distinct from new.actor) then
    perform 1 from public.st_profiles a where a.id=new.actor for key share;
    if not found then raise exception 'A live audit actor profile is required' using errcode='23503'; end if;
    insert into sectalk_private.st_v8_workspace_audit_actors(actor) values(new.actor) on conflict do nothing;
  end if;
  staged:=exists(select 1 from sectalk_private.st_v8_offboarding_requests r where r.workspace=w and r.state='read_only');
  if not exists(select 1 from sectalk_private.st_v8_workspace_audit_custody a
    where a.workspace=w and (not staged or a.live_workspace=w)) then
    insert into sectalk_private.st_v8_workspace_audit_custody as c(workspace,live_workspace)
      values(w,case when staged then w end) on conflict(workspace) do update set live_workspace=excluded.live_workspace
      where staged and c.live_workspace is null;
  end if;
  if tg_op='DELETE' then return old; end if;
  return new;
end $$;

revoke all on function sectalk_private.st_v8_workspace_audit_profile_reuse(),
  sectalk_private.st_v8_workspace_audit_attach_when_staged() from public,anon,authenticated,service_role;
notify pgrst,'reload schema';
commit;
