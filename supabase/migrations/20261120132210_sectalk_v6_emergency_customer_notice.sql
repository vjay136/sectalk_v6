begin;

create table sectalk_private.st_v6_emergency_notices (
  id uuid primary key default gen_random_uuid(),
  workspace_id uuid not null references public.st_v2_workspaces on delete cascade,
  recipient uuid not null references public.st_profiles on delete cascade,
  stage text not null check (stage in ('requested','approved','denied','revoked','accessed','closed')),
  occurred_at timestamptz not null default clock_timestamp(),
  read_at timestamptz
);
create index st_v6_emergency_notices_recipient on sectalk_private.st_v6_emergency_notices(recipient,occurred_at desc);
alter table sectalk_private.st_v6_emergency_notices enable row level security;
revoke all on sectalk_private.st_v6_emergency_notices from public,anon,authenticated,service_role;

create function sectalk_private.st_v6_notify_emergency_customer()
returns trigger language plpgsql security definer set search_path='' as $$
declare owner_id uuid;
begin
  select owner into owner_id from public.st_v2_workspaces where id=new.workspace_id;
  if owner_id is null then return new; end if;
  insert into sectalk_private.st_v6_emergency_notices(workspace_id,recipient,stage)
    values(new.workspace_id,owner_id,new.action);
  if new.action in ('requested','accessed') then
    perform realtime.send('{}'::jsonb,'emergency_customer_notice','st:account:'||owner_id,true);
  end if;
  return new;
end $$;
create trigger st_v6_emergency_customer_notice after insert on sectalk_private.st_v6_break_glass_audit
for each row execute function sectalk_private.st_v6_notify_emergency_customer();

create function public.st_v6_my_emergency_notices()
returns table(id uuid,workspace text,stage text,occurred_at timestamptz,read_at timestamptz)
language sql stable security definer set search_path='' as $$
  select n.id,w.name,n.stage,n.occurred_at,n.read_at from sectalk_private.st_v6_emergency_notices n
  join public.st_v2_workspaces w on (w.id,w.owner)=(n.workspace_id,n.recipient)
  where n.recipient=(select auth.uid()) and sectalk_private.st_v2_active(w.owner)
    and sectalk_private.st_v2_role(w.id,w.owner)='owner'
  order by n.occurred_at desc,n.id limit 50
$$;

create function public.st_v6_read_emergency_notice(p_notice uuid)
returns void language sql security definer set search_path='' as $$
  update sectalk_private.st_v6_emergency_notices n set read_at=coalesce(n.read_at,clock_timestamp())
  from public.st_v2_workspaces w where n.id=p_notice and n.recipient=(select auth.uid())
    and (w.id,w.owner)=(n.workspace_id,n.recipient) and sectalk_private.st_v2_active(w.owner)
    and sectalk_private.st_v2_role(w.id,w.owner)='owner'
$$;

revoke all on function sectalk_private.st_v6_notify_emergency_customer(),
  public.st_v6_my_emergency_notices(),public.st_v6_read_emergency_notice(uuid) from public,anon,authenticated,service_role;
grant execute on function public.st_v6_my_emergency_notices(),public.st_v6_read_emergency_notice(uuid) to authenticated;
notify pgrst,'reload schema';
commit;
