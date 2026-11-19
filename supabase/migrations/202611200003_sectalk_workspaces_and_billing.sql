begin;

create table public.st_v2_subscriptions (
  user_id uuid primary key references auth.users on delete cascade,
  plan text not null check(plan in ('free','basic','professional','business','enterprise')),
  status text not null,
  customer_id text unique,
  subscription_id text unique,
  period_end timestamptz,
  cancel_at_period_end boolean not null default false,
  synced_at timestamptz not null default now()
);
create table sectalk_private.st_v2_billing_events (
  event_id text primary key,
  received_at timestamptz not null default now()
);
create table sectalk_private.st_v2_checkout (
  user_id uuid primary key references auth.users on delete cascade,
  id uuid not null default gen_random_uuid(),
  price text not null,
  expires timestamptz not null
);
alter table public.st_v2_subscriptions enable row level security;
revoke all on public.st_v2_subscriptions from public,anon,authenticated;
grant select on public.st_v2_subscriptions to authenticated;
create policy st_v2_own_subscription on public.st_v2_subscriptions for select to authenticated using(user_id=(select auth.uid()));

create function public.st_v2_reserve_checkout(p_user uuid,p_price text)
returns jsonb language plpgsql security definer set search_path='' as $$
declare lease sectalk_private.st_v2_checkout;
begin
  insert into sectalk_private.st_v2_checkout as checkout(user_id,price,expires)
    values(p_user,p_price,now()+interval '35 minutes')
  on conflict(user_id) do update set id=gen_random_uuid(),price=excluded.price,expires=excluded.expires
    where checkout.expires <= now();
  select * into lease from sectalk_private.st_v2_checkout where user_id=p_user;
  if lease.price is distinct from p_price then return null; end if;
  return jsonb_build_object('id',lease.id,'expires_epoch',floor(extract(epoch from lease.expires)));
end $$;
revoke all on function public.st_v2_reserve_checkout(uuid,text) from public,anon,authenticated;
grant execute on function public.st_v2_reserve_checkout(uuid,text) to service_role;

create function public.st_v2_sync_billing(
  p_event text, p_user uuid, p_customer text, p_subscription text, p_plan text,
  p_status text, p_end timestamptz, p_cancel boolean, p_synced timestamptz
) returns void language plpgsql security definer set search_path='' as $$
begin
  if p_plan not in ('basic','professional','business','enterprise') or
    p_status not in ('incomplete','incomplete_expired','trialing','active','past_due','canceled','unpaid','paused') then
    raise exception 'Invalid provider subscription';
  end if;
  insert into sectalk_private.st_v2_billing_events(event_id) values(p_event) on conflict do nothing;
  if not found then return; end if;
  insert into public.st_v2_subscriptions as subscriptions
    (user_id,plan,status,customer_id,subscription_id,period_end,cancel_at_period_end,synced_at)
    values(p_user,p_plan,p_status,p_customer,p_subscription,p_end,p_cancel,p_synced)
  on conflict(user_id) do update set plan=excluded.plan,status=excluded.status,
    customer_id=excluded.customer_id,subscription_id=excluded.subscription_id,period_end=excluded.period_end,
    cancel_at_period_end=excluded.cancel_at_period_end,synced_at=excluded.synced_at
    where subscriptions.synced_at <= excluded.synced_at
      and (subscriptions.subscription_id = excluded.subscription_id
        or subscriptions.status in ('canceled','incomplete_expired','unpaid','paused'));
end $$;

create function sectalk_private.st_v2_effective_plan(p_user uuid)
returns text language sql stable security definer set search_path='' as $$
  select coalesce((select plan from public.st_v2_subscriptions where user_id=p_user
      and (status in ('active','trialing') and period_end>now()
        or status='past_due' and period_end + interval '3 days' > now())), 'free')
$$;

create table public.st_v2_workspaces (
  id uuid primary key default gen_random_uuid(),
  name text not null check(char_length(btrim(name)) between 1 and 64),
  owner uuid not null references public.st_profiles,
  created_at timestamptz not null default now()
);
create index st_v2_workspace_owner on public.st_v2_workspaces(owner);
create table public.st_v2_members (
  workspace_id uuid not null references public.st_v2_workspaces on delete cascade,
  user_id uuid not null references public.st_profiles,
  role text not null default 'member' check(role in ('owner','admin','member')),
  joined_at timestamptz not null default now(),
  primary key(workspace_id, user_id)
);
create index st_v2_member_user on public.st_v2_members(user_id, workspace_id);
create table public.st_v2_invites (
  id uuid primary key default gen_random_uuid(),
  workspace_id uuid not null references public.st_v2_workspaces on delete cascade,
  invitee uuid not null references public.st_profiles,
  created_by uuid not null references public.st_profiles,
  workspace_name text not null,
  status text not null default 'pending' check(status in ('pending','accepted','declined','cancelled')),
  created_at timestamptz not null default now(),
  unique(workspace_id,invitee)
);
create index st_v2_invite_user on public.st_v2_invites(invitee,status);
create table public.st_v2_channels (
  id uuid primary key default gen_random_uuid(),
  workspace_id uuid not null references public.st_v2_workspaces on delete cascade,
  name text not null check(name ~ '^[a-z0-9][a-z0-9-]{0,39}$'),
  created_at timestamptz not null default now(),
  unique(workspace_id,name)
);
create table public.st_v2_posts (
  id uuid primary key,
  channel_id uuid not null references public.st_v2_channels on delete cascade,
  sender uuid not null references public.st_profiles,
  body text not null check(char_length(btrim(body)) between 1 and 4000),
  created_at timestamptz not null default now()
);
create index st_v2_post_feed on public.st_v2_posts(channel_id,created_at desc,id desc);
create table public.st_v2_items (
  id uuid primary key default gen_random_uuid(),
  workspace_id uuid not null references public.st_v2_workspaces on delete cascade,
  kind text not null check(kind in ('task','note','event','announcement')),
  title text not null check(char_length(btrim(title)) between 1 and 120),
  details text not null default '' check(char_length(details)<=3000),
  due_at timestamptz,
  completed boolean not null default false,
  created_by uuid not null references public.st_profiles,
  created_at timestamptz not null default now(),
  check(kind<>'event' or due_at is not null),
  check(kind='task' or not completed)
);
create index st_v2_items_feed on public.st_v2_items(workspace_id,kind,created_at desc);
create table public.st_v2_workspace_audit (
  id bigint generated always as identity primary key,
  workspace_id uuid not null references public.st_v2_workspaces on delete cascade,
  actor uuid not null references public.st_profiles,
  event text not null,
  target uuid,
  created_at timestamptz not null default now()
);
create index st_v2_workspace_audit_feed on public.st_v2_workspace_audit(workspace_id,created_at desc,id desc);

create function sectalk_private.st_v2_role(w uuid,u uuid)
returns text language sql stable security definer set search_path='' as $$
  select role from public.st_v2_members where workspace_id=w and user_id=u
$$;
create function sectalk_private.st_v2_shared_profile(p uuid,u uuid)
returns boolean language sql stable security definer set search_path='' as $$
  select exists(select 1 from public.st_v2_members a join public.st_v2_members b using(workspace_id)
    where a.user_id=u and b.user_id=p)
$$;
create function sectalk_private.st_v2_post_read(c uuid, s uuid, u uuid)
returns boolean language sql stable security definer set search_path='' as $$
  select exists(select 1 from public.st_v2_channels where id=c and sectalk_private.st_v2_role(workspace_id,u) is not null)
    and not exists(select 1 from public.st_blocks where (actor,target) in ((u,s),(s,u)))
$$;
create function sectalk_private.st_v2_active(u uuid)
returns boolean language sql stable security definer set search_path='' as $$
  select u is not null and not exists(select 1 from sectalk_private.suspensions where user_id=u and until_at>now())
$$;

alter table public.st_v2_workspaces enable row level security;
alter table public.st_v2_members enable row level security;
alter table public.st_v2_invites enable row level security;
alter table public.st_v2_channels enable row level security;
alter table public.st_v2_posts enable row level security;
alter table public.st_v2_items enable row level security;
alter table public.st_v2_workspace_audit enable row level security;

revoke all on public.st_v2_workspaces,public.st_v2_members,public.st_v2_invites,public.st_v2_channels,
  public.st_v2_posts,public.st_v2_items,public.st_v2_workspace_audit from public,anon,authenticated;
grant select on public.st_v2_workspaces,public.st_v2_members,public.st_v2_invites,public.st_v2_channels,
  public.st_v2_posts,public.st_v2_items,public.st_v2_workspace_audit to authenticated;
create policy st_v2_workspace_read on public.st_v2_workspaces for select to authenticated using(sectalk_private.st_v2_role(id,(select auth.uid())) is not null);
create policy st_v2_member_read on public.st_v2_members for select to authenticated using(sectalk_private.st_v2_role(workspace_id,(select auth.uid())) is not null);
create policy st_v2_invite_read on public.st_v2_invites for select to authenticated using(invitee=(select auth.uid()) or sectalk_private.st_v2_role(workspace_id,(select auth.uid())) in ('owner','admin'));
create policy st_v2_channel_read on public.st_v2_channels for select to authenticated using(sectalk_private.st_v2_role(workspace_id,(select auth.uid())) is not null);
create policy st_v2_post_read on public.st_v2_posts for select to authenticated using(sectalk_private.st_v2_post_read(channel_id,sender,(select auth.uid())));
create policy st_v2_item_read on public.st_v2_items for select to authenticated using(sectalk_private.st_v2_role(workspace_id,(select auth.uid())) is not null);
create policy st_v2_audit_read on public.st_v2_workspace_audit for select to authenticated using(sectalk_private.st_v2_role(workspace_id,(select auth.uid())) in ('owner','admin'));
create policy st_v2_profile_read on public.st_profiles for select to authenticated using(sectalk_private.st_v2_shared_profile(id,(select auth.uid())));

create function public.st_v2_create_workspace(p_name text)
returns uuid language plpgsql security definer set search_path='' as $$
declare me uuid:=auth.uid(); w uuid; cap integer;
begin
  perform sectalk_private.limit_action('v2_workspace',4);
  if not sectalk_private.st_v2_active(me) then raise exception 'Workspace access is restricted'; end if;
  perform id from public.st_profiles where id=me for update;
  if not found then raise exception 'Create a profile first'; end if;
  cap:=case sectalk_private.st_v2_effective_plan(me)
    when 'basic' then 2 when 'professional' then 5 when 'business' then 20 when 'enterprise' then 100 else 1 end;
  if (select count(*) from public.st_v2_workspaces where owner=me)>=cap then
    raise exception 'Your plan’s workspace limit has been reached';
  end if;
  insert into public.st_v2_workspaces(name,owner) values(btrim(p_name),me) returning id into w;
  insert into public.st_v2_members(workspace_id,user_id,role) values(w,me,'owner');
  insert into public.st_v2_channels(workspace_id,name) values(w,'general');
  insert into public.st_v2_workspace_audit(workspace_id,actor,event) values(w,me,'workspace.created');
  return w;
end $$;

create function public.st_v2_invite(p_workspace uuid,p_handle text)
returns boolean language plpgsql security definer set search_path='' as $$
declare me uuid:=auth.uid(); peer uuid; workspace_name text;
begin
  perform sectalk_private.limit_action('v2_invite',10);
  select name into workspace_name from public.st_v2_workspaces where id=p_workspace for update;
  if workspace_name is null or not coalesce(sectalk_private.st_v2_role(p_workspace,me) in ('owner','admin'),false)
    or not sectalk_private.st_v2_active(me) then raise exception 'Workspace action unavailable'; end if;
  select id into peer from public.st_profiles where handle=lower(btrim(p_handle));
  if peer is null or peer=me or not sectalk_private.open_pair(me,peer)
    or sectalk_private.st_v2_role(p_workspace,peer) is not null then return false; end if;
  insert into public.st_v2_invites(workspace_id,invitee,created_by,workspace_name)
  values(p_workspace,peer,me,workspace_name) on conflict(workspace_id,invitee) do nothing;
  if not found then return false; end if;
  insert into public.st_v2_workspace_audit(workspace_id,actor,event,target) values(p_workspace,me,'member.invited',peer);
  return true;
end $$;

create function public.st_v2_reply_invite(p_invite uuid,p_accept boolean)
returns uuid language plpgsql security definer set search_path='' as $$
declare me uuid:=auth.uid(); invitation public.st_v2_invites; workspace_owner uuid; cap integer;
begin
  perform sectalk_private.limit_action('v2_reply_invite',10);
  select * into invitation from public.st_v2_invites where id=p_invite and invitee=me and status='pending';
  if not found then raise exception 'Workspace invitation unavailable'; end if;
  select owner into workspace_owner from public.st_v2_workspaces where id=invitation.workspace_id for update;
  select * into invitation from public.st_v2_invites where id=p_invite and invitee=me and status='pending' for update;
  if not found then raise exception 'Workspace invitation unavailable'; end if;
  if not p_accept then
    update public.st_v2_invites set status='declined' where id=p_invite;
    return null;
  end if;
  if not coalesce(sectalk_private.st_v2_role(invitation.workspace_id,invitation.created_by) in ('owner','admin'),false)
    or not sectalk_private.open_pair(me,invitation.created_by) then raise exception 'Workspace invitation unavailable'; end if;
  cap:=case sectalk_private.st_v2_effective_plan(workspace_owner)
    when 'basic' then 12 when 'professional' then 30 when 'business' then 100 when 'enterprise' then 500 else 5 end;
  if (select count(*) from public.st_v2_members where workspace_id=invitation.workspace_id)>=cap then
    raise exception 'This workspace has reached its member limit';
  end if;
  insert into public.st_v2_members(workspace_id,user_id) values(invitation.workspace_id,me) on conflict do nothing;
  update public.st_v2_invites set status='accepted' where id=p_invite;
  insert into public.st_v2_workspace_audit(workspace_id,actor,event,target) values(invitation.workspace_id,me,'member.joined',me);
  return invitation.workspace_id;
end $$;

create function public.st_v2_set_member(p_workspace uuid,p_member uuid,p_role text)
returns void language plpgsql security definer set search_path='' as $$
declare me uuid:=auth.uid();
begin
  perform sectalk_private.limit_action('v2_role',12);
  perform id from public.st_v2_workspaces where id=p_workspace for update;
  if sectalk_private.st_v2_role(p_workspace,me) is distinct from 'owner' or not sectalk_private.st_v2_active(me)
    or p_role is null or p_role not in ('admin','member','remove') or p_member=me then raise exception 'Workspace action unavailable'; end if;
  if p_role='remove' then
    delete from public.st_v2_members where workspace_id=p_workspace and user_id=p_member;
  else
    update public.st_v2_members set role=p_role where workspace_id=p_workspace and user_id=p_member;
  end if;
  if not found then raise exception 'Workspace member unavailable'; end if;
  insert into public.st_v2_workspace_audit(workspace_id,actor,event,target) values(p_workspace,me,'member.'||p_role,p_member);
end $$;

create function public.st_v2_create_channel(p_workspace uuid,p_name text)
returns uuid language plpgsql security definer set search_path='' as $$
declare channel uuid;
begin
  perform sectalk_private.limit_action('v2_channel',10);
  perform id from public.st_v2_workspaces where id=p_workspace for update;
  if not coalesce(sectalk_private.st_v2_role(p_workspace,auth.uid()) in ('owner','admin'),false)
    or not sectalk_private.st_v2_active(auth.uid()) then raise exception 'Workspace action unavailable'; end if;
  if (select count(*) from public.st_v2_channels where workspace_id=p_workspace)>=100 then raise exception 'Channel limit reached'; end if;
  insert into public.st_v2_channels(workspace_id,name) values(p_workspace,lower(btrim(p_name))) returning id into channel;
  insert into public.st_v2_workspace_audit(workspace_id,actor,event,target) values(p_workspace,auth.uid(),'channel.created',channel);
  return channel;
end $$;

create function public.st_v2_post(p_channel uuid,p_id uuid,p_body text)
returns void language plpgsql security definer set search_path='' as $$
declare me uuid:=auth.uid(); workspace uuid;
begin
  perform sectalk_private.limit_action('v2_post',60);
  select workspace_id into workspace from public.st_v2_channels where id=p_channel;
  if sectalk_private.st_v2_role(workspace,me) is null or not sectalk_private.st_v2_active(me)
    then raise exception 'Channel unavailable'; end if;
  insert into public.st_v2_posts(id,channel_id,sender,body) values(p_id,p_channel,me,btrim(p_body)) on conflict(id) do nothing;
  if not found and not exists(select 1 from public.st_v2_posts where id=p_id and channel_id=p_channel and sender=me and body=btrim(p_body))
    then raise exception 'Message ID already in use'; end if;
end $$;

create function public.st_v2_add_item(p_workspace uuid,p_kind text,p_title text,p_details text,p_due timestamptz)
returns uuid language plpgsql security definer set search_path='' as $$
declare me uuid:=auth.uid(); member_role text; item uuid;
begin
  perform sectalk_private.limit_action('v2_item',20);
  member_role:=sectalk_private.st_v2_role(p_workspace,me);
  if member_role is null or not sectalk_private.st_v2_active(me)
    or p_kind='announcement' and member_role not in ('owner','admin') then raise exception 'Workspace action unavailable'; end if;
  insert into public.st_v2_items(workspace_id,kind,title,details,due_at,created_by)
    values(p_workspace,p_kind,btrim(p_title),btrim(coalesce(p_details,'')),p_due,me) returning id into item;
  return item;
end $$;

create function public.st_v2_complete_task(p_item uuid,p_complete boolean)
returns void language plpgsql security definer set search_path='' as $$
begin
  perform sectalk_private.limit_action('v2_task',30);
  update public.st_v2_items set completed=p_complete where id=p_item and kind='task'
    and sectalk_private.st_v2_role(workspace_id,auth.uid()) is not null and sectalk_private.st_v2_active(auth.uid());
  if not found then raise exception 'Task unavailable'; end if;
end $$;

revoke execute on function sectalk_private.st_v2_effective_plan(uuid),sectalk_private.st_v2_role(uuid,uuid),
  sectalk_private.st_v2_shared_profile(uuid,uuid),sectalk_private.st_v2_active(uuid),sectalk_private.st_v2_post_read(uuid,uuid,uuid)
  from public,anon,authenticated;
grant execute on function sectalk_private.st_v2_role(uuid,uuid),sectalk_private.st_v2_shared_profile(uuid,uuid),
  sectalk_private.st_v2_post_read(uuid,uuid,uuid) to authenticated;
do $$
declare sig text;
begin
  for sig in select p.oid::regprocedure::text from pg_proc p join pg_namespace n on n.oid=p.pronamespace
    where n.nspname='public' and left(p.proname,6)='st_v2_'
  loop
    execute 'revoke all on function '||sig||' from public,anon,authenticated';
    if split_part(sig,'(',1) not in ('st_v2_sync_billing','public.st_v2_sync_billing','st_v2_reserve_checkout','public.st_v2_reserve_checkout') then
      execute 'grant execute on function '||sig||' to authenticated';
    end if;
  end loop;
end $$;
grant execute on function public.st_v2_sync_billing(text,uuid,text,text,text,text,timestamptz,boolean,timestamptz) to service_role;

alter publication supabase_realtime add table public.st_v2_posts,public.st_v2_invites,public.st_v2_items;
commit;
