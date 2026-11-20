begin;

create or replace function public.st_v3_ping()
returns void language plpgsql security definer set search_path='' as $$
declare actor uuid := auth.uid();
begin
  perform sectalk_private.limit_action('v6_presence_ping',12);
  if not sectalk_private.st_v2_active(actor) then return; end if;
  update public.st_v3_presence set expires_at=clock_timestamp()+interval '100 seconds'
    where user_id=actor and state<>'offline' and expires_at<=clock_timestamp()+interval '65 seconds';
end $$;

create function sectalk_private.st_v6_presence_hint()
returns trigger language plpgsql security definer set search_path='' as $$
declare
  was_visible boolean := false;
  is_visible boolean := new.state<>'offline' and new.expires_at>clock_timestamp();
  recipient uuid;
begin
  if tg_op='UPDATE' then
    was_visible:=old.state<>'offline' and old.expires_at>clock_timestamp();
    if old.state=new.state and was_visible=is_visible then return new; end if;
  end if;
  perform realtime.send('{}'::jsonb,'presence','st:account:'||new.user_id::text,true);
  if not (is_visible or was_visible) then return new; end if;
  for recipient in
    select case when c.member_a=new.user_id then c.member_b else c.member_a end
    from public.st_chats c where new.user_id in(c.member_a,c.member_b)
      and c.status='accepted' and sectalk_private.open_pair(c.member_a,c.member_b)
  loop
    perform realtime.send('{}'::jsonb,'presence','st:account:'||recipient::text,true);
  end loop;
  return new;
end $$;

revoke all on function sectalk_private.st_v6_presence_hint() from public,anon,authenticated;
create trigger st_v6_presence_hint after insert or update on public.st_v3_presence
for each row execute function sectalk_private.st_v6_presence_hint();

create or replace function sectalk_private.st_v6_presence_block_hint()
returns trigger language plpgsql security definer set search_path='' as $$
declare
  owner_id uuid;
  contact_id uuid;
begin
  if tg_op='INSERT' then
    owner_id:=new.actor;
    contact_id:=new.target;
  else
    owner_id:=old.actor;
    contact_id:=old.target;
  end if;
  if exists(select 1 from public.st_chats c
    where c.member_a=least(owner_id,contact_id) and c.member_b=greatest(owner_id,contact_id)
      and c.status='accepted') then
    perform realtime.send('{}'::jsonb,'presence','st:account:'||contact_id::text,true);
    perform realtime.send('{}'::jsonb,'presence','st:account:'||owner_id::text,true);
  end if;
  return null;
end $$;

revoke all on function sectalk_private.st_v6_presence_block_hint() from public,anon,authenticated;
create trigger st_v6_presence_block_hint after insert or delete on public.st_blocks
for each row execute function sectalk_private.st_v6_presence_block_hint();

commit;
