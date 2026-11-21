begin;

create or replace function sectalk_private.st_v8_room_structure_sso_allows(p_workspace uuid)
returns boolean language sql stable security definer set search_path='' as $$
  select sectalk_private.st_v8_entry_sso_allows(p_workspace) and not exists(select 1 from sectalk_private.st_v8_workspace_room_structure_sso p
    where p.workspace=p_workspace
      and sectalk_private.st_v8_workspace_session_receipt(p.workspace,p.protocol,p.provider) is not true);
$$;

create or replace function sectalk_private.st_v8_channel_structure_sso_allows(p_workspace uuid)
returns boolean language sql stable security definer set search_path='' as $$
  select sectalk_private.st_v8_entry_sso_allows(p_workspace) and not exists(select 1 from sectalk_private.st_v8_workspace_channel_structure_sso p
    where p.workspace=p_workspace
      and sectalk_private.st_v8_workspace_session_receipt(p.workspace,p.protocol,p.provider) is not true);
$$;

create or replace function sectalk_private.st_v8_standard_room_session_allowed(p_room uuid)
returns boolean language sql stable set search_path='' as $$
  select not exists(select 1 from public.st_v6_rooms r
    where r.id=p_room and r.encryption_mode='standard'
      and (not sectalk_private.st_v8_entry_sso_allows(r.workspace_id)
        or exists(select 1 from sectalk_private.st_v8_workspace_standard_room_sso p
          where p.workspace=r.workspace_id
            and sectalk_private.st_v8_workspace_session_receipt(p.workspace,p.protocol,p.provider) is not true)));
$$;

create or replace function sectalk_private.st_v8_standard_channel_session_allowed(p_channel uuid)
returns boolean language sql stable set search_path='' as $$
  select not exists(select 1 from public.st_v2_channels c
    where c.id=p_channel and c.encryption_mode='standard'
      and (not sectalk_private.st_v8_entry_sso_allows(c.workspace_id)
        or exists(select 1 from sectalk_private.st_v8_workspace_standard_channel_sso p
          where p.workspace=c.workspace_id
            and sectalk_private.st_v8_workspace_session_receipt(p.workspace,p.protocol,p.provider) is not true)));
$$;

create or replace function sectalk_private.st_v8_managed_content_session_allowed(p_workspace uuid,p_actor uuid,p_session text)
returns boolean language sql stable set search_path='' as $$
  with policies as (
    select workspace,protocol,provider from sectalk_private.st_v8_workspace_managed_content_sso where workspace=p_workspace
    union all
    select workspace,protocol,provider from sectalk_private.st_v8_workspace_entry_sso where workspace=p_workspace
  )
  select not exists(select 1 from policies p
    where p.workspace=p_workspace and not exists(
      select 1 from sectalk_private.st_v7_workspace_sso_sessions receipt
      join sectalk_private.st_v7_workspace_sso setup on setup.workspace=receipt.workspace
      join auth.sessions s on (s.id,s.user_id)=(receipt.session,receipt.principal)
      where receipt.workspace=p.workspace and receipt.principal=p_actor and receipt.session::text=p_session
        and (receipt.protocol,receipt.provider)=(p.protocol,p.provider)
        and (setup.protocol,setup.provider)=(p.protocol,p.provider)
        and sectalk_private.st_v7_workspace_sso_provider(setup.workspace,setup.domain,setup.protocol)=setup.provider
        and sectalk_private.st_v7_session_deadline(s.created_at,s.refreshed_at,s.not_after)>statement_timestamp()
    ));
$$;

create or replace function sectalk_private.st_v6_room_guest_policy(p_room public.st_v6_rooms)
returns boolean language sql stable set search_path='' as $$
  select p_room.kind='public' and p_room.classification='public' and p_room.forwarding_allowed
    and not p_room.locked and not p_room.archived
    and not exists(select 1 from sectalk_private.st_v8_workspace_standard_room_sso p where p.workspace=p_room.workspace_id)
    and not exists(select 1 from sectalk_private.st_v8_workspace_entry_sso p where p.workspace=p_room.workspace_id);
$$;

-- Opt-in is serialized with guest creation by the existing workspace lock.
-- Previously shared links remain revoked if the owner elects to recover later.
create function sectalk_private.st_v8_revoke_entry_room_guest_links()
returns trigger language plpgsql security definer set search_path='' as $$
begin
  update sectalk_private.st_v6_room_guest_link l set revoked_at=clock_timestamp()
    from public.st_v6_rooms r where r.id=l.room and r.workspace_id=new.workspace
      and l.revoked_at is null and l.expires_at>clock_timestamp();
  return null;
end $$;
revoke all on function sectalk_private.st_v8_revoke_entry_room_guest_links() from public,anon,authenticated,service_role;

create trigger st_v8_revoke_entry_room_guest_links
  after insert or update of protocol,provider on sectalk_private.st_v8_workspace_entry_sso
  for each row execute function sectalk_private.st_v8_revoke_entry_room_guest_links();

update sectalk_private.st_v6_room_guest_link l set revoked_at=clock_timestamp()
  from public.st_v6_rooms r join sectalk_private.st_v8_workspace_entry_sso entry on entry.workspace=r.workspace_id
  where r.id=l.room and l.revoked_at is null and l.expires_at>clock_timestamp();

commit;
