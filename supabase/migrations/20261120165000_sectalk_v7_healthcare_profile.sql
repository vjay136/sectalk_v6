begin;

create function sectalk_private.st_v7_healthcare_workspace(p_workspace uuid)
returns boolean language sql stable set search_path='' as $$
  select exists(select 1 from public.st_v6_workspace_policy p
    where p.workspace_id=p_workspace and p.compliance_profile='healthcare');
$$;

create function sectalk_private.st_v7_seed_healthcare_dlp()
returns trigger language plpgsql security definer set search_path='' as $$
begin
  if new.compliance_profile='healthcare' then
    insert into sectalk_private.st_v7_workspace_dlp(workspace_id,revision,rules)
      values(new.workspace_id,1,'{"pii":"warn","phi":"block","payment_card":"block","credential":"redact"}')
      on conflict(workspace_id) do nothing;
  end if;
  return new;
end
$$;

create function sectalk_private.st_v7_enforce_healthcare_dlp()
returns trigger language plpgsql security definer set search_path='' as $$
begin
  if sectalk_private.st_v7_healthcare_workspace(new.workspace_id)
    and (coalesce(new.rules->>'phi','') not in ('block','redact')
      or coalesce(new.rules->>'credential','') not in ('block','redact')) then
    raise exception using errcode='22023',message='Healthcare requires blocking or redacting health-record identifiers and credentials';
  end if;
  return new;
end
$$;

create function sectalk_private.st_v7_enforce_healthcare_room()
returns trigger language plpgsql security definer set search_path='' as $$
begin
  if not sectalk_private.st_v7_healthcare_workspace(new.workspace_id) then return new; end if;
  if new.kind not in ('private','admin') then
    raise exception using errcode='42501',message='Healthcare workspaces require private or admin-only rooms';
  end if;
  if tg_op='INSERT' then
    if new.classification<>'restricted' then new.classification:='confidential'; end if;
    new.forwarding_allowed:=false;
  elsif new.forwarding_allowed or new.classification not in ('confidential','restricted') then
    raise exception using errcode='42501',message='Healthcare rooms require confidential classification and block forwarding';
  end if;
  return new;
end
$$;

create function sectalk_private.st_v7_enforce_healthcare_room_admission()
returns trigger language plpgsql security definer set search_path='' as $$
declare requested_role text;
begin
  if tg_table_name='st_v6_room_entries' then requested_role:=new.invited_role; else requested_role:=new.role; end if;
  if requested_role='guest' and exists(select 1 from public.st_v6_rooms r
    where r.id=new.room_id and sectalk_private.st_v7_healthcare_workspace(r.workspace_id)) then
    raise exception using errcode='42501',message='Healthcare rooms do not allow guest access';
  end if;
  return new;
end
$$;

create function sectalk_private.st_v7_keep_healthcare_emergency_note_private()
returns trigger language plpgsql security definer set search_path='' as $$
declare note text;
begin
  if tg_table_name='st_v6_break_glass_requests' then note:=new.justification;
  else note:=new.reason; end if;
  if sectalk_private.st_v7_healthcare_workspace(new.workspace_id) and exists (
    select 1 from sectalk_private.st_v7_dlp_matches(note) m where m.category in ('phi','credential','payment_card')
  ) then raise exception using errcode='22023',
    message='Describe the emergency without health record identifiers, payment details, or credentials'; end if;
  return new;
end
$$;

create trigger st_v7_healthcare_profile_defaults after insert or update of compliance_profile on public.st_v6_workspace_policy
  for each row execute function sectalk_private.st_v7_seed_healthcare_dlp();
create trigger st_v7_healthcare_dlp_floor before insert or update of rules on sectalk_private.st_v7_workspace_dlp
  for each row execute function sectalk_private.st_v7_enforce_healthcare_dlp();
create trigger st_v7_healthcare_room_floor before insert or update of kind,classification,forwarding_allowed on public.st_v6_rooms
  for each row execute function sectalk_private.st_v7_enforce_healthcare_room();
create trigger st_v7_healthcare_guest_floor before insert or update of role on public.st_v6_room_members
  for each row execute function sectalk_private.st_v7_enforce_healthcare_room_admission();
create trigger st_v7_healthcare_emergency_request_note before insert on sectalk_private.st_v6_break_glass_requests
  for each row execute function sectalk_private.st_v7_keep_healthcare_emergency_note_private();
create trigger st_v7_healthcare_emergency_review_note before insert on sectalk_private.st_v6_break_glass_audit
  for each row execute function sectalk_private.st_v7_keep_healthcare_emergency_note_private();

insert into sectalk_private.st_v7_workspace_dlp as d(workspace_id,revision,rules)
  select p.workspace_id,1,'{"pii":"warn","phi":"block","payment_card":"block","credential":"redact"}'::jsonb
  from public.st_v6_workspace_policy p where p.compliance_profile='healthcare'
  on conflict(workspace_id) do update set revision=d.revision+1,updated_at=clock_timestamp(),rules=d.rules
    ||case when d.rules->>'phi' in ('block','redact') then '{}'::jsonb else '{"phi":"block"}'::jsonb end
    ||case when d.rules->>'credential' in ('block','redact') then '{}'::jsonb else '{"credential":"redact"}'::jsonb end
  where d.rules->>'phi' not in ('block','redact') or d.rules->>'credential' not in ('block','redact');

update public.st_v6_rooms r set forwarding_allowed=false,
  classification=case when r.classification='restricted' then 'restricted' else 'confidential' end
  where sectalk_private.st_v7_healthcare_workspace(r.workspace_id) and r.kind in ('private','admin')
    and (r.forwarding_allowed or r.classification not in ('confidential','restricted'));

create trigger st_v7_healthcare_guest_invitation_floor before insert or update of invited_role on public.st_v6_room_entries
  for each row execute function sectalk_private.st_v7_enforce_healthcare_room_admission();

create or replace function sectalk_private.st_v6_room_role(p_room uuid,p_user uuid)
returns text language sql stable security definer set search_path='' as $$
  select case when r.kind='admin' and workspace_role.role in ('owner','admin')
    then case when workspace_role.role='owner' then 'owner' else 'moderator' end
    when r.kind<>'admin' and (m.role<>'guest' or not sectalk_private.st_v7_healthcare_workspace(r.workspace_id)) then m.role end
  from public.st_v6_rooms r
  cross join lateral (select sectalk_private.st_v2_role(r.workspace_id,p_user) as role) workspace_role
  left join public.st_v6_room_members m on m.room_id=r.id and m.user_id=p_user
  where r.id=p_room and sectalk_private.st_v2_active(p_user) and workspace_role.role is not null
    and not exists(select 1 from public.st_v6_room_bans b where b.room_id=r.id and b.user_id=p_user)
$$;

revoke all on function sectalk_private.st_v7_healthcare_workspace(uuid),
  sectalk_private.st_v7_seed_healthcare_dlp(),sectalk_private.st_v7_enforce_healthcare_dlp(),
  sectalk_private.st_v7_enforce_healthcare_room(),sectalk_private.st_v7_enforce_healthcare_room_admission(),
  sectalk_private.st_v7_keep_healthcare_emergency_note_private() from public,anon,authenticated,service_role;
commit;
