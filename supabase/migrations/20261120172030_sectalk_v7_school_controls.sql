begin;
alter table public.st_v6_workspace_groups drop constraint st_v6_workspace_groups_kind_check;
alter table public.st_v6_workspace_groups add constraint st_v6_workspace_groups_kind_check
  check(kind in ('group','team','department','class'));

create table sectalk_private.st_v7_school_classes (
  workspace uuid not null references public.st_v2_workspaces(id) on delete cascade,
  id uuid not null,
  room uuid not null unique references public.st_v6_rooms(id) on delete cascade,
  primary key(workspace,id),
  foreign key(workspace,id) references public.st_v6_workspace_groups(workspace_id,id) on delete cascade
);
create table sectalk_private.st_v7_school_class_people (
  workspace uuid not null,
  class uuid not null,
  person uuid not null,
  role text not null check(role in ('teacher','student')),
  primary key(workspace,class,person),
  foreign key(workspace,class) references sectalk_private.st_v7_school_classes on delete cascade,
  foreign key(workspace,person) references public.st_v2_members(workspace_id,user_id) on delete cascade
);
create index st_v7_school_class_people_account on sectalk_private.st_v7_school_class_people(workspace,person);
alter table sectalk_private.st_v7_school_classes enable row level security;
alter table sectalk_private.st_v7_school_class_people enable row level security;
revoke all on sectalk_private.st_v7_school_classes,sectalk_private.st_v7_school_class_people from public,anon,authenticated,service_role;

create function sectalk_private.st_v7_school_group_visible(p_workspace uuid,p_group uuid)
returns boolean language sql stable security definer set search_path='' as $$
  select exists(select 1 from sectalk_private.st_v7_school_classes c where c.workspace=p_workspace and c.id=p_group
    and (sectalk_private.st_v2_role(p_workspace,auth.uid()) in ('owner','admin')
      or exists(select 1 from sectalk_private.st_v7_school_class_people p
        where p.workspace=c.workspace and p.class=c.id and p.person=auth.uid())));
$$;
revoke all on function sectalk_private.st_v7_school_group_visible(uuid,uuid) from public,anon,authenticated,service_role;
grant execute on function sectalk_private.st_v7_school_group_visible(uuid,uuid) to authenticated;

alter policy st_v6_workspace_groups_read on public.st_v6_workspace_groups
  using(sectalk_private.st_v6_group_directory_access(workspace_id)
    and (kind<>'class' or sectalk_private.st_v7_school_group_visible(workspace_id,id)));
-- An explicit classroom roster is available through the narrower School RPC.
alter policy st_v6_workspace_group_members_read on public.st_v6_workspace_group_members
  using(sectalk_private.st_v6_group_directory_access(workspace_id) and exists (
    select 1 from public.st_v6_workspace_groups g
    where (g.workspace_id,g.id)=(st_v6_workspace_group_members.workspace_id,st_v6_workspace_group_members.group_id)
      and g.kind<>'class'));

create or replace function sectalk_private.st_v6_room_role(p_room uuid,p_user uuid)
returns text language sql stable security definer set search_path='' as $$
  select case when c.id is not null then
      case when enrolled.role='teacher' and m.role in ('owner','moderator') then m.role
        when enrolled.role='student' and m.role='member' then 'member' end
    when r.kind='admin' and workspace_role.role in ('owner','admin')
      then case when workspace_role.role='owner' then 'owner' else 'moderator' end
    when r.kind<>'admin' and (m.role<>'guest' or not sectalk_private.st_v7_healthcare_workspace(r.workspace_id)) then m.role end
  from public.st_v6_rooms r
  cross join lateral (select sectalk_private.st_v2_role(r.workspace_id,p_user) as role) workspace_role
  left join public.st_v6_room_members m on m.room_id=r.id and m.user_id=p_user
  left join sectalk_private.st_v7_school_classes c on c.room=r.id
  left join sectalk_private.st_v7_school_class_people enrolled on enrolled.workspace=c.workspace
    and enrolled.class=c.id and enrolled.person=p_user
  where r.id=p_room and sectalk_private.st_v2_active(p_user) and workspace_role.role is not null
    and not exists(select 1 from public.st_v6_room_bans b where b.room_id=r.id and b.user_id=p_user)
$$;

create function sectalk_private.st_v7_school_room_floor()
returns trigger language plpgsql security definer set search_path='' as $$
declare class_room uuid; expected text;
begin
  if tg_table_name='st_v6_rooms' then
    if exists(select 1 from sectalk_private.st_v7_school_classes c where c.room=new.id)
      and (new.kind<>'private' or new.template<>'class' or new.forwarding_allowed or new.slow_seconds<15
        or new.classification not in ('confidential','restricted')) then
      raise exception using errcode='42501',message='Classroom safety defaults are required';
    end if;
  else
    class_room:=new.room_id;
    if exists(select 1 from sectalk_private.st_v7_school_classes c where c.room=class_room) then
      if tg_table_name='st_v6_room_entries' then
        raise exception using errcode='42501',message='Use School to enroll classroom participants';
      end if;
      select p.role into expected from sectalk_private.st_v7_school_classes c
        join sectalk_private.st_v7_school_class_people p on (p.workspace,p.class)=(c.workspace,c.id)
        where c.room=class_room and p.person=new.user_id;
      if expected is null or (expected='student' and new.role<>'member')
        or (expected='teacher' and new.role not in ('owner','moderator')) then
        raise exception using errcode='42501',message='Use School to change classroom membership';
      end if;
    end if;
  end if;
  return new;
end
$$;
create trigger st_v7_school_room_floor before update of kind,template,classification,forwarding_allowed,slow_seconds on public.st_v6_rooms
  for each row execute function sectalk_private.st_v7_school_room_floor();
create trigger st_v7_school_room_enrollment before insert or update of role on public.st_v6_room_members
  for each row execute function sectalk_private.st_v7_school_room_floor();
create trigger st_v7_school_room_invites before insert or update on public.st_v6_room_entries
  for each row execute function sectalk_private.st_v7_school_room_floor();

create function sectalk_private.st_v7_school_remove_enrollment()
returns trigger language plpgsql security definer set search_path='' as $$
declare linked_room uuid;
begin
  select room into linked_room from sectalk_private.st_v7_school_classes
    where workspace=old.workspace and id=old.class;
  delete from public.st_v6_room_members where room_id=linked_room and user_id=old.person;
  delete from public.st_v6_workspace_group_members where workspace_id=old.workspace and group_id=old.class and user_id=old.person;
  return null;
end
$$;
create trigger st_v7_school_enrollment_removed after delete on sectalk_private.st_v7_school_class_people
  for each row execute function sectalk_private.st_v7_school_remove_enrollment();

create function sectalk_private.st_v7_school_suspend_enrollment()
returns trigger language plpgsql security definer set search_path='' as $$
begin
  if new.suspended_at is not null and old.suspended_at is null then
    delete from sectalk_private.st_v7_school_class_people where workspace=new.workspace_id and person=new.user_id;
  end if;
  return null;
end
$$;
create trigger st_v7_school_suspend_enrollment after update of suspended_at on public.st_v2_members
  for each row execute function sectalk_private.st_v7_school_suspend_enrollment();

create function public.st_v7_school_classes(p_workspace uuid,p_action text default 'read',
  p_class uuid default null,p_name text default null,p_person uuid default null,p_role text default null)
returns jsonb language plpgsql security definer set search_path='' as $$
declare actor uuid:=auth.uid(); manages boolean; class_row sectalk_private.st_v7_school_classes; target_room uuid;
  authority text; previous text; actor_workspace_role text;
begin
  actor_workspace_role:=sectalk_private.st_v2_role(p_workspace,actor);
  if actor_workspace_role is null or not sectalk_private.st_v2_active(actor)
    or not public.st_v7_current_session_valid() or public.st_v7_account_under_lockdown()
    or public.st_v7_login_risk_status() is distinct from 'clear'
    or not exists(select 1 from public.st_v6_workspace_policy p where p.workspace_id=p_workspace and p.workspace_type='school') then
    raise exception using errcode='42501',message='School settings are unavailable';
  end if;
  manages:=actor_workspace_role in ('owner','admin');
  if p_action is distinct from 'read' then
    if public.st_v7_sensitive_action_status('room_role') is distinct from 'verified' then
      raise exception using errcode='42501',message='Verify your current sign-in to manage a classroom';
    end if;
    perform sectalk_private.limit_action('v7_school_classes',20);
    perform 1 from public.st_v2_workspaces where id=p_workspace for update;
    actor_workspace_role:=sectalk_private.st_v2_role(p_workspace,actor);
    if actor_workspace_role is null then raise exception using errcode='42501',message='School settings are unavailable'; end if;
    manages:=actor_workspace_role in ('owner','admin');
    select * into class_row from sectalk_private.st_v7_school_classes c where c.workspace=p_workspace and c.id=p_class;
    if p_action='create' and manages and p_class is not null and char_length(btrim(p_name)) between 1 and 64 then
      if class_row.id is null then
        if (select count(*) from sectalk_private.st_v7_school_classes c where c.workspace=p_workspace)>=50 then
          raise exception using errcode='22023',message='This school already has 50 classes';
        end if;
        target_room:=gen_random_uuid();
        perform public.st_v6_room_create(target_room,p_workspace,btrim(p_name),'private','class');
        update public.st_v6_rooms set forwarding_allowed=false where id=target_room;
        insert into public.st_v6_workspace_groups(workspace_id,id,kind,name) values(p_workspace,p_class,'class',btrim(p_name));
        insert into sectalk_private.st_v7_school_classes values(p_workspace,p_class,target_room);
        insert into sectalk_private.st_v7_school_class_people values(p_workspace,p_class,actor,'teacher');
        insert into public.st_v6_workspace_group_members values(p_workspace,p_class,actor);
      end if;
    elsif p_action in ('enroll','remove') and class_row.id is not null and p_person is not null then
      select m.role into authority from sectalk_private.st_v7_school_class_people m
        where m.workspace=p_workspace and m.class=p_class and m.person=actor;
      select m.role into previous from sectalk_private.st_v7_school_class_people m
        where m.workspace=p_workspace and m.class=p_class and m.person=p_person;
      if not manages and (authority is distinct from 'teacher' or sectalk_private.st_v6_room_role(class_row.room,actor) is null or previous='teacher' or (p_action='enroll' and p_role is distinct from 'student')) then
        raise exception using errcode='42501',message='Classroom roster action is unavailable';
      end if;
      if p_action='enroll' then
        perform 1 from public.st_v2_members where workspace_id=p_workspace and user_id=p_person for no key update;
        if p_role is null or p_role not in ('teacher','student') or not sectalk_private.st_v2_active(p_person)
          or (p_role='student' and sectalk_private.st_v2_role(p_workspace,p_person) is distinct from 'member')
          or (p_role='teacher' and sectalk_private.st_v2_role(p_workspace,p_person) is null) then
          raise exception using errcode='42501',message='Choose an eligible workspace member';
        end if;
        if (select count(*) from sectalk_private.st_v7_school_class_people m where m.workspace=p_workspace and m.class=p_class)>=150
          and previous is null then raise exception using errcode='22023',message='This classroom already has 150 participants'; end if;
        insert into sectalk_private.st_v7_school_class_people values(p_workspace,p_class,p_person,p_role)
          on conflict(workspace,class,person) do update set role=excluded.role;
        insert into public.st_v6_workspace_group_members values(p_workspace,p_class,p_person) on conflict do nothing;
        insert into public.st_v6_room_members(room_id,user_id,role)
          select class_row.room,p_person,case when p_role='teacher' and r.creator=p_person then 'owner'
             when p_role='teacher' then 'moderator' else 'member' end from public.st_v6_rooms r where r.id=class_row.room
          on conflict(room_id,user_id) do update set role=excluded.role;
      else
        delete from sectalk_private.st_v7_school_class_people
          where workspace=p_workspace and class=p_class and person=p_person;
      end if;
    else
      raise exception using errcode='42501',message='School action is unavailable';
    end if;
    insert into public.st_v2_workspace_audit(workspace_id,actor,event,target)
      values(p_workspace,actor,'school.class_'||p_action,coalesce(p_person,p_class));
  end if;

  return coalesce((select jsonb_agg(jsonb_build_object('id',c.id,'name',g.name,'room',
    case when sectalk_private.st_v6_room_role(c.room,actor) is not null then c.room end,'myRole',org.role,
    'people',(select coalesce(jsonb_agg(jsonb_build_object('id',m.person,'role',m.role,'name',p.name)
      order by m.role,p.name),'[]') from sectalk_private.st_v7_school_class_people m join public.st_profiles p on p.id=m.person
      where (m.workspace,m.class)=(c.workspace,c.id) and (manages or org.role='teacher' or m.role='teacher' or m.person=actor)))
    order by g.name) from sectalk_private.st_v7_school_classes c
    join public.st_v6_workspace_groups g on (g.workspace_id,g.id)=(c.workspace,c.id)
    left join sectalk_private.st_v7_school_class_people org on (org.workspace,org.class,org.person)=(c.workspace,c.id,actor)
    where c.workspace=p_workspace and (manages or org.person is not null)),'[]');
end
$$;

create function sectalk_private.st_v7_require_school_group_controls()
returns trigger language plpgsql security definer set search_path='' as $$
begin
  if old.kind='class' then raise exception using errcode='42501',message='Use School to manage this classroom'; end if;
  return new;
end
$$;
create trigger st_v7_class_backing_group before update on public.st_v6_workspace_groups
  for each row execute function sectalk_private.st_v7_require_school_group_controls();
revoke all on function sectalk_private.st_v7_require_school_group_controls() from public,anon,authenticated,service_role;
revoke all on function public.st_v7_school_classes(uuid,text,uuid,text,uuid,text),sectalk_private.st_v7_school_room_floor(),
  sectalk_private.st_v7_school_remove_enrollment(),sectalk_private.st_v7_school_suspend_enrollment()
  from public,anon,authenticated,service_role;
grant execute on function public.st_v7_school_classes(uuid,text,uuid,text,uuid,text) to authenticated;
commit;
