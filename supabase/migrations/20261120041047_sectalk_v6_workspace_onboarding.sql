begin;

create table public.st_v6_workspace_templates (
  id text primary key,
  label text not null,
  sort_order integer not null unique,
  restricted boolean not null
);
insert into public.st_v6_workspace_templates(id,label,sort_order,restricted) values
  ('personal','Individual',1,true),('family','Family',2,true),
  ('community','Community',3,false),('creator','Creator',4,false),
  ('business','Small business',5,false),('school','School',6,true),
  ('healthcare','Healthcare',7,true),('finance','Finance',8,true),
  ('government','Government',9,true),('enterprise','Enterprise',10,false),
  ('security_team','Security team',11,true),('soc','Security operations center',12,true);

create table public.st_v6_workspace_policy (
  workspace_id uuid primary key references public.st_v2_workspaces on delete cascade,
  workspace_type text not null references public.st_v6_workspace_templates,
  template text not null check(template in ('standard','restricted')),
  room_kinds text[] not null,
  bulk_admit boolean not null,
  created_by uuid not null references public.st_profiles,
  request_id uuid not null,
  unique(created_by,request_id)
);
create index st_v6_workspace_policy_type on public.st_v6_workspace_policy(workspace_type);
alter table public.st_v6_workspace_templates enable row level security;
alter table public.st_v6_workspace_policy enable row level security;
revoke all on public.st_v6_workspace_templates,public.st_v6_workspace_policy from public,anon,authenticated;
grant select on public.st_v6_workspace_templates to authenticated;
grant select(workspace_id,workspace_type,template,room_kinds,bulk_admit) on public.st_v6_workspace_policy to authenticated;
create policy st_v6_workspace_templates_read on public.st_v6_workspace_templates for select to authenticated using(true);
create policy st_v6_workspace_policy_read on public.st_v6_workspace_policy for select to authenticated
  using(sectalk_private.st_v6_group_directory_access(workspace_id));

create function public.st_v6_create_typed_workspace(p_id uuid,p_name text,p_type text)
returns uuid language plpgsql security definer set search_path='' as $$
declare
  actor uuid:=auth.uid();
  display_name text:=btrim(p_name);
  preset public.st_v6_workspace_templates;
  existing_id uuid;
  existing_name text;
  existing_type text;
  workspace uuid;
begin
  if not sectalk_private.st_v2_active(actor) then raise exception 'Workspace access is restricted'; end if;
  if p_id is null or display_name is null or char_length(display_name) not between 1 and 64
    then raise exception 'Choose a workspace name between 1 and 64 characters'; end if;
  select * into preset from public.st_v6_workspace_templates where id=p_type;
  if not found then raise exception 'Choose a workspace type'; end if;
  perform id from public.st_profiles where id=actor for update;
  if not found then raise exception 'Create a profile first'; end if;
  select p.workspace_id,w.name,p.workspace_type into existing_id,existing_name,existing_type
    from public.st_v6_workspace_policy p join public.st_v2_workspaces w on w.id=p.workspace_id
    where p.created_by=actor and p.request_id=p_id;
  if found then
    if existing_name=display_name and existing_type=p_type then return existing_id; end if;
    raise exception 'Workspace setup request ID is already in use';
  end if;
  workspace:=public.st_v2_create_workspace(display_name);
  insert into public.st_v6_workspace_policy(workspace_id,workspace_type,template,room_kinds,bulk_admit,created_by,request_id)
    values(workspace,p_type,case when preset.restricted then 'restricted' else 'standard' end,
      case when preset.restricted then array['private','admin'] else array['public','private','admin','announcement','broadcast'] end,
      not preset.restricted,actor,p_id);
  insert into public.st_v2_workspace_audit(workspace_id,actor,event,target)
    values(workspace,actor,'workspace.policy_initialized',workspace);
  return workspace;
end $$;
revoke all on function public.st_v6_create_typed_workspace(uuid,text,text) from public,anon,authenticated;
grant execute on function public.st_v6_create_typed_workspace(uuid,text,text) to authenticated;

create function sectalk_private.st_v6_workspace_room_policy()
returns trigger language plpgsql security definer set search_path='' as $$
begin
  if exists(select 1 from public.st_v6_workspace_policy p
    where p.workspace_id=new.workspace_id and not (new.kind=any(p.room_kinds)))
    then raise exception 'This workspace policy requires private or admin-only rooms'; end if;
  return new;
end $$;
revoke all on function sectalk_private.st_v6_workspace_room_policy() from public,anon,authenticated;
create trigger st_v6_workspace_room_policy before insert or update of kind,workspace_id on public.st_v6_rooms
for each row execute function sectalk_private.st_v6_workspace_room_policy();

create or replace function public.st_v6_admit_all(p_meeting uuid)
returns integer language plpgsql security definer set search_path='' as $$
begin
  perform sectalk_private.limit_action('v6_bulk_admit_policy',45);
  if not sectalk_private.st_v3_is_host(p_meeting,auth.uid()) or not sectalk_private.st_v2_active(auth.uid())
    then raise exception 'Meeting action unavailable'; end if;
  if exists(select 1 from public.st_v3_meetings m join public.st_v6_workspace_policy p on p.workspace_id=m.workspace_id
    where m.id=p_meeting and not p.bulk_admit) then raise exception 'This workspace requires individual meeting admission'; end if;
  return sectalk_private.st_v6_lobby_decide(p_meeting,null,true);
end $$;

commit;
