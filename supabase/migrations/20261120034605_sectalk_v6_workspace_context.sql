begin;

create function sectalk_private.st_v6_workspace_membership_hint()
returns trigger language plpgsql security definer set search_path='' as $$
declare recipient uuid;
begin
  if tg_op='DELETE' then recipient:=old.user_id;
  else recipient:=new.user_id;
  end if;
  perform realtime.send('{}'::jsonb,'workspace_memberships','st:account:'||recipient::text,true);
  return null;
end $$;

revoke all on function sectalk_private.st_v6_workspace_membership_hint() from public,anon,authenticated;

create trigger st_v6_workspace_membership_hint
after insert or update of role or delete on public.st_v2_members
for each row execute function sectalk_private.st_v6_workspace_membership_hint();

commit;
