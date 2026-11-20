begin;

insert into auth.users(id,email,aud,role) values
  ('69100000-0000-4000-8000-000000000001','reaction-owner@example.invalid','authenticated','authenticated'),
  ('69100000-0000-4000-8000-000000000002','reaction-member@example.invalid','authenticated','authenticated'),
  ('69100000-0000-4000-8000-000000000003','reaction-outsider@example.invalid','authenticated','authenticated');
insert into public.st_profiles(id,handle,name) values
  ('69100000-0000-4000-8000-000000000001','reaction_owner','Reaction owner'),
  ('69100000-0000-4000-8000-000000000002','reaction_member','Reaction member'),
  ('69100000-0000-4000-8000-000000000003','reaction_outsider','Reaction outsider');

set local role authenticated;
do $$
declare
  owner_id constant uuid:='69100000-0000-4000-8000-000000000001';
  member_id constant uuid:='69100000-0000-4000-8000-000000000002';
  outsider_id constant uuid:='69100000-0000-4000-8000-000000000003';
  room constant uuid:=gen_random_uuid();
  separate_room constant uuid:=gen_random_uuid();
  root constant uuid:=gen_random_uuid();
  reply constant uuid:=gen_random_uuid();
  separate_post constant uuid:=gen_random_uuid();
  workspace uuid;
  invite uuid;
  separate_workspace uuid;
begin
  perform set_config('request.jwt.claims',json_build_object('sub',owner_id,'role','authenticated')::text,true);
  workspace:=public.st_v2_create_workspace('Reaction policy fixture');
  perform public.st_v2_invite(workspace,'reaction_member');
  perform public.st_v6_room_create(room,workspace,'Reaction policy room','public','blank');
  perform public.st_v6_room_post(room,root,'Root');
  perform public.st_v6_room_post(room,reply,'Reply','message',root);
  perform public.st_v6_react_room_post(room,root,'[[st:😀|👓]]',true);
  perform public.st_v6_react_room_post(room,root,'[[st:😀|👓]]',true);
  if (select amount from public.st_v6_room_reaction_counts(room,array[root]) where mine) is distinct from 1::bigint
    or (select revision from public.st_v6_room_reaction_changes where room_id=room) is distinct from 1::bigint
    then raise exception 'Default catalog or idempotent add failed'; end if;
  begin
    perform public.st_v6_react_room_post(room,root,'free text',true);
    raise exception 'Invalid emoji accepted' using errcode='P0004';
  exception when raise_exception then null; end;

  perform public.st_v6_set_workspace_reactions(workspace,'native',8);
  begin
    perform public.st_v6_react_room_post(room,root,'[[st:😂|👓]]',true);
    raise exception 'Native-only policy accepted a combination' using errcode='P0004';
  exception when raise_exception then null; end;
  perform public.st_v6_react_room_post(room,root,'[[st:😀|👓]]',false);
  perform public.st_v6_set_workspace_reactions(workspace,'essential',2);
  perform public.st_v6_set_workspace_reactions(workspace,'essential',2);
  if (select count(*) from public.st_v2_workspace_audit where workspace_id=workspace and event='workspace.reaction_policy')<>2
    then raise exception 'A retry duplicated the workspace audit event'; end if;
  perform public.st_v6_react_room_post(room,root,'👍',true);
  perform public.st_v6_react_room_post(room,root,'❤️',true);
  perform public.st_v6_react_room_post(room,reply,'✅',true);
  begin
    perform public.st_v6_react_room_post(room,root,'👀',true);
    raise exception 'Per-message cap bypassed' using errcode='P0004';
  exception when raise_exception then
    if sqlerrm<>'Remove a reaction before adding more' then raise; end if;
  end;
  begin
    perform public.st_v6_react_room_post(room,reply,'😂',true);
    raise exception 'Essential policy accepted a nonessential reaction' using errcode='P0004';
  exception when raise_exception then
    if sqlerrm not like '%workspace policy%' then raise; end if;
  end;

  perform set_config('request.jwt.claims',json_build_object('sub',member_id,'role','authenticated')::text,true);
  select id into invite from public.st_v2_invites where workspace_id=workspace and invitee=member_id;
  perform public.st_v2_reply_invite(invite,true);
  if exists(select 1 from public.st_v6_room_reaction_counts(room,array[root,reply])) or
    exists(select 1 from public.st_v6_room_reaction_changes where room_id=room)
    then raise exception 'Workspace membership exposed reactions before room admission'; end if;
  perform public.st_v6_room_membership(room,'join');
  if (select count(*) from public.st_v6_room_reaction_counts(room,array[root,reply]) where not mine)<>3
    then raise exception 'Member did not see all three reactions as belonging to other members'; end if;
  perform public.st_v6_react_room_post(room,root,'👍',true);
  if (select amount from public.st_v6_room_reaction_counts(room,array[root]) where mine) is distinct from 2::bigint
    then raise exception 'Independent member reaction did not aggregate'; end if;
  begin
    perform public.st_v6_set_workspace_reactions(workspace,'off',1);
    raise exception 'A member changed workspace policy' using errcode='P0004';
  exception when raise_exception then null; end;
  begin
    perform 1 from sectalk_private.st_v6_room_reactions;
    raise exception 'Authenticated role could read raw reactions' using errcode='P0004';
  exception when insufficient_privilege then null; end;

  perform set_config('request.jwt.claims',json_build_object('sub',outsider_id,'role','authenticated')::text,true);
  if exists(select 1 from public.st_v6_workspace_reaction_policy where workspace_id=workspace) or
    exists(select 1 from public.st_v6_room_reaction_counts(room,array[root,reply])) or
    exists(select 1 from public.st_v6_room_reaction_changes where room_id=room)
    then raise exception 'Outsider saw another workspace reaction data'; end if;
  begin
    perform public.st_v6_react_room_post(room,root,'👍',true);
    raise exception 'Outsider could react' using errcode='P0004';
  exception when raise_exception then null; end;
  separate_workspace:=public.st_v2_create_workspace('Independent reactions fixture');
  perform public.st_v6_room_create(separate_room,separate_workspace,'Other room','public','blank');
  perform public.st_v6_room_post(separate_room,separate_post,'Independent message');
  perform public.st_v6_react_room_post(separate_room,separate_post,'😂',true);
  if not exists(select 1 from public.st_v6_room_reaction_counts(separate_room,array[separate_post]) where mine)
    then raise exception 'Policy unexpectedly affected a different workspace'; end if;

  perform set_config('request.jwt.claims',json_build_object('sub',owner_id,'role','authenticated')::text,true);
  perform public.st_v6_set_workspace_reactions(workspace,'off',1);
  begin
    perform public.st_v6_react_room_post(room,reply,'👍',true);
    raise exception 'Disabled reactions could be added' using errcode='P0004';
  exception when raise_exception then null; end;
  perform public.st_v6_react_room_post(room,root,'👍',false);
  if (select amount from public.st_v6_room_reaction_counts(room,array[root]) where emoji='👍' and not mine) is distinct from 1::bigint
    then raise exception 'Removal under tightened policy did not preserve another member reaction'; end if;
  perform public.st_v6_room_post_action(room,reply,'delete');
  if exists(select 1 from public.st_v6_room_reaction_counts(room,array[reply]))
    then raise exception 'Deleted reply exposed its old reactions'; end if;
end $$;
rollback;
