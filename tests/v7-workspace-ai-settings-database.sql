begin;

do $$
declare
  organizer uuid:=gen_random_uuid();
  participant uuid:=gen_random_uuid();
  manager uuid:=gen_random_uuid();
  workspace uuid:=gen_random_uuid();
  live_meeting uuid:=gen_random_uuid();
  ended_meeting uuid:=gen_random_uuid();
  room uuid:=gen_random_uuid();
  root uuid:=gen_random_uuid();
  lease uuid:=gen_random_uuid();
  revision text;
  state jsonb;
begin
  insert into auth.users(id,email) values
    (organizer,'workspace-ai-owner@example.invalid'),(participant,'workspace-ai-peer@example.invalid'),
    (manager,'workspace-ai-admin@example.invalid');
  insert into public.st_profiles(id,handle,name) values
    (organizer,'workspace_ai_owner','AI organizer'),(participant,'workspace_ai_peer','AI participant'),
    (manager,'workspace_ai_admin','AI manager');
  insert into public.st_v2_workspaces(id,name,owner) values(workspace,'Workspace AI SQL fixture',organizer);
  insert into public.st_v2_members(workspace_id,user_id,role) values
    (workspace,organizer,'owner'),(workspace,participant,'member'),(workspace,manager,'admin');
  insert into public.st_v3_meetings(id,workspace_id,host_id,title,status,starts_at,ends_at) values
    (live_meeting,workspace,organizer,'Active policy test','live',now()-interval '1 minute',now()+interval '30 minutes'),
    (ended_meeting,workspace,organizer,'Transcript policy test','ended',now()-interval '26 hours',now()-interval '22 hours');
  insert into public.st_v3_attendance(meeting_id,user_id,status,admitted_at)
    values(live_meeting,organizer,'admitted',now());
  insert into sectalk_private.st_v6_caption_session(meeting,source_language,expires_at,line_count)
    values(ended_meeting,'en',now()-interval '22 hours',2);
  insert into sectalk_private.st_v6_caption_consent(meeting,actor,participant_sid)
    values(ended_meeting,organizer,'PA_fixture_archive');
  insert into sectalk_private.st_v6_caption_line(meeting,actor,sequence,speaker,line,spoken_at) values
    (ended_meeting,organizer,1,'AI organizer','Older retained text for policy test.',now()-interval '25 hours'),
    (ended_meeting,organizer,2,'AI organizer','Current retained text for policy test.',now()-interval '23 hours');

  if has_function_privilege('anon','public.st_v7_workspace_ai_settings(uuid,boolean,boolean,integer,integer)','execute')
    or has_function_privilege('authenticated','sectalk_private.st_v7_purge_ai_transcript(integer)','execute')
    or has_table_privilege('authenticated','sectalk_private.st_v7_workspace_ai_policy','select') then
    raise exception 'Private policy or artifact worker exposed';
  end if;
  perform set_config('request.jwt.claims',jsonb_build_object('sub',participant,'aal','aal1')::text,true);
  set local role authenticated;
  begin
    perform public.st_v7_workspace_ai_settings(workspace);
    raise exception 'Member read manager settings';
  exception when insufficient_privilege then null; end;
  reset role;
  perform set_config('request.jwt.claims',jsonb_build_object('sub',manager,'aal','aal1')::text,true);
  set local role authenticated;
  if (public.st_v7_workspace_ai_settings(workspace)->>'owner')::boolean is distinct from false then
    raise exception 'Workspace admin could not read settings with read-only role';
  end if;
  begin
    perform public.st_v7_workspace_ai_settings(workspace,false,false,1,30);
    raise exception 'Workspace admin changed owner policy';
  exception when insufficient_privilege then null; end;
  reset role;

  perform set_config('request.jwt.claims',jsonb_build_object('sub',organizer,'aal','aal1')::text,true);
  set local role authenticated;
  begin
    perform public.st_v7_workspace_ai_settings(workspace,true,true,4,30);
    raise exception 'Threshold upper bound ignored';
  exception when invalid_parameter_value then null; end;
  begin
    perform public.st_v7_workspace_ai_settings(workspace,true,true,2,91);
    raise exception 'Retention upper bound ignored';
  exception when invalid_parameter_value then null; end;
  perform public.st_v6_room_create(room,workspace,'AI fixture room','public','blank');
  perform public.st_v6_room_post(room,root,'A concrete fixture plan should be reviewed.','message',null);
  reset role;
  perform public.st_v6_room_thread_summary_command(room,root,organizer,'policy',true);
  if public.st_v6_room_thread_summary_command(room,root,organizer,'source',null) is not null then
    raise exception 'Workspace controls bypassed person-level thread consent';
  end if;
  perform public.st_v6_room_thread_summary_command(room,root,organizer,'opt-in',null);
  revision:=public.st_v6_room_thread_summary_command(room,root,organizer,'source',null)->>'revision';
  if revision is null then raise exception 'Thread fixtures never participated'; end if;

  perform public.st_v6_meeting_summary_command(ended_meeting,organizer,'policy',true);
  perform public.st_v6_meeting_summary_command(ended_meeting,organizer,'opt-in');
  if jsonb_array_length(public.st_v6_meeting_summary_command(ended_meeting,organizer,'source')->'source')<>2 then
    raise exception 'Baseline retained caption source unavailable';
  end if;
  perform public.st_v6_meeting_caption_command(live_meeting,organizer,'start','PA_fixture_live','en');
  perform public.st_v6_meeting_caption_command(live_meeting,organizer,'join','PA_fixture_live');
  if public.st_v6_meeting_caption_command(live_meeting,organizer,'reserve','PA_fixture_live',null,lease) is null then
    raise exception 'Caption fixture failed to reserve';
  end if;

  set local role authenticated;
  perform public.st_v7_workspace_ai_settings(workspace,true,false,3,1);
  reset role;
  state:=public.st_v6_meeting_caption_command(ended_meeting,organizer,'view');
  if state->>'workspaceEnabled'<>'false' or jsonb_array_length(state->'lines')<>0
    or public.st_v6_meeting_caption_command(live_meeting,organizer,'process','PA_fixture_live',null,lease) is not null
    or public.st_v6_meeting_caption_command(live_meeting,organizer,'publish','PA_fixture_live',null,lease,'Late worker text.') is not null
    or public.st_v6_meeting_summary_command(ended_meeting,organizer,'source') is not null
    or public.st_v6_room_thread_summary_command(room,root,organizer,'source',null) is not null then
    raise exception 'Disabled content handling leaked artifacts or accepted in-flight processing';
  end if;

  set local role authenticated;
  perform public.st_v7_workspace_ai_settings(workspace,true,true,3,90);
  reset role;
  state:=public.st_v6_meeting_caption_command(ended_meeting,organizer,'view');
  if jsonb_array_length(state->'lines')<>1 or state#>>'{lines,0,line}'<>'Current retained text for policy test.'
    or jsonb_array_length(public.st_v6_meeting_summary_command(ended_meeting,organizer,'source')->'source')<>1 then
    raise exception 'Expanded retention resurrected previously expired text';
  end if;
  if public.st_v6_meeting_caption_command(live_meeting,organizer,'process','PA_fixture_live',null,lease) is not null
    or public.st_v6_meeting_caption_command(live_meeting,organizer,'publish','PA_fixture_live',null,lease,'Stale worker text.') is not null then
    raise exception 'Re-enabling processing revived a lease from a previous policy epoch';
  end if;
  if (public.st_v6_room_thread_summary_command(room,root,organizer,'source',null)->>'revision') is not distinct from revision then
    raise exception 'Tenant policy epoch failed to invalidate earlier draft';
  end if;
  perform sectalk_private.st_v7_purge_ai_transcript(2000);
  if exists(select 1 from sectalk_private.st_v6_caption_line where meeting=ended_meeting and sequence=1)
    or not exists(select 1 from sectalk_private.st_v6_caption_line where meeting=ended_meeting and sequence=2)
    or not exists(select 1 from public.st_v2_workspace_audit where workspace_id=workspace and event='workspace.ai_policy') then
    raise exception 'Scheduled cleanup or policy audit failed';
  end if;
end $$;

select 'passed: role and range checks, opt-in preservation, in-flight caption denial, revocation, retention and purge' as result;
rollback;
