begin;

do $$
declare
  organizer uuid:=gen_random_uuid();
  participant uuid:=gen_random_uuid();
  outsider uuid:=gen_random_uuid();
  workspace uuid:=gen_random_uuid();
  meeting uuid:=gen_random_uuid();
  original_revision text;
  reply jsonb;
begin
  insert into auth.users(id,email) values
    (organizer,'summary-guard-organizer@example.invalid'),
    (participant,'summary-guard-participant@example.invalid'),
    (outsider,'summary-guard-outsider@example.invalid');
  insert into public.st_profiles(id,handle,name) values
    (organizer,'summary_guard_owner','Guard organizer'),
    (participant,'summary_guard_peer','Guard participant'),
    (outsider,'summary_guard_other','Guard outsider');
  insert into public.st_v2_workspaces(id,name,owner) values(workspace,'Guardrail fixture',organizer);
  insert into public.st_v2_members(workspace_id,user_id,role) values
    (workspace,organizer,'owner'),(workspace,participant,'member');
  insert into public.st_v3_meetings(id,workspace_id,host_id,title,status,starts_at,ends_at)
    values(meeting,workspace,organizer,'Guardrail fixture','ended',now()-interval '30 minutes',now()-interval '5 minutes');
  insert into sectalk_private.st_v6_caption_session(meeting,source_language,expires_at,line_count)
    values(meeting,'en',now()+interval '1 day',2);
  insert into sectalk_private.st_v6_caption_consent(meeting,actor,participant_sid)
    values(meeting,organizer,'PA_fixture_organizer'),(meeting,participant,'PA_fixture_participant');
  insert into sectalk_private.st_v6_caption_line(meeting,actor,sequence,speaker,line) values
    (meeting,organizer,1,'Guard organizer','The project schedule is confirmed.'),
    (meeting,participant,2,'Guard participant','The shared checklist is available.');

  if has_function_privilege('authenticated','public.st_v6_meeting_summary_command(uuid,uuid,text,boolean)','execute')
     or has_function_privilege('anon','public.st_v6_meeting_summary_command(uuid,uuid,text,boolean)','execute')
     or has_table_privilege('authenticated','sectalk_private.st_v6_summary_consent','select')
     or has_table_privilege('authenticated','sectalk_private.st_v6_caption_line','select') then
    raise exception 'Private caption source is accessible outside the service command';
  end if;
  if public.st_v6_meeting_summary_command(meeting,organizer,'source') is not null
     or public.st_v6_meeting_summary_command(meeting,participant,'policy',true) is not null
     or public.st_v6_meeting_summary_command(meeting,outsider,'view') is not null then
    raise exception 'Policy-off, outsider, or unauthorized policy access succeeded';
  end if;
  perform public.st_v6_meeting_summary_command(meeting,organizer,'policy',true);
  if public.st_v6_meeting_summary_command(meeting,organizer,'source') is not null then
    raise exception 'Workspace policy bypassed personal consent';
  end if;
  perform public.st_v6_meeting_summary_command(meeting,organizer,'opt-in');
  reply:=public.st_v6_meeting_summary_command(meeting,organizer,'source');
  if jsonb_array_length(reply->'source')<>1 or reply#>>'{source,0,line}'<>'The project schedule is confirmed.' then
    raise exception 'Source included a fellow participant without summary opt-in';
  end if;
  original_revision:=reply->>'revision';
  perform public.st_v6_meeting_summary_command(meeting,participant,'opt-in');
  reply:=public.st_v6_meeting_summary_command(meeting,organizer,'source');
  if jsonb_array_length(reply->'source')<>2 or (reply->>'revision') is not distinct from original_revision then
    raise exception 'Adding consent did not rotate the source revision';
  end if;
  original_revision:=reply->>'revision';
  reply:=public.st_v6_meeting_summary_command(meeting,organizer,'view');
  if (reply->'source') is distinct from 'null'::jsonb or (reply->>'revision') is distinct from original_revision then
    raise exception 'View exposed raw captions or provided an inconsistent source revision';
  end if;
  perform public.st_v6_meeting_summary_command(meeting,participant,'withdraw');
  reply:=public.st_v6_meeting_summary_command(meeting,organizer,'source');
  if jsonb_array_length(reply->'source')<>1 or (reply->>'revision') is not distinct from original_revision then
    raise exception 'Withdrawing consent did not invalidate the earlier draft revision';
  end if;
  perform public.st_v6_meeting_summary_command(meeting,organizer,'policy',false);
  perform public.st_v6_meeting_summary_command(meeting,organizer,'policy',true);
  if public.st_v6_meeting_summary_command(meeting,organizer,'source') is not null then
    raise exception 'Turning policy off and on silently restored consent';
  end if;
end
$$;

select 'passed: scoped summary input, policy, consent, private source and revision boundaries' as result;
rollback;
