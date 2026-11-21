begin;
do $$
declare
  moderator uuid:=gen_random_uuid();
  participant uuid:=gen_random_uuid();
  outsider uuid:=gen_random_uuid();
  visitor uuid:=gen_random_uuid();
  guest_link uuid:=gen_random_uuid();
  tenant uuid:=gen_random_uuid();
  meeting uuid:=gen_random_uuid();
  protected_meeting uuid:=gen_random_uuid();
  group_call uuid:=gen_random_uuid();
begin
  if has_function_privilege('authenticated','public.st_v8_livekit_signal_admission(text,uuid,uuid,integer)','execute')
    or has_function_privilege('anon','public.st_v8_livekit_signal_admission(text,uuid,uuid,integer)','execute') then
    raise exception 'Client can probe trusted provider admission';
  end if;
  insert into auth.users(id,email) values(moderator,'gate-moderator@example.invalid'),
    (participant,'gate-participant@example.invalid'),(outsider,'gate-outsider@example.invalid');
  insert into public.st_profiles(id,handle,name) values(moderator,'gate_owner','Gate Owner'),
    (participant,'gate_member','Gate Member'),(outsider,'gate_outsider','Gate Outsider');
  insert into public.st_v2_workspaces(id,name,owner) values(tenant,'LiveKit gateway fixture',moderator);
  insert into public.st_v2_members(workspace_id,user_id,role) values(tenant,moderator,'owner'),(tenant,participant,'member');
  insert into public.st_v3_meetings(id,workspace_id,host_id,title,status,starts_at,ends_at)
    values(meeting,tenant,moderator,'Managed fixture','live',now(),now()+interval '30 minutes'),
      (protected_meeting,tenant,moderator,'Protected fixture','live',now(),now()+interval '30 minutes');
  insert into public.st_v3_attendance(meeting_id,user_id,status,admitted_at)
    select m.id,a.id,'admitted',now() from unnest(array[meeting,protected_meeting]) m(id)
      cross join unnest(array[moderator,participant]) a(id);
  insert into sectalk_private.st_v6_guest_policy(meeting,enabled) values(meeting,true);
  insert into sectalk_private.st_v6_guest_link(id,meeting,owner,digest,expires_at)
    values(guest_link,meeting,moderator,repeat('a',64),now()+interval '5 minutes');
  insert into sectalk_private.st_v6_guest_visit(id,link,digest,captcha_digest,display_name,state)
    values(visitor,guest_link,repeat('b',64),repeat('c',64),'Allowed guest','approved');
  insert into sectalk_private.st_v6_group_call(id,owner,topology,sfu_generation)
    values(group_call,moderator,'sfu',5);
  insert into sectalk_private.st_v6_group_member(call_id,actor,state) values(group_call,participant,'joined');
  if not public.st_v6_create_protected_meeting(protected_meeting,moderator) then
    raise exception 'Protected room fixture could not be enabled';
  end if;
  insert into sectalk_private.st_v6_protected_meeting_endpoint(meeting,actor,device,session_id,public_key,verified)
    values(protected_meeting,participant,gen_random_uuid(),gen_random_uuid()::text,repeat('a',87),true);
  set local role service_role;
  if not public.st_v8_livekit_signal_admission('managed',meeting,participant,null)
    or not public.st_v8_livekit_signal_admission('managed',meeting,visitor,null)
    or not public.st_v8_livekit_signal_admission('protected',protected_meeting,participant,null)
    or not public.st_v8_livekit_signal_admission('group',group_call,participant,5)
    or not public.st_v8_livekit_signal_admission('network',participant,participant,null)
    then raise exception 'A currently eligible participant could not enter'; end if;
  if public.st_v8_livekit_signal_admission('managed',meeting,outsider,null)
    or public.st_v8_livekit_signal_admission('managed',protected_meeting,participant,null)
    or public.st_v8_livekit_signal_admission('protected',meeting,participant,null)
    or public.st_v8_livekit_signal_admission('group',group_call,participant,4)
    or public.st_v8_livekit_signal_admission('network',moderator,participant,null)
    then raise exception 'A mismatched scope passed the provider guard'; end if;
  reset role;
  update public.st_v3_attendance a set status='declined',removed_at=now()
    where a.meeting_id=meeting and a.user_id=participant;
  update sectalk_private.st_v6_guest_link l set revoked_at=now() where l.id=guest_link;
  update sectalk_private.st_v6_protected_meeting e set closed=true where e.meeting=protected_meeting;
  update sectalk_private.st_v6_group_call c set topology='mesh' where c.id=group_call;
  set local role service_role;
  if public.st_v8_livekit_signal_admission('managed',meeting,participant,null)
    or public.st_v8_livekit_signal_admission('managed',meeting,visitor,null)
    or public.st_v8_livekit_signal_admission('protected',protected_meeting,participant,null)
    or public.st_v8_livekit_signal_admission('group',group_call,participant,5)
    then raise exception 'Revoked provider scope survived a current-state check'; end if;
  reset role;
end $$;
select 'passed: private provider admission, native scopes, tenant denial and revocation' as result;
rollback;
