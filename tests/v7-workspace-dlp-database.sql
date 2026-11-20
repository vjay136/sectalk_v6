begin;

do $$
declare
  owner_id uuid:=gen_random_uuid(); member_id uuid:=gen_random_uuid(); outsider_id uuid:=gen_random_uuid();
  actor uuid; native_session uuid:=gen_random_uuid(); factor uuid:=gen_random_uuid();
  workspace uuid; room uuid:=gen_random_uuid(); channel uuid; invite uuid;
  warning_id uuid:=gen_random_uuid(); redact_id uuid:=gen_random_uuid(); blocked_id uuid:=gen_random_uuid();
  owner_claims text; member_claims text; content text;
  policy jsonb:='{"pii":"warn","phi":"redact","payment_card":"block","credential":"redact"}';
begin
  foreach actor in array array[owner_id,member_id,outsider_id] loop
    insert into auth.users(id,email) values(actor,actor||'@example.invalid');
    insert into public.st_profiles(id,handle,name) values(actor,'dlp_'||left(actor::text,8),'Data policy fixture');
  end loop;
  insert into auth.mfa_factors(id,user_id,factor_type,status,created_at,updated_at)
    values(factor,owner_id,'totp','verified',now(),now());
  insert into auth.sessions(id,user_id,aal,factor_id) values(native_session,owner_id,'aal2',factor);
  insert into auth.mfa_amr_claims(id,session_id,authentication_method,created_at,updated_at)
    values(gen_random_uuid(),native_session,'totp',now(),now());
  owner_claims:=jsonb_build_object('sub',owner_id,'role','authenticated','aal','aal2','session_id',native_session)::text;
  member_claims:=jsonb_build_object('sub',member_id,'role','authenticated')::text;
  perform set_config('request.jwt.claims',owner_claims,true);
  set local role authenticated;
  workspace:=public.st_v2_create_workspace('Data policy QA');
  select id into channel from public.st_v2_channels where workspace_id=workspace limit 1;
  perform public.st_v6_room_create(room,workspace,'DLP room','public','blank');
  perform public.st_v2_invite(workspace,'dlp_'||left(member_id::text,8));
  if public.st_v7_set_workspace_dlp(workspace,0,policy)<>1 then raise exception 'Revision creation failed'; end if;
  begin
    perform public.st_v7_set_workspace_dlp(workspace,0,policy);
    raise exception 'A stale policy write succeeded';
  exception when sqlstate 'PT409' then null; end;

  perform set_config('request.jwt.claims',member_claims,true);
  select id into invite from public.st_v2_invites where workspace_id=workspace;
  perform public.st_v2_reply_invite(invite,true);
  perform public.st_v6_room_membership(room,'join');
  begin
    perform public.st_v7_workspace_dlp(workspace);
    raise exception 'Regular member saw administrative data loss rules';
  exception when insufficient_privilege then null; end;

  begin
    perform public.st_v6_room_post(room,blocked_id,'Fixture 4111 1111 1111 1111');
    raise exception 'Known test card was published despite block';
  exception when sqlstate 'PT422' then null; end;
  if exists(select 1 from public.st_v6_room_posts p where p.id=blocked_id) then raise exception 'Blocked row persisted'; end if;
  perform public.st_v6_room_post(room,gen_random_uuid(),'Number 4111 1111 1111 1112 is not a valid checksum');

  begin
    perform public.st_v6_room_post(room,warning_id,'Please email review@example.invalid next week');
    raise exception 'Warning passed without confirmation';
  exception when sqlstate 'PT428' then null; end;
  perform public.st_v7_acknowledge_dlp('room',room,warning_id,'Please email review@example.invalid next week');
  begin
    perform public.st_v6_room_post(room,warning_id,'Please email changed@example.invalid next week');
    raise exception 'A warning confirmation was reused for changed text';
  exception when sqlstate 'PT428' then null; end;
  perform public.st_v6_room_post(room,warning_id,'Please email review@example.invalid next week');
  perform public.st_v6_room_post(room,warning_id,'Please email review@example.invalid next week');

  perform public.st_v2_post(channel,redact_id,'Report MRN: LOCAL-448 and API key=fixture_token_QA');
  perform public.st_v2_post(channel,redact_id,'Report MRN: LOCAL-448 and API key=fixture_token_QA');
  select p.body into content from public.st_v2_posts p where p.id=redact_id;
  if content is distinct from 'Report […] and […]' then raise exception 'Redaction or idempotence failed'; end if;
  reset role;
  if has_table_privilege('authenticated','sectalk_private.st_v7_dlp_delivery_receipts','select')
    or has_table_privilege('authenticated','sectalk_private.st_v7_dlp_acknowledgements','select') then
    raise exception 'DLP private fingerprints were exposed';
  end if;

  set local role authenticated;
  perform public.st_v6_room_post_action(room,warning_id,'edit','Health identifier Patient ID: QA-4002');
  select p.body into content from public.st_v6_room_posts p where p.id=warning_id;
  if content is distinct from 'Health identifier […]' then raise exception 'Edit bypassed DLP'; end if;
  perform set_config('request.jwt.claims',jsonb_build_object('sub',outsider_id,'role','authenticated')::text,true);
  begin
    perform public.st_v7_acknowledge_dlp('room',room,warning_id,'someone@example.invalid');
    raise exception 'Outsider acquired a DLP warning receipt';
  exception when insufficient_privilege then null; end;
  reset role;
end $$;

select 'passed: workspace scope, native MFA policy, exact warning confirmation, validated card block, masked delivery and edits, retry and private receipt ACL' as result;
rollback;
