begin;
do $$
declare owner_id uuid:=gen_random_uuid(); member uuid:=gen_random_uuid(); owner_session uuid:=gen_random_uuid(); member_session uuid:=gen_random_uuid();
  factor uuid:=gen_random_uuid(); workspace uuid; room uuid:=gen_random_uuid(); post uuid:=gen_random_uuid(); file_id uuid:=gen_random_uuid(); category text; candidate jsonb; before_state jsonb; preview jsonb; after_state jsonb; changed jsonb;
  owner_claim text:=jsonb_build_object('sub',owner_id,'session_id',owner_session,'role','authenticated','aal','aal2')::text;
  member_claim text:=jsonb_build_object('sub',member,'session_id',member_session,'role','authenticated','aal','aal1')::text;
begin
  insert into auth.users(id,email,email_confirmed_at) values(owner_id,'policies-owner@example.invalid',now()),(member,'policies-member@example.invalid',now());
  insert into public.st_profiles values(owner_id,'policies_owner','Policy owner'),(member,'policies_member','Policy member');
  insert into auth.mfa_factors(id,user_id,factor_type,status,created_at,updated_at) values(factor,owner_id,'totp','verified',now(),now());
  insert into auth.sessions(id,user_id,aal,factor_id) values(owner_session,owner_id,'aal2',factor),(member_session,member,'aal1',null);
  set local role authenticated;
  perform set_config('request.jwt.claims',owner_claim,true);
  workspace:=public.st_v2_create_workspace('Policy workspace');
  if public.st_v7_workspace_policies(workspace,'files')->>'access'<>'mfa' then raise exception 'Stale owner read protected policy data'; end if;
  reset role;
  insert into auth.mfa_amr_claims(id,session_id,authentication_method,created_at,updated_at) values(gen_random_uuid(),owner_session,'totp',now(),now());
  insert into public.st_v2_members values(workspace,member,'admin');
  insert into sectalk_private.st_v6_workspace_files(workspace,id,uploader,filename,size_bytes,published_at)
    values(workspace,file_id,owner_id,'Synthetic policy example.txt',16,now());
  set local role authenticated;
  perform set_config('request.jwt.claims',member_claim,true);
  if public.st_v7_workspace_policies(workspace,'files','apply',0,'{"history":true}')->>'access'<>'none' then
    raise exception 'Admin applied owner-only unified policy';
  end if;
  perform set_config('request.jwt.claims',owner_claim,true);

  perform public.st_v6_room_create(room,workspace,'Synthetic policy room','public','blank');
  perform public.st_v6_room_post(room,post,'Synthetic policy target');
  for category,candidate in select * from (values
    ('messaging','{"set":"off","limit":2}'::jsonb),('files','{"history":true}'),('calls','{"paused":true}'),
    ('ai','{"enabled":false,"consent":false,"threshold":2,"days":14}'),('retention','{"days":17}'),
    ('sharing','{"mode":"require","classification_max":"internal","network":"192.0.2.0/24"}'),
    ('dlp','{"pii":"warn","phi":"block","payment_card":"block","credential":"redact"}'),
    ('external','{"domains":["example.invalid"]}')
  ) choices(domain,settings) loop
    before_state:=public.st_v7_workspace_policies(workspace,category);
    preview:=public.st_v7_workspace_policies(workspace,category,'preview',0,candidate);
    if preview->'proposed' is distinct from candidate or public.st_v7_workspace_policies(workspace,category) is distinct from before_state then
      raise exception 'Changed live state or failed to read normalized preview in %',category;
    end if;
    after_state:=public.st_v7_workspace_policies(workspace,category,'apply',0,candidate);
    if after_state->'current' is distinct from candidate or after_state->>'revision'<>'1' then
      raise exception 'Native writer did not activate %',category;
    end if;
    case category
      when 'messaging' then
        begin
          perform public.st_v6_react_room_post(room,post,'👍',true);
          raise exception 'Reaction escaped native policy';
        exception when raise_exception then
          if sqlerrm not like '%unavailable under workspace policy%' then raise; end if;
        end;
      when 'files' then
        if public.st_v6_workspace_file_history_policy_status(workspace)->>'enabled'<>'true' then raise exception 'Native audit policy did not activate'; end if;
      when 'calls' then
        if not exists(select 1 from jsonb_array_elements(public.st_v6_tenant_feature_state(workspace)->'features') f
          where f->>'feature'='recurring_meetings' and f->>'effective'='false' and f->>'paused'='true')
          then raise exception 'Recurring meeting guard ignored pause'; end if;
      when 'ai' then
        if public.st_v7_workspace_ai_settings(workspace)->>'enabled'<>'false' then raise exception 'Managed AI guard ignored disable'; end if;
      when 'retention' then
        if public.st_v6_room_retirement(room)->>'retention_days'<>'17' then raise exception 'Native retirement eligibility ignored policy'; end if;
      when 'sharing' then
        if not (public.st_v7_explain_file_egress('workspace',workspace,file_id,'share')->'reasons') ? 'session_network'
          then raise exception 'Native sharing ignored network condition'; end if;
      when 'dlp' then
        begin
          perform public.st_v6_room_post(room,gen_random_uuid(),'Synthetic patient ID: TEST-0400');
          raise exception 'Managed message ignored native DLP';
        exception when others then if sqlstate<>'PT422' then raise; end if; end;
      when 'external' then
        begin
          perform public.st_v6_workspace_link_create(workspace,'synthetic@outside.invalid',24);
          raise exception 'External invitation ignored domain policy';
        exception when raise_exception then
          if sqlerrm not like '%outside the workspace invitation policy%' then raise; end if;
        end;
    end case;
    begin
      perform public.st_v7_workspace_policies(workspace,category,'apply',0,candidate);
      raise exception 'Stale write was accepted for %',category;
    exception when others then if sqlstate<>'PT409' then raise; end if; end;
    preview:=public.st_v7_workspace_policies(workspace,category,'preview',1,p_target=>0);
    if preview->'proposed' is distinct from before_state->'current' then raise exception 'Rollback preview missed original %',category; end if;
    changed:=public.st_v7_workspace_policies(workspace,category,'rollback',1,p_target=>0);
    if changed->'current' is distinct from before_state->'current' or changed->>'revision'<>'2' then
      raise exception 'Rollback did not apply as new revision for %',category;
    end if;
  end loop;
  -- A legacy surface writes the same policy source and therefore appears here.
  perform public.st_v6_set_workspace_reactions(workspace,'essential',4);
  changed:=public.st_v7_workspace_policies(workspace,'messaging');
  if changed->>'revision'<>'3' or changed#>>'{current,set}'<>'essential' then raise exception 'Legacy write did not version'; end if;
  reset role;
  if (select count(*) from public.st_v2_workspace_audit where workspace_id=workspace and event like 'workspace.policy.%')<>16 then
    raise exception 'Missing apply/rollback audit or preview leaked writes';
  end if;
end
$$;
select 'passed: all eight native validators, isolated previews, versioned apply/rollback, legacy capture, MFA and audit' as result;
rollback;
