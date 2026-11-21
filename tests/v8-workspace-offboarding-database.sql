begin;

do $$
declare owner_id uuid:=gen_random_uuid(); reviewer_id uuid:=gen_random_uuid(); outsider_id uuid:=gen_random_uuid();
  who uuid; session_id uuid; factor_id uuid; claims jsonb:='{}';
  wid uuid; foreign_wid uuid; rid uuid:=gen_random_uuid(); cid uuid; ticket uuid; held uuid:=gen_random_uuid();
  state jsonb; first_material jsonb; note text:='Fixed synthetic workspace scope for audited offboarding.';
  content_id uuid:=gen_random_uuid(); channel_id uuid; foreign_channel uuid; room_id uuid:=gen_random_uuid();
  private_channel uuid; public_post uuid:=gen_random_uuid(); root_post uuid:=gen_random_uuid(); page jsonb; again jsonb;
  fid uuid:=gen_random_uuid(); file_export uuid:=gen_random_uuid(); file_hash text:=repeat('7',64);
  private_room uuid:=gen_random_uuid(); room_file_export uuid:=gen_random_uuid(); house_file uuid:=gen_random_uuid();
  foreign_file uuid:=gen_random_uuid(); room_hash text:=repeat('6',64);
  coverage jsonb; owner_coverage jsonb;
begin
  foreach who in array array[owner_id,reviewer_id,outsider_id] loop
    session_id:=gen_random_uuid(); factor_id:=gen_random_uuid();
    insert into auth.users(id,email) values(who,who||'@example.invalid');
    insert into public.st_profiles(id,handle,name) values(who,'off_'||left(who::text,8),'Offboarding QA');
    insert into auth.mfa_factors(id,user_id,factor_type,status,created_at,updated_at)
      values(factor_id,who,'totp','verified',now(),now());
    insert into auth.sessions(id,user_id,aal,factor_id) values(session_id,who,'aal2',factor_id);
    insert into auth.mfa_amr_claims(id,session_id,authentication_method,created_at,updated_at)
      values(gen_random_uuid(),session_id,'totp',now(),now());
    claims:=claims||jsonb_build_object(who::text,jsonb_build_object('sub',who,'role','authenticated','session_id',session_id,'aal','aal2'));
  end loop;
  perform set_config('request.jwt.claims',claims->>owner_id::text,true);
  wid:=public.st_v2_create_workspace('Offboarding rollback');
  perform set_config('request.jwt.claims',claims->>outsider_id::text,true);
  foreign_wid:=public.st_v2_create_workspace('Offboarding protected other tenant');
  insert into public.st_v2_members(workspace_id,user_id,role) values(wid,reviewer_id,'admin');
  insert into sectalk_private.st_v8_offboarding_reviewers values(wid,reviewer_id);
  -- A pinned but disconnected compliance provider must leave scoped
  -- offboarding inventory grants and their separate two-person check usable.
  insert into sectalk_private.st_v8_workspace_compliance_sso(workspace,protocol,provider)
    values(wid,'saml','disconnected-offboarding-fixture');
  if has_table_privilege('authenticated','sectalk_private.st_v8_offboarding_requests','select')
    or has_function_privilege('anon','public.st_v8_workspace_offboarding(uuid)','execute')
    or has_function_privilege('authenticated','sectalk_private.st_v8_residency_source_coverage(uuid,uuid)','execute')
    then raise exception 'Private state exposed';end if;
  set local role authenticated;
  begin
    perform public.st_v8_workspace_offboarding(wid);
    raise exception 'Other workspace owner accessed request';
  exception when insufficient_privilege then null; end;
  perform set_config('request.jwt.claims',claims->>owner_id::text,true);
  if public.st_v8_workspace_offboarding_change(wid,rid,'requested',wid::text,note)<>rid then
    raise exception 'Exact request ID not retained'; end if;
  begin
    perform public.st_v8_workspace_offboarding_change(wid,rid,'approved',wid::text);
    raise exception 'Owner self-approved';
  exception when insufficient_privilege then null; end;
  perform set_config('request.jwt.claims',claims->>reviewer_id::text,true);
  perform public.st_v8_workspace_offboarding_change(wid,rid,'approved',wid::text);
  perform public.st_v8_workspace_offboarding_change(wid,rid,'approved',wid::text);
  state:=public.st_v8_workspace_offboarding(wid);
  cid:=(state#>>'{request,case}')::uuid;
  if state#>>'{request,manifestSha256}' is null then raise exception 'Approved manifest missing';end if;
  begin
    perform public.st_v7_begin_compliance_operation(cid,'build');
    raise exception 'Reviewer could build owner export';
  exception when insufficient_privilege then null; end;
  perform set_config('request.jwt.claims',claims->>owner_id::text,true);
  if public.st_v7_compliance_access(wid)<>'sso' then raise exception 'Compliance fixture did not require SSO'; end if;
  ticket:=public.st_v7_begin_compliance_operation(cid,'build');
  reset role;
  first_material:=public.st_v7_read_compliance_operation(ticket);
  if first_material->>'bundle' is null then raise exception 'Signed native export material unavailable'; end if;
  begin
    update sectalk_private.st_v8_offboarding_requests set snapshot='{}' where id=rid;
    raise exception 'Snapshot was mutable';
  exception when insufficient_privilege then null; end;
  perform public.st_v7_finish_compliance_operation(ticket,null);
  update public.st_v2_workspaces set name='Workspace renamed after approval' where id=wid;
  set local role authenticated;
  ticket:=public.st_v7_begin_compliance_operation(cid,'build');
  reset role;
  if public.st_v7_read_compliance_operation(ticket) is distinct from first_material then
    raise exception 'A retry changed the approved inventory material'; end if;
  delete from sectalk_private.st_v8_offboarding_reviewers v where (v.workspace,v.actor)=(wid,reviewer_id);
  if public.st_v7_read_compliance_operation(ticket) is not null then
    raise exception 'Revoked reviewer could still authorize an existing export ticket'; end if;
  perform public.st_v7_finish_compliance_operation(ticket,null);
  insert into sectalk_private.st_v6_workspace_holds(id,workspace_id,member_id,reason,placed_by)
    values(held,wid,owner_id,'Do not stage the protected synthetic workspace.',owner_id);
  set local role authenticated;
  begin
    perform public.st_v8_workspace_offboarding_change(wid,rid,'read_only',wid::text);
    raise exception 'Held, undownloaded tenant could stage';
  exception when insufficient_privilege then null; end;
  perform public.st_v8_workspace_offboarding_change(wid,rid,'withdrawn',wid::text);
  perform public.st_v8_workspace_offboarding_change(wid,rid,'withdrawn',wid::text);
  reset role;
  if (select count(*) from sectalk_private.st_v8_offboarding_audit where request=rid)<>3
    or (select c.state from sectalk_private.st_v7_compliance_cases c where c.id=cid)<>'withdrawn'
    or sectalk_private.st_v7_workspace_payment_mode(foreign_wid)->>'mode'<>'active' then
    raise exception 'Withdrawal replay was not tenant-local and idempotent';end if;
  insert into sectalk_private.st_v8_offboarding_reviewers values(wid,reviewer_id);
  channel_id:=public.st_v2_create_channel(wid,'offboarding-content');
  private_channel:=public.st_v2_create_channel(wid,'offboarding-private');
  update public.st_v2_channels c set visibility='private' where c.id=private_channel;
  perform public.st_v2_post(channel_id,public_post,'Shared standard workspace record');
  perform public.st_v2_post(private_channel,gen_random_uuid(),'Private channel stays private');
  perform public.st_v6_room_create(room_id,wid,'Explicit shared room','public','blank');
  update public.st_v6_rooms r set classification='internal' where r.id=room_id;
  insert into public.st_v6_room_members(room_id,user_id,role) values(room_id,reviewer_id,'member');
  perform public.st_v6_room_post(room_id,root_post,'Shared room root message');
  perform public.st_v6_room_post(room_id,gen_random_uuid(),'Shared room reply','message',root_post);
  insert into public.st_v6_tasks(id,room_id,author_id,title)
    values(gen_random_uuid(),room_id,owner_id,'Shared room task');
  insert into public.st_v2_items(workspace_id,kind,title,created_by)
    select wid,'task','Exact task '||i,owner_id from generate_series(1,26) i;
  insert into public.st_v2_items(workspace_id,kind,title,created_by,due_at) values
    (wid,'event','Private source calendar title',owner_id,now()+interval '1 day'),
    (wid,'announcement','Private source announcement',owner_id,null),
    (foreign_wid,'event','Foreign calendar title',outsider_id,now()+interval '1 day');
  insert into public.st_v2_items(workspace_id,kind,title,created_by)
    select wid,'note','Source note '||i,owner_id from generate_series(1,502) i;
  perform set_config('request.jwt.claims',claims->>outsider_id::text,true);
  foreign_channel:=public.st_v2_create_channel(foreign_wid,'offboarding-foreign');
  perform public.st_v2_post(foreign_channel,gen_random_uuid(),'Foreign channel must stay private');
  set local role authenticated;
  perform set_config('request.jwt.claims',claims->>owner_id::text,true);
  perform public.st_v8_offboarding_content(wid,'export_content',content_id,wid::text);
  begin
    perform public.st_v8_offboarding_content(wid,'page',content_id,wid::text);
    raise exception 'Content became available before independent approval';
  exception when insufficient_privilege then null; end;
  begin
    perform public.st_v8_residency_source_coverage(wid,content_id);
    raise exception 'Coverage disclosed counts before independent approval';
  exception when insufficient_privilege then null; end;
  perform set_config('request.jwt.claims',claims->>reviewer_id::text,true);
  perform public.st_v8_offboarding_content(wid,'approve',content_id,wid::text);
  perform public.st_v8_offboarding_content(wid,'approve',content_id,wid::text);
  coverage:=public.st_v8_residency_source_coverage(wid,content_id);
  if coverage->'unsupportedBoardItems' is distinct from
    '[{"kind":"announcement","observed":1,"capped":false},{"kind":"event","observed":1,"capped":false},{"kind":"note","observed":501,"capped":true}]'::jsonb
    or coverage->>'approvedRecords' is distinct from '30'
    or coverage::text like '%Private source%' or coverage::text like '%Foreign calendar%' then
    raise exception 'Unexpected Board coverage or manifest count'; end if;
  perform set_config('request.jwt.claims',claims->>outsider_id::text,true);
  begin
    perform public.st_v8_residency_source_coverage(wid,content_id);
    raise exception 'Coverage disclosed Board counts across workspaces';
  exception when insufficient_privilege then null; end;
  perform set_config('request.jwt.claims',claims->>reviewer_id::text,true);
  begin
    perform public.st_v8_offboarding_content(wid,'page',content_id,wid::text);
    raise exception 'Reviewer could download owner content';
  exception when insufficient_privilege then null; end;
  perform set_config('request.jwt.claims',claims->>owner_id::text,true);
  owner_coverage:=public.st_v8_residency_source_coverage(wid,content_id);
  if owner_coverage is distinct from coverage then
    raise exception 'Source count access differed between reviewer and owner'; end if;
  page:=public.st_v8_offboarding_content(wid,'page',content_id,wid::text);
  again:=public.st_v8_offboarding_content(wid,'page',content_id,wid::text,25);
  if jsonb_array_length(page->'records')<>25 or page->>'next'<>'25'
    or jsonb_array_length(again->'records')<>5 or again->>'next' is not null
    or page->>'manifestSha256' is distinct from again->>'manifestSha256'
    or page::text like '%Private channel stays private%' or page::text like '%Foreign channel must stay private%'
    or page::text not like '%Shared room root message%' or page::text not like '%Shared room reply%'
    or page::text not like '%Shared room task%' then
    raise exception 'Unexpected content scope, manifest, or pagination: %',page->>'next'; end if;
  if page is distinct from public.st_v8_offboarding_content(wid,'page',content_id,wid::text) then
    raise exception 'Page replay changed approved records'; end if;
  reset role;
  update public.st_v2_posts p set body='Changed after approval' where p.id=public_post;
  set local role authenticated;
  begin
    perform public.st_v8_offboarding_content(wid,'page',content_id,wid::text);
    raise exception 'Changed revision was delivered';
  exception when insufficient_privilege then null; end;
  reset role;
  delete from sectalk_private.st_v8_offboarding_reviewers v where (v.workspace,v.actor)=(wid,reviewer_id);
  set local role authenticated;
  begin
    perform public.st_v8_offboarding_content(wid,'page',content_id,wid::text,25);
    raise exception 'Revoked reviewer still authorized another page';
  exception when insufficient_privilege then null; end;
  reset role;
  insert into sectalk_private.st_v8_offboarding_reviewers values(wid,reviewer_id);
  perform public.st_v8_offboarding_content(wid,'withdraw',content_id,wid::text);
  perform public.st_v6_release_workspace_hold(wid,held,'Release disposable fixture hold before file approval.');
  insert into storage.objects(bucket_id,name,metadata) values('sectalk-workspace-files',wid::text||'/'||fid::text,'{"size":11}');
  insert into sectalk_private.st_v6_workspace_files(workspace,id,uploader,filename,size_bytes,published_at,fingerprint)
    values(wid,fid,owner_id,'fixture.txt',11,now(),sectalk_private.st_v6_workspace_file_fingerprint(wid,file_hash));
  set local role authenticated;
  perform public.st_v8_offboarding_content(wid,'export_content_files',file_export,wid::text);
  begin
    perform public.st_v8_offboarding_content(wid,'export_content',file_export,wid::text);
    raise exception 'A retry could remove separate file consent';
  exception when insufficient_privilege then null; end;
  perform set_config('request.jwt.claims',claims->>reviewer_id::text,true);
  perform public.st_v8_offboarding_content(wid,'approve',file_export,wid::text);
  if public.st_v8_offboarding_file_access(wid,file_export,fid,file_hash) is not null then
    raise exception 'Reviewer could receive export-scoped file bytes'; end if;
  perform set_config('request.jwt.claims',claims->>owner_id::text,true);
  if public.st_v8_offboarding_file_access(wid,file_export,fid,file_hash)->>'bytes' is distinct from '11'
    or public.st_v8_offboarding_file_access(wid,file_export,fid,repeat('1',64)) is not null then
    raise exception 'File receipt did not bind approved bytes'; end if;
  reset role;
  insert into sectalk_private.st_v6_malware_hashes(sha256) values(decode(file_hash,'hex'));
  set local role authenticated;
  if public.st_v8_offboarding_file_access(wid,file_export,fid,file_hash) is not null then
    raise exception 'A late malware listing did not deny approval bytes'; end if;
  reset role;
  perform public.st_v8_offboarding_content(wid,'withdraw',file_export,wid::text);
  perform public.st_v6_room_create(private_room,wid,'Tenant private archive fixture','private','blank');
  insert into public.st_v2_members(workspace_id,user_id,role) values(wid,outsider_id,'member');
  insert into public.st_v6_room_members(room_id,user_id,role) values
    (private_room,reviewer_id,'member'),(private_room,outsider_id,'member');
  insert into storage.objects(bucket_id,name,metadata) values
    ('sectalk-workspace-files',wid::text||'/rooms/'||private_room::text||'/'||house_file::text,'{"size":11}'),
    ('sectalk-workspace-files',wid::text||'/rooms/'||private_room::text||'/'||foreign_file::text,'{"size":11}');
  insert into sectalk_private.st_v6_room_files(room,workspace,id,uploader,filename,size_bytes,published_at,sha256) values
    (private_room,wid,house_file,owner_id,'owner.txt',11,now(),room_hash),
    (private_room,wid,foreign_file,outsider_id,'third-party.txt',11,now(),repeat('8',64));
  set local role authenticated;
  perform public.st_v8_offboarding_content(wid,'export_content_room_files',room_file_export,wid::text);
  perform set_config('request.jwt.claims',claims->>reviewer_id::text,true);
  perform public.st_v8_offboarding_content(wid,'approve',room_file_export,wid::text);
  perform set_config('request.jwt.claims',claims->>owner_id::text,true);
  if public.st_v8_offboarding_room_file_access(private_room,room_file_export,house_file,room_hash)->>'bytes' is distinct from '11' then
    raise exception 'Eligible owner-uploaded private room file was not authorized'; end if;
  if public.st_v8_offboarding_room_file_access(private_room,room_file_export,foreign_file,repeat('8',64)) is not null
    or public.st_v8_offboarding_room_file_access(room_id,room_file_export,house_file,room_hash) is not null then
    raise exception 'Private room uploader consent or exact room scope was bypassed'; end if;
  reset role;
  update public.st_v6_rooms set classification='restricted' where id=private_room;
  set local role authenticated;
  if public.st_v8_offboarding_room_file_access(private_room,room_file_export,house_file,room_hash) is not null then
    raise exception 'Restricted source classification retained file access'; end if;
  reset role;
  update public.st_v6_rooms set classification='confidential' where id=private_room;
  delete from public.st_v6_room_members m where m.room_id=private_room and m.user_id=reviewer_id;
  set local role authenticated;
  if public.st_v8_offboarding_room_file_access(private_room,room_file_export,house_file,room_hash) is not null then
    raise exception 'Revoked source membership retained room file access'; end if;
  reset role;
end $$;

select 'passed: exact offboarding scope, native proof, independent approval, immutable snapshot and safe withdrawal' as result;
rollback;
