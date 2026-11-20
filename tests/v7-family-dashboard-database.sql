begin;
do $$
declare supervisor uuid:=gen_random_uuid(); member uuid:=gen_random_uuid(); peer uuid:=gen_random_uuid();
  sup_session uuid:=gen_random_uuid(); mem_session uuid:=gen_random_uuid(); file uuid:=gen_random_uuid();
  family uuid; relation uuid; chat uuid; token text; config jsonb;
  password text:='synthetic-family-protection';
  sup_claim text:=jsonb_build_object('sub',supervisor,'session_id',sup_session,'role','authenticated','aal','aal1')::text;
  mem_claim text:=jsonb_build_object('sub',member,'session_id',mem_session,'role','authenticated','aal','aal1')::text;
  device uuid:=gen_random_uuid();
begin
  insert into auth.users(id,email,email_confirmed_at) values
    (supervisor,'family-sup@example.invalid',now()),(member,'family-member@example.invalid',now()),(peer,'family-peer@example.invalid',now());
  insert into public.st_profiles values
    (supervisor,'family_supervisor','Family supervisor'),(member,'family_member','Family member'),(peer,'family_peer','Family peer');
  insert into auth.sessions(id,user_id,aal) values(sup_session,supervisor,'aal1'),(mem_session,member,'aal1');
  insert into auth.mfa_amr_claims(id,session_id,authentication_method,created_at,updated_at) values
    (gen_random_uuid(),sup_session,'password',now(),now()),(gen_random_uuid(),mem_session,'password',now(),now());
  insert into sectalk_private.st_v7_devices(id,owner,state,signing_key,agreement_key,bundle_signature)
    values(device,member,'trusted',repeat('D',87),repeat('E',87),repeat('F',86));
  insert into sectalk_private.st_v7_device_sessions(session_id,owner,device_id) values(mem_session,member,device);
  insert into public.st_chats(member_a,member_b,requester,status)
    values(least(member,peer),greatest(member,peer),member,'accepted') returning id into chat;
  insert into public.st_messages(id,chat_id,sender,body) values(file,chat,member,'Private attachment fixture');
  insert into public.st_v5_files(id,chat_id,uploader,message_id,filename,size_bytes)
    values(file,chat,member,file,'family-fixture.txt',12);
  set local role authenticated;
  perform set_config('request.jwt.claims',sup_claim,true);
  family:=public.st_v6_create_typed_workspace(gen_random_uuid(),'Household scope','family');
  reset role;
  insert into public.st_v2_members(workspace_id,user_id,role) values(family,member,'member');
  set local role authenticated;
  relation:=(public.st_v7_managed_account(family,'offer',member)#>>'{relationships,0,id}')::uuid;
  if public.st_v7_family_file_policy(family)<>'[]'::jsonb then raise exception 'Pending relationships exposed device health'; end if;
  perform set_config('request.jwt.claims',mem_claim,true);
  token:=public.st_v6_create_file_share(file,password,900,4);
  -- A client that accepts ordinary oversight without asking for the extra power cannot grant it.
  perform public.st_v7_managed_account(family,'accept',p_link=>relation);
  if public.st_v7_family_file_policy(family)#>>'{0,consent}'<>'false' then raise exception 'Oversight granted extra scope automatically'; end if;
  perform set_config('request.jwt.claims',sup_claim,true);
  begin
    perform public.st_v7_family_file_policy(family,'set',relation,true);
    raise exception 'Guardian added restrictions without participant approval';
  exception when insufficient_privilege then null; end;
  perform set_config('request.jwt.claims',mem_claim,true);
  config:=public.st_v7_family_file_policy(family,'agree',relation);
  if config#>>'{0,restricted}'<>'true' or config#>>'{0,recentTrustedCheck}'<>'true'
    or config::text like '%'||device::text||'%' or config::text like '%'||mem_session::text||'%' then
    raise exception 'File default or coarse-only health disclosure failed';
  end if;
  begin
    perform public.st_v6_create_file_share(file,password,900,4);
    raise exception 'File link issued in protected mode';
  exception when insufficient_privilege then null; end;
  if not exists(select 1 from public.st_messages where id=file and body='Private attachment fixture') then
    raise exception 'Private conversation changed under link protection';
  end if;
  reset role;
  set local role service_role;
  if public.st_v6_access_file_share(token,password,'view') is not null then raise exception 'Old public link bypassed protection'; end if;
  reset role;
  update public.st_v2_members set suspended_at=clock_timestamp() where workspace_id=family and user_id=member;
  update public.st_v2_members set suspended_at=null where workspace_id=family and user_id=member;
  set local role authenticated;
  perform set_config('request.jwt.claims',sup_claim,true);
  if public.st_v7_family_file_policy(family)<>'[]'::jsonb then raise exception 'Revoked relationship retained device or link data'; end if;
  reset role;
  set local role service_role;
  if public.st_v6_access_file_share(token,password,'view')->>'filename' is distinct from 'family-fixture.txt' then
    raise exception 'Ended relationship retained authority';
  end if;
  reset role;
end
$$;
select 'passed: explicit file consent, link mint and redemption enforcement, coarse device health and roster revocation' as result;
rollback;
