begin;
insert into auth.users(id,email) values
  ('0788259d-1521-49f2-ad86-6d41d1eca001','class-owner@example.invalid'),
  ('0788259d-1521-49f2-ad86-6d41d1eca002','class-member@example.invalid');
insert into public.st_profiles(id,handle,name) values
  ('0788259d-1521-49f2-ad86-6d41d1eca001','classification_owner','Classification owner'),
  ('0788259d-1521-49f2-ad86-6d41d1eca002','classification_member','Classification member');
insert into auth.mfa_factors(id,user_id,factor_type,status,created_at,updated_at) values
  ('0788259d-1521-49f2-ad86-6d41d1eca011','0788259d-1521-49f2-ad86-6d41d1eca001','totp','verified',now(),now());
insert into auth.sessions(id,user_id,aal,factor_id) values
  ('0788259d-1521-49f2-ad86-6d41d1eca021','0788259d-1521-49f2-ad86-6d41d1eca001','aal2','0788259d-1521-49f2-ad86-6d41d1eca011');

set local role authenticated;
do $$
declare
  owner_id uuid:='0788259d-1521-49f2-ad86-6d41d1eca001';
  member_id uuid:='0788259d-1521-49f2-ad86-6d41d1eca002';
  owner_claims text:=json_build_object('sub',owner_id,'role','authenticated','aal','aal2',
    'session_id','0788259d-1521-49f2-ad86-6d41d1eca021')::text;
  workspace uuid;
  source uuid:=gen_random_uuid();
  destination uuid:=gen_random_uuid();
  private_room uuid:=gen_random_uuid();
  message uuid:=gen_random_uuid();
  translated uuid:=gen_random_uuid();
  invitation uuid;
begin
  perform set_config('request.jwt.claims',owner_claims,true);
  workspace:=public.st_v2_create_workspace('Classification fixture');
  perform public.st_v6_room_create(source,workspace,'Internal source','public','blank');
  perform public.st_v6_room_create(destination,workspace,'Sharing destination','public','blank');
  perform public.st_v6_room_create(private_room,workspace,'Private records','private','blank');
  perform public.st_v6_room_post(source,message,'Synthetic data classification fixture');
  perform public.st_v6_set_room_forwarding(source,true);
  perform public.st_v6_set_room_forwarding(destination,true);
  if not exists(select 1 from public.st_v6_forward_room_destinations(source) where id=destination)
    or not exists(select 1 from public.st_v6_rooms where id=private_room and classification='confidential')
  then raise exception 'Room classification defaults are inaccurate'; end if;
  perform public.st_v6_set_room_classification(destination,'public');
  if exists(select 1 from public.st_v6_forward_room_destinations(source) where id=destination) then
    raise exception 'The destination offered a classification downgrade'; end if;
  begin
    perform public.st_v6_forward_room(source,message,destination,translated);
    raise exception 'An internal message was forwarded to a public label' using errcode='P0100';
  exception when raise_exception then null; end;
  perform public.st_v6_set_room_classification(source,'public');
  perform public.st_v6_forward_room(source,message,destination,translated);
  if not exists(select 1 from public.st_v6_room_posts where room_id=destination and id=translated and forwarded) then
    raise exception 'Public labeled text did not forward to an eligible destination'; end if;
  perform public.st_v6_set_room_classification(source,'restricted');
  if exists(select 1 from public.st_v6_forward_room_destinations(source)) then
    raise exception 'A restricted room still offered forward targets'; end if;
  begin
    perform public.st_v6_forward_room(source,message,destination,gen_random_uuid());
    raise exception 'A restricted room was bypassed through RPC' using errcode='P0100';
  exception when raise_exception then null; end;
  begin
    perform public.st_v6_set_room_classification(private_room,'internal');
    raise exception 'A private room label fell below the floor' using errcode='P0100';
  exception when raise_exception then null; end;
  if not exists(select 1 from public.st_v6_room_audit where room_id=source and action='room.classification_changed'
    and details->>'from_classification'='public' and details->>'to_classification'='restricted')
  then raise exception 'Classification change was not audited'; end if;
  perform public.st_v2_invite(workspace,'classification_member');
  perform set_config('request.jwt.claims',json_build_object('sub',member_id,'role','authenticated')::text,true);
  select id into invitation from public.st_v2_invites where workspace_id=workspace;
  perform public.st_v2_reply_invite(invitation,true);
  begin
    perform public.st_v6_set_room_classification(source,'internal');
    raise exception 'A regular workspace member changed classification';
  exception when insufficient_privilege then null; end;
end $$;
select 'passed: privacy floors, role and MFA scope, forward downgrade denial and classified audit' as result;
rollback;
