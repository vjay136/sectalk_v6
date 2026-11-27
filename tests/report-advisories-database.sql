begin;

do $$
declare
  moderator uuid:=gen_random_uuid(); author uuid:=gen_random_uuid();
  reporter uuid:=gen_random_uuid(); downstream uuid:=gen_random_uuid();
  actor uuid; session_id uuid; factor_id uuid; claims jsonb:='{}';
  original_chat uuid; destination uuid; source uuid:=gen_random_uuid(); copy uuid:=gen_random_uuid();
  report uuid; identical uuid:=gen_random_uuid();
  sample constant text:='Synthetic report fixture with a disputed claim.';
  note constant text:='Private staff rationale for this test.';
begin
  foreach actor in array array[moderator,author,reporter,downstream] loop
    session_id:=gen_random_uuid();
    factor_id:=gen_random_uuid();
    insert into auth.users(id,email) values(actor,actor||'@example.invalid');
    insert into public.st_profiles(id,handle,name) values(actor,'adv_'||left(actor::text,8),
      case when actor=author then 'Original author' else 'Safety fixture participant' end);
    insert into auth.mfa_factors(id,user_id,factor_type,status,created_at,updated_at)
      values(factor_id,actor,'totp','verified',now(),now());
    insert into auth.sessions(id,user_id,aal,factor_id) values(session_id,actor,'aal2',factor_id);
    insert into auth.mfa_amr_claims(id,session_id,authentication_method,created_at,updated_at)
      values(gen_random_uuid(),session_id,'totp',now(),now());
    claims:=claims||jsonb_build_object(actor::text,
      jsonb_build_object('sub',actor,'role','authenticated','session_id',session_id,'aal','aal2'));
  end loop;
  insert into sectalk_private.staff values(moderator);
  if has_table_privilege('authenticated','sectalk_private.st_message_advisories','SELECT')
    or has_function_privilege('anon','public.st_direct_message_advisories(uuid,uuid[])','EXECUTE') then
    raise exception 'Advisory backing data is exposed';
  end if;

  set local role authenticated;
  perform set_config('request.jwt.claims',claims->>reporter::text,true);
  original_chat:=public.st_request('adv_'||left(author::text,8));
  destination:=public.st_request('adv_'||left(downstream::text,8));
  perform set_config('request.jwt.claims',claims->>author::text,true);
  perform public.st_respond(original_chat,true);
  perform public.st_send(original_chat,source,sample);
  perform set_config('request.jwt.claims',claims->>downstream::text,true);
  perform public.st_respond(destination,true);
  perform set_config('request.jwt.claims',claims->>reporter::text,true);
  report:=public.st_v5_report(original_chat,source,'scam','Private reporter comment for the fixture.',false);
  reset role;
  if (select array_agg(topic) from realtime.messages
      where event='forward_lineage' and payload->>'chat_id'=original_chat::text)
    is distinct from array['st:account:'||reporter::text] then
    raise exception 'A pending complaint broadcast outside the reporter account';
  end if;
  set local role authenticated;
  perform public.st_v6_forward_direct(original_chat,source,destination,copy);
  perform public.st_send(destination,identical,sample);

  if not exists(select from public.st_direct_message_advisories(original_chat,array[source]) where verdict='reported')
    or exists(select from public.st_direct_message_advisories(destination,array[copy])) then
    raise exception 'Unreviewed report leaked to a forward or reporter lost their own marker';
  end if;
  begin
    perform public.st_report_propagation(report);
    raise exception 'Case propagation was visible without the staff role';
  exception when insufficient_privilege then null; end;
  perform set_config('request.jwt.claims',claims->>moderator::text,true);
  begin
    perform public.st_set_report_advisory(report,'warning','fraud',note);
    raise exception 'Published without a final review';
  exception when sqlstate 'PT409' then null; end;
  perform public.st_v8_resolve_direct_report(report,'resolved',note,'The report was reviewed and confirmed.');
  perform public.st_set_report_advisory(report,'warning','fraud',note);
  if (public.st_report_propagation(report)->>'forward_count')::integer<>1
    or (public.st_report_propagation(report)->>'original_name') is distinct from 'Original author'
    or not exists(select from public.st_report_propagation_members(report,0) where original)
    or not exists(select from public.st_report_propagation_members(report,0) where shares=1 and not original) then
    raise exception 'Staff audit omitted the origin or intended recipient counts';
  end if;

  perform set_config('request.jwt.claims',claims->>downstream::text,true);
  if not exists(select from public.st_direct_message_advisories(destination,array[copy,identical])
       where message_id=copy and verdict='warning' and category='fraud')
    or exists(select from public.st_direct_message_advisories(destination,array[identical]))
    or exists(select from public.st_direct_message_advisories(original_chat,array[source])) then
    raise exception 'Warning failed to follow the real forward or leaked to an unrelated message or scope';
  end if;
  perform set_config('request.jwt.claims',claims->>author::text,true);
  perform public.st_v2_edit_message(source,'A different revision');
  if exists(select from public.st_direct_message_advisories(original_chat,array[source])) then
    raise exception 'Warning leaked onto an edited revision';
  end if;
  perform set_config('request.jwt.claims',claims->>moderator::text,true);
  perform public.st_set_report_advisory(report,'remove',null,note);
  perform set_config('request.jwt.claims',claims->>downstream::text,true);
  if exists(select from public.st_direct_message_advisories(destination,array[copy])) then
    raise exception 'Retracted warning remained visible';
  end if;

  reset role;
  if exists(select from realtime.messages
    where event='forward_lineage' and payload->>'chat_id' in (original_chat::text,destination::text)
      and (private is distinct from true or payload-'id'<>jsonb_build_object('chat_id',payload->>'chat_id')
        or topic not in ('st:account:'||reporter::text,
          case payload->>'chat_id' when original_chat::text then 'st:account:'||author::text
            else 'st:account:'||downstream::text end)))
    or (select count(*) from realtime.messages where event='forward_lineage'
      and topic='st:account:'||downstream::text and payload->>'chat_id'=destination::text)<>3 then
    raise exception 'Forward, warning, or retraction hints had the wrong payload or audience';
  end if;
end $$;

select 'passed: exact report revision, scoped pending marker, verified moderation, forwarding, private roster, retraction and private update hints';
rollback;
