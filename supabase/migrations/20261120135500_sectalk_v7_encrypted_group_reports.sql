begin;

alter table public.st_reports alter column chat_id drop not null,
  add column group_chat_id uuid,
  add column group_message_id uuid,
  add constraint st_reports_conversation_source check (
    (chat_id is not null and group_chat_id is null and group_message_id is null)
    or (chat_id is null and message_id is null and group_chat_id is not null and group_message_id is not null)
  );
create unique index st_group_report_once on public.st_reports(reporter,group_chat_id,group_message_id)
  where group_chat_id is not null;

create function public.st_report_group_message(p_group uuid,p_message uuid,p_category text,p_share boolean,p_evidence text default null)
returns uuid language plpgsql security definer set search_path='' as $$
declare me uuid:=auth.uid(); local_device uuid; subject_id uuid; report_id uuid;
begin
  if not coalesce(sectalk_private.st_v7_manage_sessions(),false)
    or not coalesce(sectalk_private.st_v2_active(me),false) then
    raise exception using errcode='42501',message='Sign in on an approved device to report a group message';
  end if;
  select d.id into local_device from sectalk_private.st_v7_device_sessions s
    join sectalk_private.st_v7_devices d on (d.owner,d.id)=(s.owner,s.device_id)
    where s.owner=me and s.session_id::text=auth.jwt()->>'session_id' and d.state in ('trusted','managed');
  if local_device is null then raise exception using errcode='42501',message='Approved device required'; end if;
  if p_category is null or p_category not in ('scam','harassment','threat','impersonation','other')
    or p_share is null or (not p_share and p_evidence is not null)
    or (p_share and (p_evidence is null or btrim(p_evidence)='' or octet_length(p_evidence)>4000)) then
    raise exception using errcode='22023',message='Choose a report category and confirm any text you want to share';
  end if;
  perform 1 from sectalk_private.st_group_chats g where g.id=p_group for share;
  if not found then raise exception using errcode='42501',message='Group message unavailable'; end if;
  select m.actor into subject_id from sectalk_private.st_group_messages m
    where m.group_id=p_group and m.id=p_message and m.actor<>me
      and exists(select 1 from sectalk_private.st_group_members member where member.group_id=p_group and member.actor=me)
      and exists(select 1 from sectalk_private.st_group_envelopes e where e.group_id=p_group and e.epoch=m.epoch and e.device=local_device);
  if subject_id is null then raise exception using errcode='42501',message='Group message unavailable'; end if;
  perform sectalk_private.limit_action('report',5);
  -- The server cannot authenticate the cleartext; it is a reporter-supplied statement, with no key disclosure.
  insert into public.st_reports(reporter,subject,group_chat_id,group_message_id,category,details,evidence)
    values(me,subject_id,p_group,p_message,p_category,
      case when p_share then 'Encrypted group message. The attached text was provided by the reporter and cannot be verified by the server.'
        else 'Encrypted group message. The reporter did not share message text.' end,
      case when p_share then p_evidence end)
    on conflict (reporter,group_chat_id,group_message_id) where group_chat_id is not null do nothing
    returning id into report_id;
  if report_id is null then
    select r.id into report_id from public.st_reports r where r.reporter=me and r.group_chat_id=p_group and r.group_message_id=p_message;
  end if;
  return report_id;
end $$;
revoke execute on function public.st_report_group_message(uuid,uuid,text,boolean,text) from public,anon;
grant execute on function public.st_report_group_message(uuid,uuid,text,boolean,text) to authenticated;

commit;
