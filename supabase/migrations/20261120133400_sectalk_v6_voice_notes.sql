begin;
alter table public.st_messages add column voice_note boolean not null default false,
  add column voice_transcript boolean not null default false;

create table sectalk_private.st_v6_voice_note (
  message uuid primary key references public.st_messages on delete cascade,
  sender uuid not null references public.st_profiles on delete cascade,
  created_at timestamptz not null default clock_timestamp(),
  sealed bytea not null check(octet_length(sealed) between 2028 and 960028),
  speech_allowed boolean not null default false,
  transcript bytea check(octet_length(transcript)<=4124),
  attempt_at timestamptz
);
create index st_v6_voice_sender_idx on sectalk_private.st_v6_voice_note(sender,created_at);
alter table sectalk_private.st_v6_voice_note enable row level security;
revoke all on sectalk_private.st_v6_voice_note from public,anon,authenticated;

create function public.st_v6_voice_note_command(p_action text,p_actor uuid,p_chat uuid,p_message uuid,
  p_cipher text default null,p_speech boolean default false,p_seconds integer default 0)
returns jsonb language plpgsql security definer set search_path='' as $$
declare
  item public.st_messages;
  clip sectalk_private.st_v6_voice_note;
  data_bytes bytea;
begin
  if p_message is null or p_chat is null or not coalesce(sectalk_private.st_v2_active(p_actor),false)
    or not coalesce(sectalk_private.st_v2_chat_write(p_chat,p_actor),false) then return null; end if;
  if p_action='create' then
    if p_cipher is null or length(p_cipher)>1280040 or p_seconds is null or p_seconds not in (0,60,3600,86400,604800) then return null; end if;
    perform pg_advisory_xact_lock(hashtextextended(p_actor::text,222));
    perform id from public.st_chats where id=p_chat for update;
    select * into item from public.st_messages where id=p_message for update;
    if found then
      if item.chat_id=p_chat and item.sender=p_actor and item.voice_note and item.revoked_at is null
        and (item.expires_at is null or item.expires_at>clock_timestamp()) then return jsonb_build_object('ok',true); end if;
      return null;
    end if;
    if (select count(*) from sectalk_private.st_v6_voice_note where sender=p_actor
      and created_at>clock_timestamp()-interval '1 minute')>=10 then return null; end if;
    data_bytes:=decode(p_cipher,'base64');
    if octet_length(data_bytes) not between 2028 and 960028 or (select coalesce(sum(octet_length(sealed)),0)
      from sectalk_private.st_v6_voice_note where sender=p_actor)+octet_length(data_bytes)>268435456 then return null; end if;
    if sectalk_private.st_v6_write_message(p_actor,p_chat,p_message,'Voice note') is distinct from 'sent' then return null; end if;
    update public.st_messages set voice_note=true,expires_at=case when p_seconds>0
      then created_at+make_interval(secs=>p_seconds) end where id=p_message;
    insert into sectalk_private.st_v6_voice_note(message,sender,sealed,speech_allowed)
      values(p_message,p_actor,data_bytes,coalesce(p_speech,false));
    return jsonb_build_object('ok',true);
  end if;

  select * into item from public.st_messages m where m.id=p_message and m.chat_id=p_chat and m.voice_note
    and m.revoked_at is null and (m.expires_at is null or m.expires_at>clock_timestamp())
    and not exists(select 1 from public.st_v5_hidden_messages h where h.message_id=m.id and h.user_id=p_actor)
    for share;
  if not found then return null; end if;
  if p_action in ('begin_speech','save_speech') then
    select * into clip from sectalk_private.st_v6_voice_note where message=p_message for update;
    if not found or clip.sender is distinct from p_actor or not clip.speech_allowed then return null; end if;
    if p_action='begin_speech' then
      if clip.transcript is not null then return jsonb_build_object('done',true); end if;
      if clip.attempt_at>clock_timestamp()-interval '45 seconds' then return null; end if;
      update sectalk_private.st_v6_voice_note set attempt_at=clock_timestamp() where message=p_message;
    else
      if clip.attempt_at is null or clip.attempt_at<clock_timestamp()-interval '45 seconds' or clip.transcript is not null
        or p_cipher is null or length(p_cipher)>5500 then return null; end if;
      update sectalk_private.st_v6_voice_note set transcript=decode(p_cipher,'base64') where message=p_message;
      update public.st_messages set voice_transcript=true where id=p_message;
      return jsonb_build_object('ok',true);
    end if;
  elsif p_action='read' then
    select * into clip from sectalk_private.st_v6_voice_note where message=p_message;
    if not found then return null; end if;
  else return null;
  end if;
  return jsonb_build_object('audio',encode(clip.sealed,'base64'),'speech',encode(clip.transcript,'base64'),
    'canTranscribe',clip.sender=p_actor and clip.speech_allowed,'expiresAt',item.expires_at);
end
$$;
revoke all on function public.st_v6_voice_note_command(text,uuid,uuid,uuid,text,boolean,integer) from public,anon,authenticated;
grant execute on function public.st_v6_voice_note_command(text,uuid,uuid,uuid,text,boolean,integer) to service_role;

create function sectalk_private.st_v6_voice_note_message_lifecycle()
returns trigger language plpgsql security definer set search_path='' as $$
begin
  if old.voice_note and new.revoked_at is not null then
    delete from sectalk_private.st_v6_voice_note where message=old.id;
  elsif old.voice_note and (not new.voice_note or new.body is distinct from old.body) then
    raise exception 'Voice note content cannot be edited' using errcode='42501';
  end if;
  return new;
end
$$;
revoke all on function sectalk_private.st_v6_voice_note_message_lifecycle() from public,anon,authenticated;
create trigger st_v6_voice_note_message_lifecycle after update of voice_note,body,revoked_at on public.st_messages
for each row execute function sectalk_private.st_v6_voice_note_message_lifecycle();
commit;
