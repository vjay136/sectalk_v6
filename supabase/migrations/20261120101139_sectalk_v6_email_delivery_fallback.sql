begin;

alter table sectalk_private.st_v6_notification_delivery_events
  add column channel text not null default 'web_push' check(channel in ('web_push','email')),
  add column consent_version uuid,
  add column window_start timestamptz,
  add column window_end timestamptz,
  add constraint st_v6_delivery_email_window check (
    (channel='web_push' and num_nonnulls(consent_version,window_start,window_end)=0) or
    (channel='email' and num_nonnulls(consent_version,window_start,window_end)=3 and window_start<=window_end)
  );

alter table sectalk_private.st_v6_notification_dead_letters
  add column id uuid not null default gen_random_uuid(),
  add column email_event_id uuid references sectalk_private.st_v6_notification_delivery_events on delete cascade,
  drop constraint st_v6_notification_dead_letters_pkey,
  drop constraint st_v6_notification_dead_letters_channel_check,
  alter column job_id drop not null,
  add primary key(id),
  add unique(job_id),
  add unique(email_event_id),
  add constraint st_v6_dead_letter_channel check (
    (channel='web_push' and job_id is not null and email_event_id is null)
    or (channel='email' and job_id is null and email_event_id is not null)
  );

alter table sectalk_private.st_v6_notification_email
  add column consent_version uuid not null default gen_random_uuid(),
  add column delivery_id uuid references sectalk_private.st_v6_notification_delivery_events on delete set null;
create index st_v6_email_pending_delivery on sectalk_private.st_v6_notification_email(delivery_id) where delivery_id is not null;

create function sectalk_private.st_v6_notification_email_consent_change()
returns trigger language plpgsql set search_path='' as $$
begin
  if (new.email_at_consent,new.enabled,new.cadence,new.categories) is distinct from
     (old.email_at_consent,old.enabled,old.cadence,old.categories) then
    update sectalk_private.st_v6_notification_delivery_events e
    set state='discarded',completed_at=clock_timestamp()
    where e.id=old.delivery_id and e.state='pending';
    new.consent_version:=gen_random_uuid();
    new.delivery_id:=null;
  end if;
  return new;
end
$$;
create trigger st_v6_email_consent_change before update of email_at_consent,enabled,cadence,categories
on sectalk_private.st_v6_notification_email for each row execute function sectalk_private.st_v6_notification_email_consent_change();

create function sectalk_private.st_v6_notification_email_counts(
  p_recipient uuid,p_categories text[],p_start timestamptz,p_end timestamptz
)
returns table(mentions bigint,tasks bigint,calls bigint)
language sql stable set search_path='' as $$
  select
    case when 'mention'=any(p_categories) then (
      select count(*) from public.st_v3_notifications n
      where n.recipient=p_recipient and n.room_id is not null and n.kind like 'mention.%'
        and n.created_at>p_start and n.created_at<=p_end
        and sectalk_private.st_v6_web_push_allowed(p_recipient,n.kind,n.room_id,null,null)
    ) else 0 end,
    case when 'task'=any(p_categories) then (
      select count(*) from public.st_v6_task_notices n join public.st_v6_tasks t on t.id=n.task_id
      where n.recipient=p_recipient and n.created_at>p_start and n.created_at<=p_end
        and sectalk_private.st_v6_web_push_allowed(p_recipient,'task.'||n.kind,t.room_id,t.chat_id,null)
    ) else 0 end,
    case when 'call'=any(p_categories) then (
      select count(*) from public.st_calls c
      where c.callee=p_recipient and c.expires_at>p_start and c.expires_at<=p_end
        and (c.end_reason='missed' or (c.status='ringing' and c.expires_at<=now()))
        and sectalk_private.st_v6_web_push_allowed(p_recipient,'call.incoming',null,c.chat_id,null)
    ) else 0 end
$$;

create function sectalk_private.st_v6_email_fallback_allowed(
  p_event sectalk_private.st_v6_notification_delivery_events
)
returns boolean language sql stable set search_path='' as $$
  select exists(select 1 from sectalk_private.st_v6_notification_email p
    join auth.users u on u.id=p.recipient
    where p.recipient=p_event.recipient and p.enabled and p.consent_version=p_event.consent_version
      and p.email_at_consent=lower(u.email) and u.email_confirmed_at is not null and coalesce(u.email_change,'')=''
      and sectalk_private.st_v2_active(p.recipient)
      and exists(select 1 from sectalk_private.st_v6_notification_email_counts(
        p.recipient,p.categories,p_event.window_start,p_event.window_end) counts
        where counts.mentions+counts.tasks+counts.calls>0))
$$;

create function sectalk_private.st_v6_complete_email_window(
  p_recipient uuid,p_delivery uuid,p_boundary timestamptz,p_result text
)
returns void language plpgsql set search_path='' as $$
begin
  if p_result in ('provider_rejected','retry_exhausted','expired') then
    insert into sectalk_private.st_v6_notification_dead_letters(email_event_id,channel,reason)
      values(p_delivery,'email',p_result) on conflict(email_event_id) do nothing;
  end if;
  update sectalk_private.st_v6_notification_delivery_events e set
    state=case when p_result='sent' then 'sent'
      when p_result in ('provider_rejected','retry_exhausted','expired')
        and sectalk_private.st_v6_email_fallback_allowed(e) then 'fallback'
      else 'discarded' end,
    completed_at=clock_timestamp()
  where e.id=p_delivery and e.state='pending';
  update sectalk_private.st_v6_notification_email p set scanned_at=p_boundary,
    next_at=now()+sectalk_private.st_v6_email_cadence(p.cadence),window_end=null,
    lease_id=null,attempts=0,delivery_id=null
  where p.recipient=p_recipient;
end
$$;

drop function public.st_v6_claim_notification_email();
create function public.st_v6_claim_notification_email()
returns table(recipient uuid,lease uuid,email text,cadence text,unsubscribe_key uuid,mentions bigint,tasks bigint,calls bigint,delivery_id uuid)
language plpgsql security definer set search_path='' as $$
declare pref record; boundary timestamptz; counts record; event uuid;
begin
  delete from sectalk_private.st_v6_notification_delivery_events e where e.channel='email'
    and e.completed_at<now()-interval '7 days';
  for pref in
    select p.*,u.email as current_email,u.email_confirmed_at,u.email_change
    from sectalk_private.st_v6_notification_email p join auth.users u on u.id=p.recipient
    where p.enabled and p.next_at<=now()
    order by p.next_at,p.recipient limit 20 for update of p skip locked
  loop
    if pref.email_confirmed_at is null or lower(pref.current_email) is distinct from pref.email_at_consent
      or coalesce(pref.email_change,'')<>'' or not sectalk_private.st_v2_active(pref.recipient) then
      update sectalk_private.st_v6_notification_email p set enabled=false,email_at_consent=null,
        lease_id=null,window_end=null,attempts=0 where p.recipient=pref.recipient;
      continue;
    end if;
    boundary:=coalesce(pref.window_end,now());
    event:=pref.delivery_id;
    if event is not null and (boundary<=now()-interval '1 day' or pref.attempts>=3) then
      perform sectalk_private.st_v6_complete_email_window(pref.recipient,event,boundary,
        case when boundary<=now()-interval '1 day' then 'expired' else 'retry_exhausted' end);
      continue;
    end if;
    select * into counts from sectalk_private.st_v6_notification_email_counts(pref.recipient,pref.categories,pref.scanned_at,boundary);
    if counts.mentions+counts.tasks+counts.calls=0 then
      perform sectalk_private.st_v6_complete_email_window(pref.recipient,event,boundary,'discarded');
      continue;
    end if;
    if event is null then
      insert into sectalk_private.st_v6_notification_delivery_events
        (recipient,event_key,kind,channel,consent_version,window_start,window_end)
      values(pref.recipient,'email:'||pref.consent_version||':'||extract(epoch from boundary),'email.digest','email',
        pref.consent_version,pref.scanned_at,boundary)
      on conflict on constraint st_v6_notification_delivery_events_recipient_event_key_key do nothing returning id into event;
      if event is null then
        perform sectalk_private.st_v6_complete_email_window(pref.recipient,null,boundary,'discarded');
        continue;
      end if;
    end if;
    update sectalk_private.st_v6_notification_email p set next_at=now()+interval '45 seconds',
      window_end=boundary,lease_id=gen_random_uuid(),attempts=p.attempts+1,delivery_id=event
    where p.recipient=pref.recipient returning p.lease_id into lease;
    recipient:=pref.recipient;
    email:=pref.current_email;
    cadence:=pref.cadence;
    unsubscribe_key:=pref.unsubscribe_key;
    mentions:=counts.mentions;
    tasks:=counts.tasks;
    calls:=counts.calls;
    delivery_id:=event;
    return next;
  end loop;
end
$$;

create function public.st_v6_finish_notification_email(p_recipient uuid,p_lease uuid,p_result text)
returns void language plpgsql security definer set search_path='' as $$
declare pref sectalk_private.st_v6_notification_email;
begin
  if p_result is null or p_result not in ('sent','retry','rejected','discarded') then return; end if;
  select p.* into pref from sectalk_private.st_v6_notification_email p
  where p.recipient=p_recipient and p.enabled and p.lease_id=p_lease and p.delivery_id is not null
  for update;
  if not found then return; end if;
  if p_result='retry' and pref.attempts<3 then
    update sectalk_private.st_v6_notification_email p
    set next_at=now()+make_interval(secs=>30*pref.attempts),lease_id=null where p.recipient=p_recipient;
    return;
  end if;
  perform sectalk_private.st_v6_complete_email_window(p_recipient,pref.delivery_id,pref.window_end,
    case p_result when 'retry' then 'retry_exhausted' when 'rejected' then 'provider_rejected' else p_result end);
end
$$;

create or replace function public.st_v6_finish_notification_email(p_recipient uuid,p_lease uuid,p_sent boolean)
returns void language sql set search_path=''
return public.st_v6_finish_notification_email(p_recipient,p_lease,case when p_sent then 'sent' else 'retry' end);

create or replace function public.st_v6_confirm_notification_email(p_recipient uuid,p_lease uuid)
returns boolean language sql stable security definer set search_path='' as $$
  select exists(select 1 from sectalk_private.st_v6_notification_email p
    join sectalk_private.st_v6_notification_delivery_events e on e.id=p.delivery_id
    where p.recipient=p_recipient and p.enabled and p.lease_id=p_lease and p.next_at>now()
      and e.state='pending' and sectalk_private.st_v6_email_fallback_allowed(e))
$$;

create or replace function public.st_v6_notification_fallbacks()
returns table(id uuid,kind text,occurred_at timestamptz,read_at timestamptz)
language sql stable security definer set search_path='' as $$
  select e.id,e.kind,e.completed_at,e.read_at
  from sectalk_private.st_v6_notification_delivery_events e
  where e.recipient=auth.uid() and e.state='fallback' and e.completed_at>=now()-interval '7 days'
    and case e.channel when 'email' then sectalk_private.st_v6_email_fallback_allowed(e)
      else sectalk_private.st_v6_web_push_allowed(e.recipient,e.kind,e.room_id,e.chat_id,e.call_id) end
  order by e.completed_at desc,e.id desc limit 100
$$;

revoke all on function sectalk_private.st_v6_notification_email_consent_change(),
  sectalk_private.st_v6_notification_email_counts(uuid,text[],timestamptz,timestamptz),
  sectalk_private.st_v6_email_fallback_allowed(sectalk_private.st_v6_notification_delivery_events),
  sectalk_private.st_v6_complete_email_window(uuid,uuid,timestamptz,text),
  public.st_v6_claim_notification_email(),public.st_v6_finish_notification_email(uuid,uuid,text)
  from public,anon,authenticated,service_role;
grant execute on function public.st_v6_claim_notification_email(),public.st_v6_finish_notification_email(uuid,uuid,text)
  to service_role;

commit;
