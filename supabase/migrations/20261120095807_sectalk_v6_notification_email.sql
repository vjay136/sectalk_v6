begin;

create table sectalk_private.st_v6_notification_email (
  recipient uuid primary key references public.st_profiles on delete cascade,
  email_at_consent text,
  enabled boolean not null,
  cadence text not null check(cadence in ('prompt','daily','weekly')),
  categories text[] not null check(categories<@array['mention','task','call']),
  unsubscribe_key uuid not null unique default gen_random_uuid(),
  scanned_at timestamptz not null default now(),
  next_at timestamptz not null default now(),
  window_end timestamptz,
  lease_id uuid,
  attempts smallint not null default 0
);
create index st_v6_notification_email_due on sectalk_private.st_v6_notification_email(next_at,recipient) where enabled;
alter table sectalk_private.st_v6_notification_email enable row level security;
revoke all on sectalk_private.st_v6_notification_email from public,anon,authenticated,service_role;

create function sectalk_private.st_v6_email_cadence(p_cadence text)
returns interval language sql immutable set search_path='' as $$
  select case p_cadence when 'prompt' then interval '1 minute'
    when 'daily' then interval '24 hours' else interval '7 days' end
$$;

create function public.st_v6_notification_email_settings()
returns jsonb language sql stable security definer set search_path='' as $$
  select jsonb_build_object('available',u.email is not null and u.email_confirmed_at is not null and coalesce(u.email_change,'')='',
    'enabled',coalesce(p.enabled and p.email_at_consent=lower(u.email)
      and u.email_confirmed_at is not null and coalesce(u.email_change,'')='',false),
    'cadence',coalesce(p.cadence,'daily'),'categories',coalesce(p.categories,'{}'))
  from auth.users u left join sectalk_private.st_v6_notification_email p on p.recipient=u.id
  where u.id=auth.uid()
$$;

create function public.st_v6_set_notification_email(p_enabled boolean,p_cadence text,p_categories text[])
returns void language plpgsql security definer set search_path='' as $$
declare actor uuid:=auth.uid(); mailbox text; categories text[];
begin
  if actor is null or p_enabled is null or p_cadence is null or p_cadence not in ('prompt','daily','weekly')
    or p_categories is null or cardinality(p_categories)>3
    or not p_categories<@array['mention','task','call']
    or (cardinality(p_categories)>0 and array_ndims(p_categories) is distinct from 1)
    or (p_enabled and cardinality(p_categories)=0) then
    raise exception 'Choose a valid email frequency and at least one category to subscribe';
  end if;
  perform sectalk_private.limit_action('v6_notification_email',20);
  select lower(u.email) into mailbox from auth.users u where u.id=actor and u.email_confirmed_at is not null
    and coalesce(u.email_change,'')='';
  if p_enabled and (mailbox is null or not sectalk_private.st_v2_active(actor)) then
    raise exception 'Verify your current email to enable notifications';
  end if;
  categories:=array(select distinct category from unnest(p_categories) category order by category);
  insert into sectalk_private.st_v6_notification_email as p(recipient,email_at_consent,enabled,cadence,categories,next_at)
  values(actor,case when p_enabled then mailbox end,p_enabled,p_cadence,categories,
    now()+case when p_cadence='prompt' then interval '0 seconds' else sectalk_private.st_v6_email_cadence(p_cadence) end)
  on conflict(recipient) do update set email_at_consent=excluded.email_at_consent,
    enabled=excluded.enabled,cadence=excluded.cadence,categories=excluded.categories,
    next_at=excluded.next_at,scanned_at=now(),window_end=null,lease_id=null,attempts=0,
    unsubscribe_key=gen_random_uuid()
  where (p.email_at_consent,p.enabled,p.cadence,p.categories) is distinct from
    (excluded.email_at_consent,excluded.enabled,excluded.cadence,excluded.categories);
end
$$;

create function public.st_v6_unsubscribe_notification_email(p_key uuid)
returns void language sql security definer set search_path='' as $$
  update sectalk_private.st_v6_notification_email p set enabled=false,email_at_consent=null,
    lease_id=null,window_end=null,attempts=0,unsubscribe_key=gen_random_uuid()
  where p.unsubscribe_key=p_key and p.enabled
$$;

create function public.st_v6_claim_notification_email()
returns table(recipient uuid,lease uuid,email text,cadence text,unsubscribe_key uuid,mentions bigint,tasks bigint,calls bigint)
language plpgsql security definer set search_path='' as $$
declare pref record; boundary timestamptz; mentions_count bigint; tasks_count bigint; calls_count bigint;
begin
  for pref in
    select p.*,u.email as current_email,u.email_confirmed_at, u.email_change
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
    mentions_count:=0;
    tasks_count:=0;
    calls_count:=0;
    if 'mention'=any(pref.categories) then
      select count(*) into mentions_count from public.st_v3_notifications n
      where n.recipient=pref.recipient and n.room_id is not null and n.kind like 'mention.%'
        and n.created_at>pref.scanned_at and n.created_at<=boundary
        and sectalk_private.st_v6_web_push_allowed(pref.recipient,n.kind,n.room_id,null,null);
    end if;
    if 'task'=any(pref.categories) then
      select count(*) into tasks_count from public.st_v6_task_notices n join public.st_v6_tasks t on t.id=n.task_id
      where n.recipient=pref.recipient and n.created_at>pref.scanned_at and n.created_at<=boundary
        and sectalk_private.st_v6_web_push_allowed(pref.recipient,'task.'||n.kind,t.room_id,t.chat_id,null);
    end if;
    if 'call'=any(pref.categories) then
      select count(*) into calls_count from public.st_calls c
      where c.callee=pref.recipient and c.expires_at>pref.scanned_at and c.expires_at<=boundary
        and (c.end_reason='missed' or (c.status='ringing' and c.expires_at<=now()))
        and sectalk_private.st_v6_web_push_allowed(pref.recipient,'call.incoming',null,c.chat_id,null);
    end if;
    if mentions_count+tasks_count+calls_count=0 or pref.attempts>=3 then
      update sectalk_private.st_v6_notification_email p set scanned_at=boundary,
        next_at=now()+sectalk_private.st_v6_email_cadence(pref.cadence),window_end=null,lease_id=null,attempts=0
      where p.recipient=pref.recipient;
      continue;
    end if;
    update sectalk_private.st_v6_notification_email p
    set next_at=now()+interval '45 seconds', window_end=boundary,lease_id=gen_random_uuid(),attempts=p.attempts+1
    where p.recipient=pref.recipient
    returning p.lease_id into lease;
    recipient:=pref.recipient;
    email:=pref.current_email;
    cadence:=pref.cadence;
    unsubscribe_key:=pref.unsubscribe_key;
    mentions:=mentions_count;
    tasks:=tasks_count;
    calls:=calls_count;
    return next;
  end loop;
end
$$;

create function public.st_v6_confirm_notification_email(p_recipient uuid,p_lease uuid)
returns boolean language sql stable security definer set search_path='' as $$
  select exists(select 1 from sectalk_private.st_v6_notification_email p
    join auth.users u on u.id=p.recipient
    where p.recipient=p_recipient and p.enabled and p.lease_id=p_lease and p.next_at>now()
      and p.email_at_consent=lower(u.email) and u.email_confirmed_at is not null
      and coalesce(u.email_change,'')='' and sectalk_private.st_v2_active(p.recipient))
$$;

create function public.st_v6_finish_notification_email(p_recipient uuid,p_lease uuid,p_sent boolean)
returns void language sql security definer set search_path='' as $$
  update sectalk_private.st_v6_notification_email p set
    scanned_at=case when p_sent or p.attempts>=3 then p.window_end else p.scanned_at end,
    next_at=now()+case when p_sent or p.attempts>=3
      then sectalk_private.st_v6_email_cadence(p.cadence) else make_interval(secs=>30*p.attempts) end,
    window_end=case when p_sent or p.attempts>=3 then null else p.window_end end,
    attempts=case when p_sent or p.attempts>=3 then 0 else p.attempts end,lease_id=null
  where p.recipient=p_recipient and p.lease_id=p_lease and p.enabled
$$;

revoke all on function sectalk_private.st_v6_email_cadence(text),
  public.st_v6_notification_email_settings(),public.st_v6_set_notification_email(boolean,text,text[]),
  public.st_v6_unsubscribe_notification_email(uuid),public.st_v6_claim_notification_email(),
  public.st_v6_confirm_notification_email(uuid,uuid),public.st_v6_finish_notification_email(uuid,uuid,boolean)
  from public,anon,authenticated,service_role;
grant execute on function public.st_v6_notification_email_settings(),
  public.st_v6_set_notification_email(boolean,text,text[]) to authenticated;
grant execute on function public.st_v6_unsubscribe_notification_email(uuid),public.st_v6_claim_notification_email(),
  public.st_v6_confirm_notification_email(uuid,uuid),public.st_v6_finish_notification_email(uuid,uuid,boolean) to service_role;

commit;
