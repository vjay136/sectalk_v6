begin;

create table sectalk_private.st_v7_user_appearance (
  owner uuid primary key references auth.users on delete cascade,
  theme text not null check(theme in ('light','dark','high-contrast')),
  reduce_motion boolean not null
);
create table sectalk_private.st_v7_personal_deletion (
  owner uuid primary key references auth.users on delete cascade,
  requested_at timestamptz not null default clock_timestamp()
);
alter table sectalk_private.st_v7_user_appearance enable row level security;
alter table sectalk_private.st_v7_personal_deletion enable row level security;
revoke all on sectalk_private.st_v7_user_appearance,sectalk_private.st_v7_personal_deletion
  from public,anon,authenticated,service_role;

create function public.st_v7_user_appearance(p_owner uuid,p_theme text default null,p_reduce boolean default null)
returns jsonb language plpgsql security definer set search_path='' as $$
declare settings sectalk_private.st_v7_user_appearance;
begin
  if p_owner is null or p_owner is distinct from auth.uid()
    or not public.st_v7_current_session_valid() or not sectalk_private.st_v2_active(p_owner) then
    raise exception using errcode='42501',message='Appearance settings are unavailable';
  end if;
  if p_theme is not null or p_reduce is not null then
    if p_theme is null or p_theme not in ('light','dark','high-contrast') or p_reduce is null then
      raise exception using errcode='22023',message='Choose valid appearance settings';
    end if;
    perform sectalk_private.limit_action('account_appearance',20);
    insert into sectalk_private.st_v7_user_appearance(owner,theme,reduce_motion) values(p_owner,p_theme,p_reduce)
      on conflict(owner) do update set theme=excluded.theme,reduce_motion=excluded.reduce_motion;
  end if;
  select * into settings from sectalk_private.st_v7_user_appearance where owner=p_owner;
  return jsonb_build_object('theme',coalesce(settings.theme,'dark'),'reduceMotion',coalesce(settings.reduce_motion,false));
end
$$;

create function sectalk_private.st_v7_personal_data_verified(p_owner uuid)
returns boolean language sql stable security definer set search_path='' as $$
  select coalesce(p_owner=auth.uid() and public.st_v7_current_session_valid() and sectalk_private.st_v2_active(p_owner)
    and sectalk_private.st_v7_security_session(case when exists(select 1 from auth.mfa_factors f
      where f.user_id=p_owner and f.status='verified' and f.factor_type='totp') then 'totp' else 'password' end),false)
$$;

create function public.st_v7_personal_data_export(p_owner uuid,p_before timestamptz default null,p_before_id uuid default null)
returns jsonb language plpgsql security definer set search_path='' as $$
declare result jsonb;
begin
  if not sectalk_private.st_v7_personal_data_verified(p_owner) then
    raise exception using errcode='42501',message='Verify your current credentials to export your data';
  end if;
  if num_nonnulls(p_before,p_before_id)=1 then raise exception using errcode='22023',message='Invalid export cursor'; end if;
  perform sectalk_private.limit_action('account_data_export',20);
  with records as (
    select * from (
      select 'direct'::text kind,m.id,m.created_at,m.body from public.st_messages m
      where m.sender=p_owner and m.revoked_at is null and m.expires_at is null
        and not exists(select 1 from public.st_v5_hidden_messages h where h.message_id=m.id and h.user_id=p_owner)
      union all
      select 'room',p.id,p.created_at,p.body from public.st_v6_room_posts p
      where p.sender=p_owner and p.removed_at is null and sectalk_private.st_v6_room_role(p.room_id,p_owner) is not null
    ) feed where p_before is null or (feed.created_at,feed.id)<(p_before,p_before_id)
    order by created_at desc,id desc limit 201
  ), page as (
    select * from records order by created_at desc,id desc limit 200
  )
  select jsonb_build_object('format','sectalk-personal-data-v1','generatedAt',clock_timestamp(),
    'profile',(select jsonb_build_object('accountId',u.id,'email',u.email,'createdAt',u.created_at,'handle',p.handle,'name',p.name)
      from auth.users u left join public.st_profiles p on p.id=u.id where u.id=p_owner),
    'appearance',(select jsonb_build_object('theme',a.theme,'reduceMotion',a.reduce_motion)
      from sectalk_private.st_v7_user_appearance a where a.owner=p_owner),
    'profileDetails',(select jsonb_build_object('statusMessage',p.status_message,'sharesLastSeen',p.share_last_seen)
      from public.st_v5_profile_details p where p.user_id=p_owner),
    'notificationPreferences',public.st_v6_notification_preferences(),
    'billing',(select jsonb_build_object('plan',b.plan,'status',b.status,'periodEnd',b.period_end)
      from public.st_v2_subscriptions b where b.user_id=p_owner),
    'sessions',coalesce((select jsonb_agg(jsonb_build_object('startedAt',s.created_at,'expiresAt',s.not_after,
      'current',s.id::text=auth.jwt()->>'session_id') order by s.created_at desc)
      from (select id,created_at,not_after from auth.sessions where user_id=p_owner order by created_at desc limit 100) s),'[]'),
    'discovery',(select jsonb_build_object('stage',d.stage,'categories',d.categories,'discoverable',d.discoverable)
      from public.st_v5_discovery d where d.user_id=p_owner),
    'devices',coalesce((select jsonb_agg(jsonb_build_object('id',d.id,'state',d.state,'registeredAt',d.created_at) order by d.created_at)
      from (select id,state,created_at from sectalk_private.st_v7_devices where owner=p_owner order by created_at desc limit 100) d),'[]'),
    'authoredMessages',coalesce((select jsonb_agg(to_jsonb(p) order by p.created_at desc,p.id desc) from page p),'[]'),
    'next',case when (select count(*) from records)>200 then (select jsonb_build_object('before',p.created_at,'beforeId',p.id)
      from page p order by p.created_at,p.id limit 1) end) into result;
  return result;
end
$$;

create function public.st_v7_personal_deletion(p_owner uuid,p_action text default 'status',p_confirmation text default null)
returns jsonb language plpgsql security definer set search_path='' as $$
declare queued timestamptz;
begin
  if p_owner is null or p_owner is distinct from auth.uid() or not public.st_v7_current_session_valid() then
    raise exception using errcode='42501',message='Account settings are unavailable';
  end if;
  if p_action in ('request','retry','cancel') then
    if not sectalk_private.st_v7_personal_data_verified(p_owner) then
      raise exception using errcode='42501',message='Verify your current credentials to change the deletion request';
    end if;
    perform sectalk_private.limit_action('account_deletion_request',5);
    perform 1 from auth.users where id=p_owner for update;
    if not found then raise exception using errcode='42501',message='Account settings are unavailable'; end if;
    if p_action='cancel' then
      delete from sectalk_private.st_v7_personal_deletion where owner=p_owner;
    elsif p_confirmation is distinct from 'DELETE ACCOUNT' then
      raise exception using errcode='22023',message='Enter DELETE ACCOUNT to confirm';
    else
      if p_action='retry' then
        if not exists(select 1 from sectalk_private.st_v7_personal_deletion where owner=p_owner) then
          raise exception using errcode='22023',message='There is no pending deletion request';
        end if;
      else
        insert into sectalk_private.st_v7_personal_deletion(owner) values(p_owner) on conflict do nothing;
      end if;
      -- Do not sever managed records, holds, ownership or external payment/storage dependencies.
      if not exists(select 1 from public.st_v2_workspaces w where w.owner=p_owner)
        and not exists(select 1 from public.st_v2_subscriptions s where s.user_id=p_owner and s.plan<>'free' and s.status not in ('canceled','incomplete_expired'))
        and not exists(select 1 from sectalk_private.st_v6_workspace_holds h where h.member_id=p_owner and h.released_at is null)
        and not exists(select 1 from sectalk_private.st_v6_preserved_post_versions p
          join sectalk_private.st_v6_workspace_holds h on h.id=p.hold_id where p.sender=p_owner and h.released_at is null)
        and not exists(select 1 from public.st_v6_room_posts p where p.sender=p_owner)
        and not exists(select 1 from public.st_v2_posts p where p.sender=p_owner)
        and not exists(select 1 from storage.objects o where o.owner_id::text=p_owner::text)
        and not exists(select 1 from public.st_v5_files f where f.uploader=p_owner)
        and not exists(select 1 from sectalk_private.st_v7_devices d where d.owner=p_owner) then
        begin
          delete from auth.users where id=p_owner;
          if found then return jsonb_build_object('status','deleted','requestedAt',null); end if;
        exception when foreign_key_violation then
          null;
        end;
      end if;
    end if;
  elsif p_action is distinct from 'status' then
    raise exception using errcode='22023',message='Choose a valid account data action';
  end if;
  select requested_at into queued from sectalk_private.st_v7_personal_deletion where owner=p_owner;
  return jsonb_build_object('status',case when queued is null then 'none' else 'needs_review' end,'requestedAt',queued);
end
$$;

revoke all on function sectalk_private.st_v7_personal_data_verified(uuid),
  public.st_v7_user_appearance(uuid,text,boolean),public.st_v7_personal_data_export(uuid,timestamptz,uuid),
  public.st_v7_personal_deletion(uuid,text,text) from public,anon,authenticated,service_role;
grant execute on function public.st_v7_user_appearance(uuid,text,boolean),public.st_v7_personal_data_export(uuid,timestamptz,uuid),
  public.st_v7_personal_deletion(uuid,text,text) to authenticated;
commit;
