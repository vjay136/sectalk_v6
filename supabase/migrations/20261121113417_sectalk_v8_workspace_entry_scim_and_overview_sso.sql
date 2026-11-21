begin;

create or replace function public.st_v8_scim_settings(p_workspace uuid,p_action text default 'read',p_domain text default null)
returns jsonb language plpgsql security definer set search_path='' as $$
declare access text; secret text; setup jsonb;
begin
  access:=sectalk_private.st_v7_file_egress_operator(p_workspace);
  if access is distinct from 'none' and not sectalk_private.st_v8_entry_sso_allows(p_workspace) then
    return '{"access":"sso"}'::jsonb;
  end if;
  if access is distinct from 'verified' then return jsonb_build_object('access',access); end if;
  if p_action is distinct from 'read' then
    perform sectalk_private.limit_action('v8_scim_settings',5);
    perform 1 from public.st_v2_workspaces where id=p_workspace for update;
    if not found or sectalk_private.st_v7_file_egress_operator(p_workspace) is distinct from 'verified'
      or not sectalk_private.st_v8_entry_sso_allows(p_workspace) then
      raise insufficient_privilege;
    end if;
  end if;
  if p_action='revoke' then
    delete from sectalk_private.st_v8_scim_keys where workspace=p_workspace;
    insert into public.st_v2_workspace_audit(workspace_id,actor,event) values(p_workspace,auth.uid(),'scim.token.revoked');
  elsif p_action='rotate' then
    if (sectalk_private.st_v7_workspace_entitlements(p_workspace)).plan is distinct from 'enterprise'
      or not exists(select 1 from sectalk_private.st_v7_org_domains d where d.workspace=p_workspace
        and d.domain=p_domain and d.verified_at is not null) then raise insufficient_privilege; end if;
    secret:='stscim_'||encode(extensions.gen_random_bytes(32),'hex');
    insert into sectalk_private.st_v8_scim_keys(workspace,digest,domain,issued_by,expires_at)
      values(p_workspace,encode(extensions.digest(secret,'sha256'),'hex'),p_domain,auth.uid(),now()+interval '180 days')
      on conflict(workspace) do update set digest=excluded.digest,domain=excluded.domain,
        issued_by=excluded.issued_by,expires_at=excluded.expires_at;
    insert into public.st_v2_workspace_audit(workspace_id,actor,event) values(p_workspace,auth.uid(),'scim.token.rotated');
  elsif p_action is distinct from 'read' then raise invalid_parameter_value;
  end if;
  select jsonb_build_object('domain',k.domain,'expires',k.expires_at) into setup
    from sectalk_private.st_v8_scim_keys k where k.workspace=p_workspace;
  return jsonb_build_object('access','verified','setup',setup,'token',secret,
    'enterprise',(sectalk_private.st_v7_workspace_entitlements(p_workspace)).plan is not distinct from 'enterprise',
    'domains',coalesce((select jsonb_agg(d.domain order by d.domain) from sectalk_private.st_v7_org_domains d
      where d.workspace=p_workspace and d.verified_at is not null),'[]'::jsonb));
end $$;

create or replace function public.st_v6_workspace_analytics(p_workspace uuid)
returns jsonb language plpgsql stable security definer set search_path='' as $$
declare cutoff timestamptz:=date_trunc('day',now(),'UTC');
declare shared_activity jsonb;
declare quality jsonb;
declare posture jsonb;
begin
  if sectalk_private.st_v6_holds_access(p_workspace) is distinct from 'verified'
    or not sectalk_private.st_v8_entry_sso_allows(p_workspace) then
    raise exception 'Verified workspace analytics access is required' using errcode='42501';
  end if;
  with eligible as (
    select p.sender from public.st_v6_room_posts p join public.st_v6_rooms r on r.id=p.room_id
      where r.workspace_id=p_workspace and r.kind in ('public','announcement','broadcast')
        and r.classification in ('public','internal') and not r.archived and p.removed_at is null
        and p.created_at>=cutoff-interval '168 hours' and p.created_at<cutoff
    union all
    select p.sender from public.st_v2_posts p join public.st_v2_channels c on c.id=p.channel_id
      where c.workspace_id=p_workspace and c.visibility='workspace' and not c.archived
        and p.created_at>=cutoff-interval '168 hours' and p.created_at<cutoff
  ), measured as (
    select count(*) posts,count(distinct sender) contributors from eligible e
    join public.st_v2_members m on m.workspace_id=p_workspace and m.user_id=e.sender and m.suspended_at is null
    having count(distinct sender)>=5
  )
  select jsonb_build_object('posts',(posts/5)*5,'contributors',(contributors/5)*5) into shared_activity from measured;

  with qualified_days as (
    select day,metric,count(*) sampled,count(*) filter(where bucket in ('connected','relayed')) positive
    from sectalk_private.st_v6_call_qos
    where workspace_id=p_workspace and mode='meeting' and day>=(cutoff at time zone 'UTC')::date-7
      and day<(cutoff at time zone 'UTC')::date and metric in ('join','relay')
    group by day,metric
    having count(*)>=10 and count(distinct reporter_key)>=5
      and count(distinct reporter_key) filter(where bucket in ('connected','relayed')) not between 1 and 4
      and count(distinct reporter_key) filter(where bucket not in ('connected','relayed')) not between 1 and 4
  ), totals as (
    select metric,sum((sampled/10)*10) samples,floor(sum(positive)*10/sum(sampled))*10 rate
    from qualified_days group by metric
  )
  select coalesce(jsonb_object_agg(metric,jsonb_build_object('samples',samples,'percent',rate)),'{}'::jsonb)
    into quality from totals;

  select jsonb_build_object(
    'managed_rooms',count(*),'protected_rooms',count(*) filter(where r.classification in ('confidential','restricted')),
    'blocked_forwarding',count(*) filter(where r.classification in ('confidential','restricted') or not r.forwarding_allowed),
    'archived_rooms',count(*) filter(where r.archived)
  ) into posture from public.st_v6_rooms r
  where r.workspace_id=p_workspace and sectalk_private.st_v6_room_directory(r.id);

  return jsonb_build_object('period_start',cutoff-interval '168 hours','period_end',cutoff,
    'shared_activity',shared_activity,'meeting_quality',quality,'security_posture',posture);
end $$;

create or replace function public.st_v6_workspace_admin_overview(p_workspace uuid)
returns jsonb language plpgsql stable security definer set search_path='' as $$
declare workspace_owner uuid;
declare plan text;
declare seat_limit integer;
declare occupied integer;
declare enabled integer;
declare pending_invites integer;
declare expiring_links integer;
declare access_requests integer;
declare contributors integer;
declare since timestamptz:=now()-interval '168 hours';
begin
  if not coalesce(sectalk_private.st_v2_role(p_workspace,auth.uid()) in ('owner','admin'),false)
    or sectalk_private.st_v2_active(auth.uid()) is not true
    or not sectalk_private.st_v8_entry_sso_allows(p_workspace)
  then raise exception 'Workspace overview is unavailable' using errcode='42501'; end if;
  select w.owner into workspace_owner from public.st_v2_workspaces w where w.id=p_workspace;
  select e.plan,e.seat_limit into plan,seat_limit from sectalk_private.st_v7_workspace_entitlements(p_workspace) e;
  select count(*),count(*) filter(where m.suspended_at is null) into occupied,enabled
  from public.st_v2_members m where m.workspace_id=p_workspace;

  select (select count(*) from public.st_v2_invites i where i.workspace_id=p_workspace and i.status='pending')
      + count(*),
    count(*) filter(where i.expires_at<=now()+interval '24 hours')
  into pending_invites,expiring_links
  from sectalk_private.st_v6_workspace_link_invites i
  where i.workspace_id=p_workspace and i.consumed_at is null and i.expires_at>now();
  select count(*) into access_requests
  from public.st_v6_room_entries e join public.st_v6_rooms r on r.id=e.room_id
  where r.workspace_id=p_workspace and not r.archived and e.kind='request' and e.expires_at>now()
    and sectalk_private.st_v6_room_role(r.id) in ('owner','moderator');

  if enabled>=5 then
    select count(*) into contributors from public.st_v2_members m
    where m.workspace_id=p_workspace and m.suspended_at is null and (
      exists(select 1 from public.st_v6_room_posts p join public.st_v6_rooms r on r.id=p.room_id
        where r.workspace_id=p_workspace and r.kind in ('public','announcement','broadcast')
          and not r.archived and p.sender=m.user_id and p.removed_at is null and p.created_at>=since)
      or exists(select 1 from public.st_v2_posts p join public.st_v2_channels c on c.id=p.channel_id
        where c.workspace_id=p_workspace and c.visibility='workspace' and not c.archived
          and p.sender=m.user_id and p.created_at>=since)
    );
    if contributors<3 then contributors:=null; end if;
  end if;
  return jsonb_build_object('plan',plan,'seat_limit',seat_limit,'occupied',occupied,'active',enabled,
    'pending_invites',pending_invites,'expiring_links',expiring_links,'access_requests',access_requests,
    'contributors',contributors,'activity_window_hours',168);
end $$;

notify pgrst,'reload schema';
commit;
