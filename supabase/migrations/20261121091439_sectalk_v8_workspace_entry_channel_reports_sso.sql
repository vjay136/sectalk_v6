begin;

-- Workspace reviewers need the pinned entry receipt before reading or acting on a handed-off report.

create or replace function public.st_v7_channel_report_queue(p_scope text)
returns jsonb language plpgsql stable security definer set search_path='' as $$
begin
  if not sectalk_private.st_v7_channel_report_staff(p_scope) then
    raise exception using errcode='42501',message='Channel report review is unavailable';
  end if;
  return coalesce((select jsonb_agg(to_jsonb(q) order by q.created_at desc,q.id) from(
    select r.id,r.category,r.state,r.created_at,r.handed_off_at,r.category in ('spam','other') and r.tenant_consent as handoff_allowed,
      case when p_scope='platform' then r.details else '' end as details,case when r.managed_revision is null then r.evidence end as evidence,r.managed_revision is not null as managed,c.name as channel_name,w.name as workspace_name
    from sectalk_private.st_v7_channel_reports r
    left join public.st_v2_channels c on c.id=r.channel_id and c.workspace_id=r.workspace_id
    left join public.st_v2_workspaces w on w.id=r.workspace_id
    where auth.uid()<>r.reporter and auth.uid() is distinct from r.subject
      and (p_scope='platform' or (r.handed_off_at is not null
        and sectalk_private.st_v8_entry_sso_allows(r.workspace_id) and
        sectalk_private.st_v7_channel_report_local(r.channel_id,r.workspace_id,auth.uid())))
    order by r.created_at desc,r.id limit 100
  ) q),'[]'::jsonb);
end $$;

create or replace function public.st_v7_review_channel_report(p_report uuid,p_scope text,p_action text,p_reason text)
returns void language plpgsql security definer set search_path='' as $$
declare item sectalk_private.st_v7_channel_reports; actor uuid:=auth.uid(); why text:=btrim(p_reason);
begin
  if not sectalk_private.st_v7_channel_report_staff(p_scope) then
    raise exception using errcode='42501',message='Channel report review is unavailable';
  end if;
  if why is null or char_length(why) not between 1 and 500 or p_action is null
      or p_action not in ('handoff','reviewing','resolved','dismissed') then
    raise exception using errcode='22023',message='Choose a decision and enter a review reason';
  end if;
  select * into item from sectalk_private.st_v7_channel_reports where id=p_report for update;
  if not found or actor=item.reporter or actor is not distinct from item.subject or
    (p_scope='workspace' and (item.handed_off_at is null
      or not sectalk_private.st_v8_entry_sso_allows(item.workspace_id) or
      not sectalk_private.st_v7_channel_report_local(item.channel_id,item.workspace_id,actor))) then
    raise exception using errcode='42501',message='Channel report review is unavailable';
  end if;
  if item.state in ('resolved','dismissed') then raise exception using errcode='PT409',message='The report is closed'; end if;
  if p_action='handoff' then
    if p_scope<>'platform' or not item.tenant_consent or item.category not in ('spam','other') then
      raise exception using errcode='42501',message='This report requires platform review';
    end if;
    if item.handed_off_at is not null then return; end if;
    if not exists(select 1 from public.st_v2_members m where m.workspace_id=item.workspace_id
      and m.user_id not in (actor,item.reporter) and m.user_id is distinct from item.subject
      and sectalk_private.st_v7_channel_report_local(item.channel_id,item.workspace_id,m.user_id)
      and sectalk_private.st_v6_on_call_eligible(m.user_id)) then
      raise exception using errcode='PT409',message='No eligible workspace reviewer can read this channel';
    end if;
    update sectalk_private.st_v7_channel_reports set handed_off_at=clock_timestamp(),state='reviewing' where id=item.id;
  else
    if item.state=p_action then return; end if;
    update sectalk_private.st_v7_channel_reports set state=p_action where id=item.id;
  end if;
  perform sectalk_private.limit_action('v7_channel_review',30);
  insert into sectalk_private.st_v7_channel_report_actions(report_id,actor,action,review_scope,reason)
    values(item.id,actor,p_action,p_scope,why);
  perform realtime.send('{}','channel_report_updated','st:account:'||item.reporter,true);
end $$;

create or replace function public.st_v8_view_managed_channel_report(p_report uuid,p_scope text)
returns text language plpgsql security definer set search_path='' as $$
declare item sectalk_private.st_v7_channel_reports; me uuid:=auth.uid();
begin
  if sectalk_private.st_v7_admin_fresh() is not true or public.st_v7_account_under_lockdown()
    or not sectalk_private.st_v7_channel_report_staff(p_scope) then
    raise exception 'Fresh channel evidence review access required' using errcode='42501'; end if;
  select * into item from sectalk_private.st_v7_channel_reports where id=p_report;
  if item.managed_revision is null or me=item.reporter or me is not distinct from item.subject
    or (p_scope='workspace' and (not item.tenant_consent or item.handed_off_at is null
      or not sectalk_private.st_v8_entry_sso_allows(item.workspace_id)
      or not sectalk_private.st_v7_channel_report_local(item.channel_id,item.workspace_id,me))) then
    raise exception 'Managed channel evidence unavailable' using errcode='42501'; end if;
  perform sectalk_private.limit_action('v8_managed_report_view',30);
  insert into sectalk_private.st_v8_managed_evidence_views(report,workspace,actor,review_scope,revision)
    values(item.id,item.workspace_id,me,p_scope,item.managed_revision);
  return item.evidence;
end $$;

commit;
