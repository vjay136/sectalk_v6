begin;

create or replace function public.st_v8_operator_overview()
returns jsonb language plpgsql stable security definer set search_path='' as $$
declare
  snapshot_at timestamptz := statement_timestamp();
  since_at timestamptz := snapshot_at - interval '24 hours';
  until_epoch numeric := extract(epoch from snapshot_at);
begin
  if not coalesce(sectalk_private.st_v6_case_redaction_staff(),false)
    or public.st_v7_login_risk_status() is distinct from 'clear'
    or coalesce((public.st_v7_account_lock_status()->>'locked')::boolean,true)
    or not exists(
      select 1 from jsonb_array_elements(case when jsonb_typeof(auth.jwt()->'amr')='array'
        then auth.jwt()->'amr' else '[]'::jsonb end) proof
      where proof->>'method'='totp'
        and case when proof->>'timestamp' ~ '^[0-9]{1,12}$' then
          (proof->>'timestamp')::numeric between until_epoch-600 and until_epoch
        else false end
    ) then
    raise insufficient_privilege using message='Verified platform moderator access is required';
  end if;

  return (
    with storage_groups as (
      select case
        when o.bucket_id='sectalk-chat-files' then 'Chat attachments'
        when o.bucket_id='sectalk-avatars' then 'Profile photos'
        when o.bucket_id='sectalk-vault' then 'Vault objects'
        else 'Other SecTalk storage'
        end as label,
        count(*) as objects,
        coalesce(sum(case when o.metadata->>'size' ~ '^[0-9]{1,18}$' then (o.metadata->>'size')::numeric end),0) as bytes,
        count(*) filter(where (o.metadata->>'size' ~ '^[0-9]{1,18}$') is not true) as unknown_sizes
      from storage.objects o
      where starts_with(o.bucket_id,'sectalk-')
      group by 1
    ), reports as (
      select status from public.st_reports
      union all select status from sectalk_private.st_v6_room_reports
      union all select state from sectalk_private.st_v7_channel_reports
    )
    select jsonb_build_object(
      'asOf',snapshot_at,
      'accounts',(select count(*) from public.st_profiles),
      'newAccounts',(select count(*) from auth.users u where u.created_at>=since_at and u.deleted_at is null),
      'workspaces',(select count(*) from public.st_v2_workspaces),
      'directMessages',(select count(*) from public.st_messages where created_at>=since_at)
        +(select count(*) from sectalk_private.st_v8_olm_direct_events where sent_at>=since_at),
      'groupMessages',(select count(*) from sectalk_private.st_group_messages where sent>=since_at),
      'workspacePosts',(select count(*) from public.st_v2_posts where created_at>=since_at)
        +(select count(*) from public.st_v6_room_posts where created_at>=since_at)
        +(select count(*) from sectalk_private.st_v8_managed_room_posts where created_at>=since_at),
      'audioCalls',(select count(*) from public.st_calls where created_at>=since_at and not video),
      'videoCalls',(select count(*) from public.st_calls where created_at>=since_at and video),
      'openReports',(select count(*) from reports where status in ('open','reviewing')),
      'restrictedAccounts',(select count(*) from sectalk_private.suspensions s where s.until_at>snapshot_at),
      'storage',coalesce((select jsonb_agg(to_jsonb(s) order by s.label) from storage_groups s),'[]'::jsonb)
    )
  );
end;
$$;

revoke all on function public.st_v8_operator_overview() from public,anon,authenticated,service_role;
grant execute on function public.st_v8_operator_overview() to authenticated;

commit;
