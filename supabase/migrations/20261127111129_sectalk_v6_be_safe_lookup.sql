begin;

create index st_forward_lineage_advisory_fingerprint
  on sectalk_private.st_forward_lineage(body_digest) where root_id is null;

create function public.st_be_safe_lookup(p_fingerprint text, p_links text[], p_handle text)
returns jsonb language plpgsql security definer set search_path='' as $$
declare
  caller uuid := auth.uid();
  warnings jsonb := '[]';
  addresses jsonb := '[]';
  restricted boolean := false;
begin
  if caller is null or public.st_v7_current_session_valid() is not true
    or sectalk_private.st_v2_active(caller) is not true then
    raise exception 'A current session is required' using errcode='42501';
  end if;
  perform sectalk_private.limit_action('be_safe_lookup', 15);
  if (p_fingerprint is not null and (length(p_fingerprint)<>64 or p_fingerprint !~ '^[a-f0-9]{64}$'))
    or (p_handle is not null and (length(p_handle)>24 or p_handle !~ '^[a-z0-9_]{3,24}$'))
    or coalesce(cardinality(p_links),0)>8 then
    raise exception 'Invalid safety lookup' using errcode='22023';
  end if;

  if p_fingerprint is not null then
    select coalesce(jsonb_agg(distinct a.category order by a.category),'[]') into warnings
    from sectalk_private.st_forward_lineage origin
    join sectalk_private.st_message_advisories a on a.root=origin.id
    join public.st_reports r on r.id=a.report
    where origin.root_id is null and origin.body_digest=decode(p_fingerprint,'hex')
      and a.verdict='warning' and r.status='resolved';
  end if;

  if cardinality(p_links)>0 then
    select coalesce(jsonb_agg(jsonb_build_object('address',link.address,
      'restricted',not public.st_v7_link_policy_allows(link.address)) order by link.address),'[]') into addresses
    from (select distinct sectalk_private.st_v7_soc_url_key(value) as address from unnest(p_links) value) link
    where link.address is not null;
  end if;

  if p_handle is not null then
    select exists (
      select 1 from public.st_profiles p
      join sectalk_private.suspensions s on s.user_id=p.id and s.until_at>statement_timestamp()
      where p.handle=p_handle and (
        exists(select 1 from public.st_v5_discovery d where d.user_id=p.id and d.discoverable)
        or exists(select 1 from public.st_chats c where c.status='accepted' and
          (c.member_a,c.member_b) in ((caller,p.id),(p.id,caller)))
      )
    ) into restricted;
  end if;

  return jsonb_build_object('categories',warnings,'links',addresses,'restricted',restricted);
end $$;

revoke all on function public.st_be_safe_lookup(text,text[],text) from public,anon,authenticated,service_role;
grant execute on function public.st_be_safe_lookup(text,text[],text) to authenticated;

create or replace function public.st_direct_message_advisories(p_chat uuid,p_messages uuid[])
returns table(message_id uuid,verdict text,category text)
language sql stable security definer set search_path='' as $$
  with viewer as (
    select auth.uid() as id where cardinality(p_messages) between 1 and 100
      and sectalk_private.member(p_chat,auth.uid())
      and not public.st_v7_step_up_pending() and not public.st_v7_account_data_unavailable()
  ), visible as materialized (
    select m.id,m.body,v.id as viewer_id
    from viewer v join public.st_messages m on m.chat_id=p_chat and m.id=any(p_messages)
    where m.revoked_at is null and (m.expires_at is null or m.expires_at>statement_timestamp())
      and not exists(select from public.st_v5_hidden_messages h where h.message_id=m.id and h.user_id=v.id)
  ), assessments as (
    select m.id,a.verdict,a.category,
      exists(
        select from (
          select sectalk_private.st_v7_soc_url_key(rtrim(scanned.parts[1], '.,!?;)')) as address
          from regexp_matches(m.body, '(https?://[^[:space:]<>"'']+)', 'gi') as scanned(parts) limit 8
        ) candidate where candidate.address is not null and (
          sectalk_private.st_v7_domain_blocked(split_part(split_part(candidate.address,'://',2),'/',1))
          or exists(select from sectalk_private.st_v7_soc_url_blocks b
            where b.url_key=candidate.address and b.expires_at>statement_timestamp())
        )
      ) as blocked_link,
      exists(
        select from sectalk_private.st_report_lineage anchor
        join public.st_reports r on r.id=anchor.report
        where anchor.root=coalesce(n.root_id,n.id) and r.chat_id=p_chat and r.message_id=m.id
          and r.reporter=m.viewer_id and r.status in ('open','reviewing')
      ) as own_report
    from visible m
    left join sectalk_private.st_forward_lineage n on n.kind='direct' and n.scope_id=p_chat
      and n.message_id=m.id and n.body_digest=extensions.digest(m.body,'sha256')
    left join sectalk_private.st_message_advisories a on a.root=coalesce(n.root_id,n.id)
  )
  select a.id,
    case when a.verdict='warning' then 'warning' when a.blocked_link then 'blocked_link' else coalesce(a.verdict,'reported') end,
    case when a.verdict='warning' then a.category when a.blocked_link then 'insecure_link' else a.category end
  from assessments a where a.verdict is not null or a.blocked_link or a.own_report;
$$;

notify pgrst,'reload schema';
commit;
