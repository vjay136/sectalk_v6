begin;

create index st_v8_soc_url_block_fingerprint
  on sectalk_private.st_v7_soc_url_blocks (extensions.digest(url_key, 'sha256'));

create function public.st_v8_link_safety_summary(p_url text)
returns jsonb language plpgsql security definer set search_path='' as $$
declare
  canonical_url text := sectalk_private.st_v7_soc_url_key(p_url);
  matched boolean;
begin
  if auth.uid() is null or public.st_v7_current_session_valid() is not true
    or sectalk_private.st_v2_active(auth.uid()) is not true or canonical_url is null then
    return null;
  end if;
  perform sectalk_private.limit_action('v8_link_safety_summary', 30);

  select exists (
    select 1
      from sectalk_private.st_v7_soc_url_blocks b
      join sectalk_private.st_v7_soc_responses r on r.id=b.response
     where extensions.digest(b.url_key, 'sha256')=extensions.digest(canonical_url, 'sha256')
       and b.url_key=canonical_url
       and b.expires_at>statement_timestamp()
       and r.domain=b.url_key and r.workspace is null and r.action='block_url' and r.decision='executed'
  ) into matched;

  return jsonb_build_object(
    'allowed', public.st_v7_link_policy_allows(canonical_url),
    'recordedRisk', matched
  );
end $$;

revoke all on function public.st_v8_link_safety_summary(text) from public, anon, authenticated, service_role;
grant execute on function public.st_v8_link_safety_summary(text) to authenticated;

commit;
