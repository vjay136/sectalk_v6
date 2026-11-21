begin;

alter function public.st_v8_residency_source_coverage(uuid,uuid) set schema sectalk_private;
revoke all on function sectalk_private.st_v8_residency_source_coverage(uuid,uuid)
  from public,anon,authenticated,service_role;

create function public.st_v8_residency_source_coverage(p_workspace uuid,p_approval uuid)
returns jsonb language plpgsql stable security definer set search_path='' as $$
declare coverage jsonb;
begin
  coverage:=sectalk_private.st_v8_residency_source_coverage(p_workspace,p_approval);

  return coverage||jsonb_build_object('unsupportedBoardItems',(
    select jsonb_agg(jsonb_build_object('kind',board.kind,'observed',board.observed,
      'capped',board.observed=501) order by board.kind)
    from (
      select kinds.kind,(select count(*) from (
        select 1 from public.st_v2_items item
        where item.workspace_id=p_workspace and item.kind=kinds.kind limit 501
      ) sample) as observed
      from unnest(array['event','note','announcement']) kinds(kind)
    ) board
  ));
end $$;

revoke all on function public.st_v8_residency_source_coverage(uuid,uuid)
  from public,anon,authenticated,service_role;
grant execute on function public.st_v8_residency_source_coverage(uuid,uuid) to authenticated;
notify pgrst,'reload schema';
commit;
