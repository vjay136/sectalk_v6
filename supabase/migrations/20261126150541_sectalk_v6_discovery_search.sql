create or replace function public.st_v5_find_friends(p_query text,p_stage text,p_category text)
returns table(handle text,name text,stage text,categories text[])
language plpgsql security definer set search_path='' as $$
declare
  actor uuid:=auth.uid();
  needle text:=lower(btrim(coalesce(p_query,'')));
  by_handle boolean:=left(needle,1)='@';
begin
  if by_handle then needle:=substr(needle,2); end if;
  if char_length(needle)>64 or (needle='' and p_stage is null and p_category is null) then return; end if;

  if not sectalk_private.st_v2_active(actor) then
    raise exception 'Sign in with an active account to find people' using errcode='PT403';
  end if;
  if not exists(select 1 from public.st_v5_discovery where user_id=actor and discoverable) then
    raise exception 'Turn on discovery to browse public profiles' using errcode='PT403';
  end if;
  perform sectalk_private.limit_action('v5_discovery_search',12);

  return query
    select p.handle,p.name,d.stage,d.categories
    from public.st_v5_discovery d join public.st_profiles p on p.id=d.user_id
    where d.discoverable and d.user_id<>actor
      and (p_stage is null or d.stage=p_stage)
      and (p_category is null or d.categories @> array[p_category])
      and (needle=''
        or starts_with(lower(p.handle),needle)
        or (not by_handle and (
          case when char_length(needle)=1 then
            exists(select 1 from regexp_split_to_table(lower(p.name),'[[:space:]]+') as words(word)
              where starts_with(words.word,needle))
          else strpos(lower(p.name),needle)>0 or strpos(lower(p.handle),needle)>0
          end
        )))
      and sectalk_private.open_pair(d.user_id,actor)
      and not exists(select 1 from public.st_chats c where c.member_a=least(d.user_id,actor) and c.member_b=greatest(d.user_id,actor))
    order by case
      when needle<>'' and lower(p.handle)=needle then 0
      when needle<>'' and (starts_with(lower(p.handle),needle) or starts_with(lower(p.name),needle)) then 1
      else 2
    end,lower(p.name),p.handle limit 24;
end $$;

revoke all on function public.st_v5_find_friends(text,text,text) from public,anon;
grant execute on function public.st_v5_find_friends(text,text,text) to authenticated;
