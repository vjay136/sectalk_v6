begin;

alter table public.st_v5_discovery add column online_discoverable boolean not null default false;

-- Saving an opt-out through an older client must clear online visibility too.
create function sectalk_private.st_v6_clear_online_discovery()
returns trigger language plpgsql set search_path='' as $$
begin
  if not new.discoverable then new.online_discoverable:=false; end if;
  return new;
end $$;
revoke all on function sectalk_private.st_v6_clear_online_discovery() from public,anon,authenticated;

create trigger st_v6_clear_online_discovery before update of discoverable on public.st_v5_discovery
  for each row execute function sectalk_private.st_v6_clear_online_discovery();

create function sectalk_private.st_v6_seed_presence(actor uuid)
returns void language sql set search_path='' as $$
  -- Publish a first heartbeat only after an explicit choice to share availability.
  insert into public.st_v3_presence(user_id,state,expires_at)
    select id,'online',clock_timestamp()+interval '100 seconds'
    from public.st_profiles where id=actor
      and not exists(select 1 from public.st_v3_presence where user_id=actor)
      and sectalk_private.st_v6_shares_presence(actor)
      and (
        exists(select 1 from public.st_v5_discovery where user_id=actor and discoverable and online_discoverable)
        or exists(select 1 from sectalk_private.st_v6_presence_privacy where user_id=actor and share_availability)
      )
    on conflict(user_id) do nothing
$$;
revoke all on function sectalk_private.st_v6_seed_presence(uuid) from public,anon,authenticated;

create function public.st_v6_save_discovery(
  p_stage text,p_categories text[],p_discoverable boolean,p_adult boolean,p_show_online boolean
)
returns void language plpgsql security definer set search_path='' as $$
declare actor uuid:=auth.uid();
begin
  if not sectalk_private.st_v2_active(actor) then
    raise exception 'Sign in with an active account to manage discovery' using errcode='PT403';
  end if;
  perform public.st_v5_save_discovery(p_stage,p_categories,p_discoverable,p_adult);
  update public.st_v5_discovery set online_discoverable=discoverable and p_show_online is true
    where user_id=actor;
  if p_discoverable is true and p_show_online is true then
    perform sectalk_private.st_v6_seed_presence(actor);
  end if;
end $$;

create function sectalk_private.st_v6_discovery_results(
  p_query text,p_stage text,p_category text,p_online_only boolean,p_page integer
)
returns table(handle text,name text,stage text,categories text[],online boolean,chat_id uuid)
language plpgsql set search_path='' as $$
declare
  actor uuid:=auth.uid();
  needle text:=lower(btrim(coalesce(p_query,'')));
  by_handle boolean:=left(needle,1)='@';
begin
  if by_handle then needle:=substr(needle,2); end if;
  if p_online_only is null or p_page is null or p_page not between 0 and 999
    or char_length(needle)>64
    or (not p_online_only and needle='' and p_stage is null and p_category is null) then return; end if;
  if not sectalk_private.st_v2_active(actor) then
    raise exception 'Sign in with an active account to find people' using errcode='PT403';
  end if;
  if not exists(select 1 from public.st_v5_discovery where user_id=actor and discoverable) then
    raise exception 'Turn on discovery to browse public profiles' using errcode='PT403';
  end if;
  perform sectalk_private.limit_action('v5_discovery_search',12);

  return query
    select p.handle,p.name,d.stage,d.categories,available.user_id is not null,c.id
    from public.st_v5_discovery d
    join public.st_profiles p on p.id=d.user_id
    left join public.st_chats c on c.member_a=least(d.user_id,actor) and c.member_b=greatest(d.user_id,actor)
    left join public.st_v3_presence available on available.user_id=d.user_id
      and d.online_discoverable and available.state='online' and available.expires_at>now()
      and sectalk_private.st_v6_shares_presence(d.user_id)
    where d.discoverable and d.user_id<>actor
      and (p_stage is null or d.stage=p_stage)
      and (p_category is null or d.categories @> array[p_category])
      and (not p_online_only or available.user_id is not null)
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
      and (c.id is null or (p_online_only and c.status='accepted'))
    order by case
      when needle<>'' and lower(p.handle)=needle then 0
      when needle<>'' and (starts_with(lower(p.handle),needle) or starts_with(lower(p.name),needle)) then 1
      else 2
    end,lower(p.name),p.handle
    offset (p_page * 24) limit 25;
end $$;

revoke all on function sectalk_private.st_v6_discovery_results(text,text,text,boolean,integer)
  from public,anon,authenticated;

create function public.st_v6_find_friends(
  p_query text,p_stage text,p_category text,p_online_only boolean,p_page integer
)
returns table(handle text,name text,stage text,categories text[],online boolean,chat_id uuid)
language sql security definer set search_path='' as $$
  select * from sectalk_private.st_v6_discovery_results(p_query,p_stage,p_category,p_online_only,p_page)
$$;

create or replace function public.st_v5_find_friends(p_query text,p_stage text,p_category text)
returns table(handle text,name text,stage text,categories text[])
language sql security definer set search_path='' as $$
  select result.handle,result.name,result.stage,result.categories
  from sectalk_private.st_v6_discovery_results(p_query,p_stage,p_category,false,0) result
  limit 24
$$;

revoke all on function public.st_v6_find_friends(text,text,text,boolean,integer),
  public.st_v6_save_discovery(text,text[],boolean,boolean,boolean),public.st_v5_find_friends(text,text,text)
  from public,anon;
grant execute on function public.st_v6_find_friends(text,text,text,boolean,integer),
  public.st_v6_save_discovery(text,text[],boolean,boolean,boolean),public.st_v5_find_friends(text,text,text)
  to authenticated;

create or replace function public.st_v3_ping()
returns void language plpgsql security definer set search_path='' as $$
declare actor uuid:=auth.uid();
begin
  perform sectalk_private.limit_action('v6_presence_ping',12);
  if not sectalk_private.st_v2_active(actor) then return; end if;
  update public.st_v3_presence set expires_at=clock_timestamp()+interval '100 seconds'
    where user_id=actor and state in ('online','away','busy') and expires_at<=clock_timestamp()+interval '65 seconds';
  if not found then perform sectalk_private.st_v6_seed_presence(actor); end if;
end $$;

commit;
