begin;

alter table public.st_v3_presence add column automatic boolean not null default false;

create or replace function sectalk_private.st_v6_seed_presence(actor uuid)
returns void language sql set search_path='' as $$
  insert into public.st_v3_presence(user_id,state,expires_at,automatic)
    select id,'online',clock_timestamp()+interval '100 seconds',true
    from public.st_profiles
    where id=actor and sectalk_private.st_v6_shares_presence(actor)
    on conflict(user_id) do nothing
$$;

create or replace function public.st_v3_set_presence(p_state text)
returns void language plpgsql security definer set search_path='' as $$
declare
  actor uuid:=auth.uid();
  sharing_required boolean;
  resumed_sharing boolean;
  state_to_publish text:=case when p_state='auto' then 'online' else p_state end;
begin
  perform sectalk_private.limit_action('v3_presence_set',10);
  if not sectalk_private.st_v2_active(actor) then return; end if;
  if p_state is null or p_state not in ('auto','online','away','busy','offline','invisible') then
    raise exception 'Choose an availability state';
  end if;
  perform id from public.st_profiles where id=actor for update;
  sharing_required:=sectalk_private.st_v6_presence_required(actor);
  if p_state='invisible' and sharing_required then
    raise exception 'A workspace policy requires availability sharing';
  end if;
  insert into public.st_v3_presence(user_id,state,expires_at,automatic)
    values(actor,state_to_publish,
      case when state_to_publish in ('offline','invisible') then now() else now()+interval '100 seconds' end,
      p_state='auto')
    on conflict(user_id) do update set state=excluded.state,expires_at=excluded.expires_at,automatic=excluded.automatic;
  if sharing_required then
    delete from sectalk_private.st_v6_presence_privacy where user_id=actor and not share_availability
      returning true into resumed_sharing;
    if resumed_sharing then perform sectalk_private.st_v6_contact_presence_refresh(actor); end if;
  end if;
end $$;

create or replace function sectalk_private.st_v6_discovery_results(
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
      and (not available.automatic or available.expires_at>now()+interval '40 seconds')
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

commit;
