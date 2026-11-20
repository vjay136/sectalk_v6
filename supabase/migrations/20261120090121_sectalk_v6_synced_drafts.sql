begin;

create extension if not exists supabase_vault with schema vault;
select vault.create_secret(encode(extensions.gen_random_bytes(32),'hex'),
  'sectalk_v6_draft_key','Encrypts SecTalk private composer drafts');

create table sectalk_private.st_v6_drafts (
  actor uuid not null references auth.users on delete cascade,
  scope text not null check(scope in ('chat','room')),
  conversation uuid not null,
  parent uuid,
  revision bigint not null,
  ciphertext bytea,
  unique nulls not distinct(actor,scope,conversation,parent),
  check(scope='room' or parent is null)
);
alter table sectalk_private.st_v6_drafts enable row level security;
revoke all on sectalk_private.st_v6_drafts from public,anon,authenticated,service_role;

create function sectalk_private.st_v6_draft_access(p_scope text,p_conversation uuid,p_parent uuid)
returns boolean language sql stable set search_path='' as $$
  select auth.uid() is not null and case
    when p_scope='chat' then p_parent is null and sectalk_private.st_v2_chat_write(p_conversation,auth.uid())
    when p_scope='room' then exists(
      select 1 from public.st_v6_rooms r
      cross join lateral (select sectalk_private.st_v6_room_role(r.id,auth.uid()) as name) role
      where r.id=p_conversation and not r.archived
        and role.name in ('owner','moderator','member','guest')
        and (role.name in ('owner','moderator') or (not r.locked and r.kind not in ('announcement','broadcast')))
        and not exists(select 1 from public.st_v6_room_timeouts t
          where t.room_id=r.id and t.user_id=auth.uid() and t.until_at>now())
        and (p_parent is null or (r.kind<>'announcement' and exists(
          select 1 from public.st_v6_room_posts p where p.room_id=r.id and p.id=p_parent and p.parent_id is null
        )))
    )
    else false end
$$;

create function sectalk_private.st_v6_draft_secret()
returns text language sql stable set search_path='' as $$
  select s.decrypted_secret from vault.decrypted_secrets s where s.name='sectalk_v6_draft_key'
$$;

create function sectalk_private.st_v6_read_draft(p_actor uuid,p_scope text,p_conversation uuid,p_parent uuid)
returns jsonb language plpgsql stable security definer set search_path='' as $$
declare saved sectalk_private.st_v6_drafts;
declare draft_key text;
begin
  if auth.uid() is distinct from p_actor or not coalesce(sectalk_private.st_v6_draft_access(p_scope,p_conversation,p_parent),false)
  then raise exception 'Draft unavailable' using errcode='42501'; end if;
  select * into saved from sectalk_private.st_v6_drafts
    where actor=auth.uid() and scope=p_scope and conversation=p_conversation and parent is not distinct from p_parent;
  if saved.ciphertext is not null then
    draft_key:=sectalk_private.st_v6_draft_secret();
    if draft_key is null then raise exception 'Draft unavailable'; end if;
  end if;
  return jsonb_build_object('revision',coalesce(saved.revision,0),
    'body',coalesce(extensions.pgp_sym_decrypt(saved.ciphertext,draft_key),''));
end
$$;

create function sectalk_private.st_v6_save_draft(
  p_actor uuid,p_scope text,p_conversation uuid,p_parent uuid,p_expected bigint,p_body text
)
returns jsonb language plpgsql security definer set search_path='' as $$
declare owner_id uuid:=auth.uid();
declare current_revision bigint;
declare draft_key text;
declare encrypted bytea;
begin
  if owner_id is distinct from p_actor or not coalesce(sectalk_private.st_v6_draft_access(p_scope,p_conversation,p_parent),false)
  then raise exception 'Draft unavailable' using errcode='42501'; end if;
  if p_expected is null or p_expected<0 or p_body is null or char_length(p_body)>4000
  then raise exception 'Invalid draft'; end if;
  perform sectalk_private.limit_action('v6_save_draft',180);
  perform pg_advisory_xact_lock(hashtextextended(concat_ws(':',owner_id,p_scope,p_conversation,p_parent),0));
  if not coalesce(sectalk_private.st_v6_draft_access(p_scope,p_conversation,p_parent),false)
  then raise exception 'Draft unavailable' using errcode='42501'; end if;
  select d.revision into current_revision from sectalk_private.st_v6_drafts d
    where d.actor=owner_id and d.scope=p_scope and d.conversation=p_conversation and d.parent is not distinct from p_parent;
  if coalesce(current_revision,0)<>p_expected then
    return sectalk_private.st_v6_read_draft(p_actor,p_scope,p_conversation,p_parent)||jsonb_build_object('saved',false);
  end if;
  if p_body<>'' then
    draft_key:=sectalk_private.st_v6_draft_secret();
    if draft_key is null then raise exception 'Draft unavailable'; end if;
    encrypted:=extensions.pgp_sym_encrypt(p_body,draft_key,'cipher-algo=aes256,compress-algo=0');
  end if;
  insert into sectalk_private.st_v6_drafts(actor,scope,conversation,parent,revision,ciphertext)
    values(owner_id,p_scope,p_conversation,p_parent,p_expected+1,encrypted)
    on conflict(actor,scope,conversation,parent) do update set
      revision=excluded.revision,ciphertext=excluded.ciphertext;
  perform realtime.send(jsonb_build_object('scope',p_scope,'conversation',p_conversation,'parent',p_parent),
    'draft_change','st:account:'||owner_id,true);
  return jsonb_build_object('saved',true,'revision',p_expected+1,'body',p_body);
end
$$;

create function public.st_v6_read_draft(p_actor uuid,p_scope text,p_conversation uuid,p_parent uuid)
returns jsonb language sql stable set search_path=''
return sectalk_private.st_v6_read_draft(p_actor,p_scope,p_conversation,p_parent);

create function public.st_v6_save_draft(p_actor uuid,p_scope text,p_conversation uuid,p_parent uuid,p_expected bigint,p_body text)
returns jsonb language sql set search_path=''
return sectalk_private.st_v6_save_draft(p_actor,p_scope,p_conversation,p_parent,p_expected,p_body);

revoke all on function sectalk_private.st_v6_draft_access(text,uuid,uuid),sectalk_private.st_v6_draft_secret(),
  sectalk_private.st_v6_read_draft(uuid,text,uuid,uuid),sectalk_private.st_v6_save_draft(uuid,text,uuid,uuid,bigint,text),
  public.st_v6_read_draft(uuid,text,uuid,uuid),public.st_v6_save_draft(uuid,text,uuid,uuid,bigint,text)
  from public,anon,authenticated,service_role;
grant execute on function sectalk_private.st_v6_read_draft(uuid,text,uuid,uuid),
  sectalk_private.st_v6_save_draft(uuid,text,uuid,uuid,bigint,text),
  public.st_v6_read_draft(uuid,text,uuid,uuid),public.st_v6_save_draft(uuid,text,uuid,uuid,bigint,text)
  to authenticated;

commit;
