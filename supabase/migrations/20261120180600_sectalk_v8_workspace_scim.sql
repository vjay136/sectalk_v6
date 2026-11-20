begin;

create table sectalk_private.st_v8_scim_keys (
  workspace uuid primary key references public.st_v2_workspaces on delete cascade,
  digest text unique not null,
  domain text not null,
  issued_by uuid not null references public.st_profiles on delete cascade,
  expires_at timestamptz not null,
  minute timestamptz not null default date_trunc('minute', now()),
  used int not null default 0
);
create table sectalk_private.st_v8_scim_users (
  workspace uuid not null references public.st_v2_workspaces on delete cascade,
  id uuid not null default gen_random_uuid(),
  principal uuid references public.st_profiles on delete cascade,
  username text not null,
  external_id text,
  display_name text,
  deleted boolean not null default false,
  managed_active boolean not null default false,
  manual_departure boolean not null default false,
  requested_active boolean not null default false,
  primary key(workspace,id),
  unique(workspace,principal),
  unique(workspace,username),
  unique(workspace,external_id)
);
create table sectalk_private.st_v8_scim_groups (
  workspace uuid not null,
  id uuid not null,
  external_id text,
  primary key(workspace,id),
  unique(workspace,external_id),
  foreign key(workspace,id) references public.st_v6_workspace_groups(workspace_id,id) on delete cascade
);
create table sectalk_private.st_v8_scim_pending_groups (
  workspace uuid not null,
  group_id uuid not null,
  user_id uuid not null,
  primary key(workspace,group_id,user_id),
  foreign key(workspace,group_id) references sectalk_private.st_v8_scim_groups on delete cascade,
  foreign key(workspace,user_id) references sectalk_private.st_v8_scim_users on delete cascade
);
alter table sectalk_private.st_v8_scim_keys enable row level security;
alter table sectalk_private.st_v8_scim_users enable row level security;
alter table sectalk_private.st_v8_scim_groups enable row level security;
alter table sectalk_private.st_v8_scim_pending_groups enable row level security;
revoke all on sectalk_private.st_v8_scim_keys,sectalk_private.st_v8_scim_users,
  sectalk_private.st_v8_scim_groups,sectalk_private.st_v8_scim_pending_groups from public,anon,authenticated,service_role;

create function sectalk_private.st_v8_scim_record_departure()
returns trigger language plpgsql security definer set search_path='' as $$
begin
  update sectalk_private.st_v8_scim_users
    set managed_active=false, requested_active=false, manual_departure=true
    where workspace=old.workspace_id and principal=old.user_id and managed_active;
  return old;
end $$;
revoke all on function sectalk_private.st_v8_scim_record_departure() from public,anon,authenticated,service_role;
create trigger st_v8_scim_member_departure after delete on public.st_v2_members
  for each row execute function sectalk_private.st_v8_scim_record_departure();

create function sectalk_private.st_v8_scim_block_inactive_join()
returns trigger language plpgsql security definer set search_path='' as $$
begin
  if exists(select 1 from sectalk_private.st_v8_scim_users u
      where u.workspace=new.workspace_id and u.principal=new.user_id and not u.managed_active) then
    raise insufficient_privilege;
  end if;
  return new;
end $$;
revoke all on function sectalk_private.st_v8_scim_block_inactive_join() from public,anon,authenticated,service_role;
create trigger st_v8_scim_inactive_join before insert on public.st_v2_members
  for each row execute function sectalk_private.st_v8_scim_block_inactive_join();

create function public.st_v8_scim_settings(p_workspace uuid,p_action text default 'read',p_domain text default null)
returns jsonb language plpgsql security definer set search_path='' as $$
declare access text; secret text; setup jsonb;
begin
  access:=sectalk_private.st_v7_file_egress_operator(p_workspace);
  if access is distinct from 'verified' then return jsonb_build_object('access',access); end if;
  if p_action is distinct from 'read' then
    perform sectalk_private.limit_action('v8_scim_settings',5);
    perform 1 from public.st_v2_workspaces where id=p_workspace for update;
    if not found or sectalk_private.st_v7_file_egress_operator(p_workspace) is distinct from 'verified' then
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
revoke all on function public.st_v8_scim_settings(uuid,text,text) from public,anon,authenticated,service_role;
grant execute on function public.st_v8_scim_settings(uuid,text,text) to authenticated;

create function sectalk_private.st_v8_scim_resource(p_workspace uuid,p_kind text,p_id uuid)
returns jsonb language sql stable set search_path='' as $$
  select case p_kind when 'Users' then (
    select jsonb_build_object('id',u.id,'externalId',u.external_id,'userName',u.username,'displayName',u.display_name,
      'active',case when u.principal is null then u.requested_active
        else coalesce(m.role='member' and m.suspended_at is null and sectalk_private.st_v2_active(u.principal),false) end)
    from sectalk_private.st_v8_scim_users u left join public.st_v2_members m
      on m.workspace_id=u.workspace and m.user_id=u.principal
    where u.workspace=p_workspace and u.id=p_id and not u.deleted
  ) else (
    select jsonb_build_object('id',g.id,'externalId',g.external_id,'displayName',d.name,'members',coalesce((
      select jsonb_agg(jsonb_build_object('value',member.id) order by member.id)
      from (
        select u.id from public.st_v6_workspace_group_members m join sectalk_private.st_v8_scim_users u
          on u.workspace=m.workspace_id and u.principal=m.user_id and not u.deleted
        join public.st_v2_members w on w.workspace_id=m.workspace_id and w.user_id=m.user_id
          and w.role='member' and w.suspended_at is null
        where m.workspace_id=g.workspace and m.group_id=g.id
        union
        select u.id from sectalk_private.st_v8_scim_pending_groups p join sectalk_private.st_v8_scim_users u
          on u.workspace=p.workspace and u.id=p.user_id and u.principal is null and u.requested_active and not u.deleted
        where p.workspace=g.workspace and p.group_id=g.id
      ) member), '[]'::jsonb))
    from sectalk_private.st_v8_scim_groups g join public.st_v6_workspace_groups d
      on d.workspace_id=g.workspace and d.id=g.id and d.archived_at is null
    where g.workspace=p_workspace and g.id=p_id
  ) end
$$;
revoke all on function sectalk_private.st_v8_scim_resource(uuid,text,uuid) from public,anon,authenticated,service_role;

create function public.st_v8_scim_request(p_digest text,p_kind text,p_method text,p_id uuid,p_body jsonb default '{}',
  p_filter text default null,p_value text default null,p_start int default 1,p_count int default 100)
returns jsonb language plpgsql security definer set search_path='' as $$
declare
  tenant uuid; key_row sectalk_private.st_v8_scim_keys; user_row sectalk_private.st_v8_scim_users;
  group_row sectalk_private.st_v8_scim_groups; account_id uuid; prior_account uuid; item uuid:=p_id; previous jsonb;
  login_name text; label text; reference_id text; active boolean; method_role text; suspended timestamptz;
  patch jsonb; member_values jsonb; member_op text; member_id uuid; resource_ids uuid[]; total int; response jsonb;
begin
  select k.workspace into tenant from sectalk_private.st_v8_scim_keys k where k.digest=p_digest;
  if not found then return '{"status":401}'; end if;
  perform 1 from public.st_v2_workspaces where id=tenant for update;
  select * into key_row from sectalk_private.st_v8_scim_keys k
    where k.workspace=tenant and k.digest=p_digest and k.expires_at>clock_timestamp();
  if not found or sectalk_private.st_v2_role(tenant,key_row.issued_by) is distinct from 'owner'
    or not sectalk_private.st_v2_active(key_row.issued_by)
    or (sectalk_private.st_v7_workspace_entitlements(tenant)).plan is distinct from 'enterprise'
    or not exists(select 1 from sectalk_private.st_v7_org_domains d where d.workspace=tenant
      and d.domain=key_row.domain and d.verified_at is not null) then return '{"status":401}'; end if;
  if key_row.minute=date_trunc('minute',now()) and key_row.used>=120 then return '{"status":429}'; end if;
  update sectalk_private.st_v8_scim_keys set used=case when minute=date_trunc('minute',now()) then used+1 else 1 end,
    minute=date_trunc('minute',now()) where workspace=tenant;
  if p_kind='ServiceProviderConfig' and p_method='GET' then return '{"status":200}'; end if;
  if p_kind not in ('Users','Groups') or p_method not in ('GET','POST','PATCH','PUT','DELETE') then return '{"status":404}'; end if;
  if p_method='GET' and item is null then
    with candidates as (
      select u.id from sectalk_private.st_v8_scim_users u where p_kind='Users' and u.workspace=tenant and not u.deleted
        and (p_filter is null or p_filter='username' and u.username=lower(p_value) or p_filter='externalid' and u.external_id=p_value)
      union all
      select g.id from sectalk_private.st_v8_scim_groups g join public.st_v6_workspace_groups d
        on d.workspace_id=g.workspace and d.id=g.id where p_kind='Groups' and g.workspace=tenant and d.archived_at is null
        and (p_filter is null or p_filter='displayname' and lower(d.name)=lower(p_value) or p_filter='externalid' and g.external_id=p_value)
    )
    select (select count(*) from candidates), (select array_agg(page.id order by page.id) from
      (select c.id from candidates c order by c.id offset greatest(p_start-1,0) limit least(greatest(p_count,0),100)) page)
      into total,resource_ids;
    select coalesce(jsonb_agg(sectalk_private.st_v8_scim_resource(tenant,p_kind,id) order by id),'[]'::jsonb)
      into response from unnest(resource_ids) id;
    return jsonb_build_object('status',200,'total',total,'resources',response);
  end if;
  if p_method<>'POST' then
    previous:=sectalk_private.st_v8_scim_resource(tenant,p_kind,item);
    if previous is null then return '{"status":404}'; end if;
    if p_method='GET' then return jsonb_build_object('status',200,'resource',previous); end if;
  end if;
  -- The mutation block rolls back every row in a rejected multi-operation PATCH.
  begin
    if p_kind='Users' then
      select * into user_row from sectalk_private.st_v8_scim_users u where u.workspace=tenant and u.id=item;
      login_name:=lower(btrim(coalesce(p_body->>'userName',user_row.username)));
      label:=case when p_method='PUT' or p_body?'displayName' then nullif(btrim(p_body->>'displayName'),'') else user_row.display_name end;
      reference_id:=case when p_method='PUT' or p_body?'externalId' then nullif(btrim(p_body->>'externalId'),'') else user_row.external_id end;
      active:=case when p_method='DELETE' then false when p_body?'active' then (p_body->>'active')::boolean
        else coalesce((previous->>'active')::boolean,true) end;
      if login_name is null or length(login_name)>254 or login_name !~ '^[^@[:space:]]+@[^@[:space:]]+$'
        or length(label)>120 or length(reference_id)>160 or active is null then raise invalid_parameter_value; end if;
      if p_method='POST' then
        select case when count(*)=1 then min(a.id::text)::uuid end into account_id
        from auth.users a join public.st_profiles s on s.id=a.id
        where lower(a.email)=login_name and a.email_confirmed_at is not null and sectalk_private.st_v2_active(a.id);
        if exists(select 1 from sectalk_private.st_v8_scim_users u
            where u.workspace=tenant and u.username=login_name and not u.deleted) then
          raise unique_violation;
        end if;
        if split_part(login_name,'@',2)<>key_row.domain
          or exists(select 1 from public.st_v2_members m where m.workspace_id=tenant and m.user_id=account_id)
          or exists(select 1 from sectalk_private.st_v8_scim_users u where u.workspace=tenant and u.principal=account_id and u.manual_departure)
          then raise insufficient_privilege; end if;
        select u.id,u.principal into item,prior_account from sectalk_private.st_v8_scim_users u
          where u.workspace=tenant and u.username=login_name and u.deleted
            and (u.principal is null or u.principal=account_id);
        if found then account_id:=prior_account; end if;
        item:=coalesce(item,gen_random_uuid());
        insert into sectalk_private.st_v8_scim_users(workspace,id,principal,username,external_id,display_name)
          values(tenant,item,account_id,login_name,reference_id,label)
          on conflict(workspace,id) do update set username=excluded.username,external_id=excluded.external_id,
            display_name=excluded.display_name,deleted=false;
      else
        account_id:=user_row.principal;
        if login_name is distinct from user_row.username then raise invalid_parameter_value; end if;
        update sectalk_private.st_v8_scim_users u set external_id=reference_id,display_name=label,
          deleted=p_method='DELETE' where u.workspace=tenant and u.id=item;
      end if;
      update sectalk_private.st_v8_scim_users u set requested_active=active where u.workspace=tenant and u.id=item;
      if not active then
        delete from sectalk_private.st_v8_scim_pending_groups m where m.workspace=tenant and m.user_id=item;
      end if;
      select m.role,m.suspended_at into method_role,suspended from public.st_v2_members m
        where m.workspace_id=tenant and m.user_id=account_id for update;
      if method_role is not null and method_role<>'member' then raise insufficient_privilege; end if;
      if account_id is not null and active then
        if split_part(login_name,'@',2)<>key_row.domain or suspended is not null or coalesce(user_row.manual_departure,false)
          or not exists(select 1 from auth.users a where a.id=account_id and lower(a.email)=login_name and a.email_confirmed_at is not null
            and sectalk_private.st_v2_active(a.id)) then raise insufficient_privilege; end if;
        update sectalk_private.st_v8_scim_users u set managed_active=true where u.workspace=tenant and u.id=item;
        if method_role is null then
          if (select count(*) from public.st_v2_members m where m.workspace_id=tenant)>=
            coalesce((sectalk_private.st_v7_workspace_entitlements(tenant)).seat_limit,0) then
            raise check_violation;
          end if;
          insert into public.st_v2_members(workspace_id,user_id,role) values(tenant,account_id,'member');
        end if;
      elsif account_id is not null then
        if suspended is not null then raise insufficient_privilege; end if;
        update sectalk_private.st_v8_scim_users u set managed_active=false where u.workspace=tenant and u.id=item;
        delete from public.st_v2_members m where m.workspace_id=tenant and m.user_id=account_id and m.role='member';
      end if;
    else
      select * into group_row from sectalk_private.st_v8_scim_groups g where g.workspace=tenant and g.id=item;
      label:=btrim(coalesce(p_body->>'displayName',case when p_method='PATCH' or p_method='DELETE' then previous->>'displayName' end));
      reference_id:=case when p_method='PUT' or p_body?'externalId' then nullif(btrim(p_body->>'externalId'),'') else group_row.external_id end;
      if label is null or length(label) not between 1 and 80 or length(reference_id)>160 then raise invalid_parameter_value; end if;
      if p_method='POST' then
        item:=gen_random_uuid();
        insert into public.st_v6_workspace_groups(workspace_id,id,kind,name) values(tenant,item,'group',label);
        insert into sectalk_private.st_v8_scim_groups values(tenant,item,reference_id);
      elsif p_method='DELETE' then
        delete from sectalk_private.st_v8_scim_groups g where g.workspace=tenant and g.id=item;
        delete from public.st_v6_workspace_group_members m where m.workspace_id=tenant and m.group_id=item;
        update public.st_v6_workspace_groups d set archived_at=clock_timestamp() where d.workspace_id=tenant and d.id=item;
      else
        update public.st_v6_workspace_groups d set name=label where d.workspace_id=tenant and d.id=item;
        update sectalk_private.st_v8_scim_groups g set external_id=reference_id where g.workspace=tenant and g.id=item;
      end if;
      if p_method<>'DELETE' then
        for patch in select value from jsonb_array_elements(
          case when p_method='PATCH' then coalesce(p_body->'memberOps','[]'::jsonb)
          else jsonb_build_array(jsonb_build_object('op','replace','value',coalesce(p_body->'members','[]'::jsonb))) end)
        loop
          member_op:=patch->>'op';
          member_values:=patch->'value';
          if member_op is null or member_op not in ('add','replace','remove') or jsonb_typeof(member_values) is distinct from 'array'
            or jsonb_array_length(member_values)>1000 then raise invalid_parameter_value; end if;
          if member_op='replace' then
            delete from sectalk_private.st_v8_scim_pending_groups m where m.workspace=tenant and m.group_id=item;
            delete from public.st_v6_workspace_group_members m where m.workspace_id=tenant and m.group_id=item
              and exists(select 1 from sectalk_private.st_v8_scim_users u where u.workspace=tenant and u.principal=m.user_id);
          end if;
          for patch in select value from jsonb_array_elements(member_values) loop
            select u.id,u.principal into member_id,account_id from sectalk_private.st_v8_scim_users u
              left join public.st_v2_members m on m.workspace_id=u.workspace and m.user_id=u.principal
              where u.workspace=tenant and u.id=(patch->>'value')::uuid and not u.deleted and
                (member_op='remove' or u.principal is null and u.requested_active
                 or m.role='member' and m.suspended_at is null and sectalk_private.st_v2_active(u.principal));
            if member_id is null then raise insufficient_privilege; end if;
            if account_id is null then
              if member_op='remove' then
                delete from sectalk_private.st_v8_scim_pending_groups m
                  where m.workspace=tenant and m.group_id=item and m.user_id=member_id;
              else
                insert into sectalk_private.st_v8_scim_pending_groups values(tenant,item,member_id) on conflict do nothing;
              end if;
            elsif member_op='remove' then
              delete from public.st_v6_workspace_group_members m where m.workspace_id=tenant and m.group_id=item and m.user_id=account_id;
            else
              insert into public.st_v6_workspace_group_members values(tenant,item,account_id) on conflict do nothing;
            end if;
          end loop;
        end loop;
      end if;
    end if;
    insert into public.st_v2_workspace_audit(workspace_id,actor,event,target)
      values(tenant,key_row.issued_by,'scim.'||lower(p_kind)||'.'||lower(p_method),item);
    return case when p_method='DELETE' then '{"status":204}'::jsonb else
      jsonb_build_object('status',case when p_method='POST' then 201 else 200 end,
        'resource',sectalk_private.st_v8_scim_resource(tenant,p_kind,item)) end;
  exception
    when insufficient_privilege then return '{"status":403}';
    when unique_violation then return '{"status":409}';
    when check_violation then return '{"status":409}';
    when invalid_parameter_value or invalid_text_representation then return '{"status":400}';
  end;
end $$;
revoke all on function public.st_v8_scim_request(text,text,text,uuid,jsonb,text,text,int,int) from public,anon,authenticated,service_role;
grant execute on function public.st_v8_scim_request(text,text,text,uuid,jsonb,text,text,int,int) to service_role;

create function public.st_v8_scim_claim(p_accept boolean default false)
returns jsonb language plpgsql security definer set search_path='' as $$
declare
  actor uuid:=auth.uid(); login_name text; provision sectalk_private.st_v8_scim_users;
  native_session text:=auth.jwt()->>'session_id'; eligible_workspaces uuid[];
begin
  if actor is null or p_accept is null or public.st_v7_current_session_valid() is not true
    or public.st_v7_account_under_lockdown() is not false or sectalk_private.st_v2_active(actor) is not true then
    return '{"state":"none"}';
  end if;
  select lower(a.email) into login_name from auth.users a where a.id=actor and a.email_confirmed_at is not null
    and lower(a.email)=lower(auth.jwt()->>'email') and exists(select 1 from public.st_profiles s where s.id=actor)
    and exists(select 1 from auth.identities i where i.user_id=actor and i.provider='email'
      and lower(i.email)=lower(a.email) and i.identity_data->>'email_verified'='true');
  if login_name is null or (select count(*) from auth.users a where lower(a.email)=login_name and a.email_confirmed_at is not null)<>1 then
    return '{"state":"none"}';
  end if;
  select array_agg(u.workspace) into eligible_workspaces from sectalk_private.st_v8_scim_users u
    join sectalk_private.st_v7_org_domains d on d.workspace=u.workspace and d.domain=split_part(login_name,'@',2)
    where u.username=login_name and u.principal is null and u.requested_active and not u.deleted and d.verified_at is not null
      and (sectalk_private.st_v7_workspace_entitlements(u.workspace)).plan is not distinct from 'enterprise';
  if coalesce(cardinality(eligible_workspaces),0)<>1 then return '{"state":"none"}'; end if;
  if not p_accept then return '{"state":"pending"}'; end if;
  perform sectalk_private.limit_action('v8_scim_claim',8);
  if not exists(select 1 from auth.sessions s join auth.mfa_amr_claims a on a.session_id=s.id
      where s.id::text=native_session and s.user_id=actor and s.created_at>now()-interval '10 minutes'
        and s.created_at<=now() and a.authentication_method='magiclink') then
    return '{"state":"verify"}';
  end if;
  perform 1 from public.st_v2_workspaces w where w.id=eligible_workspaces[1] for update;
  if not found then return '{"state":"none"}'; end if;
  select * into provision from sectalk_private.st_v8_scim_users u where u.workspace=eligible_workspaces[1]
    and u.username=login_name and u.principal is null and u.requested_active and not u.deleted for update;
  if not found or (sectalk_private.st_v7_workspace_entitlements(provision.workspace)).plan is distinct from 'enterprise'
    or not exists(select 1 from sectalk_private.st_v7_org_domains d where d.workspace=provision.workspace
      and d.domain=split_part(login_name,'@',2) and d.verified_at is not null)
    or exists(select 1 from public.st_v2_members m where m.workspace_id=provision.workspace and m.user_id=actor)
    or exists(select 1 from sectalk_private.st_v8_scim_users u where u.workspace=provision.workspace and u.principal=actor)
    or not exists(select 1 from auth.users a where a.id=actor and lower(a.email)=login_name and a.email_confirmed_at is not null)
    then return '{"state":"none"}'; end if;
  if (select count(*) from public.st_v2_members m where m.workspace_id=provision.workspace)>=
    coalesce((sectalk_private.st_v7_workspace_entitlements(provision.workspace)).seat_limit,0) then return '{"state":"seat_limit"}'; end if;
  update sectalk_private.st_v8_scim_users u set principal=actor,managed_active=true
    where u.workspace=provision.workspace and u.id=provision.id;
  insert into public.st_v2_members(workspace_id,user_id,role) values(provision.workspace,actor,'member');
  insert into public.st_v6_workspace_group_members(workspace_id,group_id,user_id)
    select p.workspace,p.group_id,actor from sectalk_private.st_v8_scim_pending_groups p
    join public.st_v6_workspace_groups g on g.workspace_id=p.workspace and g.id=p.group_id and g.archived_at is null
    where p.workspace=provision.workspace and p.user_id=provision.id;
  delete from sectalk_private.st_v8_scim_pending_groups p where p.workspace=provision.workspace and p.user_id=provision.id;
  insert into public.st_v2_workspace_audit(workspace_id,actor,event,target)
    values(provision.workspace,actor,'scim.user.claimed',provision.id);
  return jsonb_build_object('state','joined','workspace',provision.workspace);
end $$;
revoke all on function public.st_v8_scim_claim(boolean) from public,anon,authenticated,service_role;
grant execute on function public.st_v8_scim_claim(boolean) to authenticated;

commit;
