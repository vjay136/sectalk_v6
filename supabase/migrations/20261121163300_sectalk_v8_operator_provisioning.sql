begin;

create table sectalk_private.st_v8_operator_provisioning_audit (
  id bigint generated always as identity primary key,
  account uuid not null,
  capability text not null check (capability in ('moderation','account_operator','account_reviewer')),
  database_role name not null,
  approval_reference text not null check (char_length(approval_reference) between 8 and 160),
  granted_at timestamptz not null default clock_timestamp()
);
alter table sectalk_private.st_v8_operator_provisioning_audit enable row level security;
revoke all on sectalk_private.st_v8_operator_provisioning_audit from public,anon,authenticated,service_role;

create function sectalk_private.st_v8_provision_operator(
  p_account uuid,p_confirmed_email text,p_capability text,p_approval_reference text
) returns boolean language plpgsql security invoker set search_path='' as $$
declare assigned text; granted boolean;
begin
  if p_account is null or nullif(btrim(p_confirmed_email),'') is null or
    p_capability is null or p_capability not in ('moderation','account_operator','account_reviewer') or
    p_approval_reference is null or char_length(btrim(p_approval_reference)) not between 8 and 160
    then raise exception 'Provide the exact account, confirmed email, capability and approval reference.' using errcode='22023'; end if;

  perform 1 from auth.users u join public.st_profiles p on p.id=u.id
    where u.id=p_account and lower(btrim(u.email))=lower(btrim(p_confirmed_email))
      and u.email_confirmed_at is not null and nullif(btrim(u.email_change),'') is null
      and u.deleted_at is null and u.is_anonymous is not true and u.is_sso_user is not true
      and nullif(u.encrypted_password,'') is not null
      and exists(select 1 from auth.identities i where i.user_id=u.id and i.provider='email')
      and sectalk_private.st_v2_active(p_account)
    for no key update of u;
  if not found then raise exception 'The exact active, confirmed account is required.' using errcode='42501'; end if;

  perform 1 from auth.mfa_factors f
    where f.user_id=p_account and f.factor_type='totp' and f.status='verified'
    order by f.id limit 1 for share;
  if not found then raise exception 'The account must enroll and verify a TOTP authenticator before provisioning.'
    using errcode='42501'; end if;

  if p_capability='moderation' then
    insert into sectalk_private.staff(user_id) values(p_account) on conflict do nothing;
    granted:=found;
  else
    assigned:=case p_capability when 'account_operator' then 'operator' else 'reviewer' end;
    insert into sectalk_private.st_v7_account_operators(user_id,capability) values(p_account,assigned)
      on conflict(user_id) do nothing;
    granted:=found;
    if not exists(select 1 from sectalk_private.st_v7_account_operators o
      where (o.user_id,o.capability)=(p_account,assigned)) then
      raise exception 'The account already has the other account-administration role.' using errcode='PT409';
    end if;
  end if;

  if granted then
    insert into sectalk_private.st_v8_operator_provisioning_audit(account,capability,database_role,approval_reference)
      values(p_account,p_capability,current_user,btrim(p_approval_reference));
  end if;
  return granted;
end $$;
revoke all on function sectalk_private.st_v8_provision_operator(uuid,text,text,text) from public,anon,authenticated,service_role;

commit;
