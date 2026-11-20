begin;

create function public.st_v8_consume_password_signup_permit(p_email text,p_token text)
returns boolean language plpgsql security definer set search_path='' as $$
declare address text:=lower(btrim(p_email));
begin
  if address is null or char_length(address)>254 or p_token is null or p_token !~ '^[a-f0-9]{64}$' then
    return false;
  end if;
  delete from sectalk_private.st_v7_signup_proofs p
    where p.token_hash=extensions.digest(p_token,'sha256')
      and p.email_key=sectalk_private.st_v7_rate_bucket('signup_address',address)
      and p.kind='permit' and p.expires_at>clock_timestamp();
  return found;
end;
$$;

create or replace function public.st_v7_before_signup(event jsonb)
returns jsonb language plpgsql security definer set search_path='' as $$
begin
  if event->'user'->'app_metadata'->>'provider' is distinct from 'email' then return '{}'; end if;
  if public.st_v8_consume_password_signup_permit(event->'user'->>'email',event->'user'->'user_metadata'->>'sectalk_signup_gate') then
    return '{}';
  end if;
  return '{"error":{"http_code":403,"message":"Complete signup in SecTalk."}}';
end;
$$;

revoke all on function public.st_v8_consume_password_signup_permit(text,text) from public,anon,authenticated,supabase_auth_admin;
grant execute on function public.st_v8_consume_password_signup_permit(text,text) to service_role;

commit;
