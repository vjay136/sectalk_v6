begin;
create function public.st_v7_authorize_url_inspection()
returns boolean language plpgsql security definer set search_path='' as $$
begin
  if not coalesce(public.st_v7_current_session_valid(),false) or not coalesce(sectalk_private.st_v2_active(auth.uid()),false) then
    return false;
  end if;
  perform sectalk_private.limit_action('user_url_inspection',6);
  return true;
end
$$;
revoke all on function public.st_v7_authorize_url_inspection() from public,anon,authenticated,service_role;
grant execute on function public.st_v7_authorize_url_inspection() to authenticated;
commit;
