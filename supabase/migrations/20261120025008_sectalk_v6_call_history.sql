begin;

alter table public.st_calls add column end_reason text
  check(end_reason is null or (status='ended' and end_reason in ('missed','declined','cancelled')));

create or replace function public.st_call_status(p_call uuid,p_accept boolean)
returns void language plpgsql security definer set search_path='' as $$
begin
  perform sectalk_private.limit_action('call_status',20);
  if p_accept is null then raise exception 'Choose whether to accept the call'; end if;
  if p_accept then
    update public.st_calls set status='active',expires_at=now()+interval '2 hours'
    where id=p_call and callee=auth.uid() and status='ringing' and expires_at>now()
      and sectalk_private.open_pair(caller,callee);
    if not found then raise exception 'This call is unavailable'; end if;
  else
    update public.st_calls set status='ended',expires_at=now(),end_reason=case
      when status='ringing' and expires_at<=now() then 'missed'
      when status='ringing' and callee=auth.uid() then 'declined'
      when status='ringing' then 'cancelled'
      else null end
    where id=p_call and auth.uid() in (caller,callee) and status<>'ended';
  end if;
end $$;

commit;
