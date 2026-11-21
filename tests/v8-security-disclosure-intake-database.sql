\set ON_ERROR_STOP on
begin;
do $$
declare scope text:=encode(sha256(gen_random_uuid()::text::bytea),'hex'); report_id uuid; i integer;
declare envelope text:='v1.ABCDEFGHIJKLMNOQ.ABCDEFGHIJKLMNOPQRSTUV.ABCDEFGHIJKLMNOPQRSTUVWXYZ';
begin
  if has_function_privilege('anon','public.st_v8_disclosure_queue(text,uuid,text)','execute')
    or has_function_privilege('authenticated','public.st_v8_disclosure_submit(uuid,text,text,text)','execute')
    or has_table_privilege('authenticated','sectalk_private.st_v8_disclosure_intake','select')
    or has_table_privilege('authenticated','sectalk_private.st_v8_disclosure_audit','insert') then
    raise exception 'Anonymous or direct authenticated access bypassed the disclosure boundary';
  end if;
  for i in 1..5 loop
    report_id:=gen_random_uuid();
    if public.st_v8_disclosure_submit(report_id,encode(sha256(report_id::text::bytea),'hex'),envelope,scope)<>'received' then
      raise exception 'The legitimate synthetic report was incorrectly refused';
    end if;
  end loop;
  report_id:=gen_random_uuid();
  if public.st_v8_disclosure_submit(report_id,encode(sha256(report_id::text::bytea),'hex'),envelope,scope)<>'limited'
    or exists(select 1 from sectalk_private.st_v8_disclosure_intake where id=report_id)
    or exists(select 1 from sectalk_private.st_v8_disclosure_audit a where a.report=report_id) then
    raise exception 'Rate-limited submission was accepted or recorded';
  end if;
end $$;
rollback;
