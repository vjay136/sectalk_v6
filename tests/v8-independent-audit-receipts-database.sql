begin;

grant sectalk_audit_anchor_reader to current_user with set true;

do $$
declare checkpoint jsonb;
begin
  if has_function_privilege('authenticated','sectalk_private.st_v8_audit_checkpoint(text,text)','EXECUTE')
    or has_function_privilege('service_role','sectalk_private.st_v8_audit_checkpoint(text,text)','EXECUTE')
    or has_table_privilege('sectalk_audit_anchor_reader','sectalk_private.st_v6_audit_chain','SELECT,INSERT,UPDATE,DELETE') then
    raise exception 'The independent reader must only see checkpoint digests';
  end if;
  set local role sectalk_audit_anchor_reader;
  checkpoint:=sectalk_private.st_v8_audit_checkpoint();
  if checkpoint ?& array['entry','sha256'] is not true then raise exception 'Missing receipt fields'; end if;
  if sectalk_private.st_v8_audit_checkpoint(checkpoint->>'entry',checkpoint->>'sha256')<>checkpoint then
    raise exception 'Valid checkpoint was not verified';
  end if;
  begin
    perform sectalk_private.st_v8_audit_checkpoint(checkpoint->>'entry',repeat('a',64));
    raise exception 'Independent digest mismatch was not refused';
  exception when others then
    if sqlerrm not like 'SecTalk audit anchor mismatch at entry %' then raise; end if;
  end;
  begin
    perform sectalk_private.st_v8_audit_checkpoint(checkpoint->>'entry',null);
    raise exception 'Invalid independent checkpoint was not refused';
  exception when invalid_parameter_value then null;
  end;
  reset role;
end;
$$;

rollback;
