begin;
do $$
declare tenant uuid:=gen_random_uuid(); outsider uuid:=gen_random_uuid();
  pinned text:='external_v2_'||repeat('a',43)||'_';
begin
  insert into sectalk_private.st_v7_tenant_key_versions(workspace,version,custody,provider_ref,wrapped) values
    (tenant,1,'byok','first',pinned||repeat('b',43));
  begin
    insert into sectalk_private.st_v7_tenant_key_versions(workspace,version,custody,provider_ref,wrapped) values
      (tenant,2,'byok','duplicate',pinned||repeat('c',43));
    raise exception 'A rotation reused the same immutable key';
  exception when unique_violation then null;
  end;
  begin
    insert into sectalk_private.st_v7_tenant_key_versions(workspace,version,custody,provider_ref,wrapped) values
      (outsider,1,'byok','duplicate',pinned||repeat('d',43));
    raise exception 'Another workspace reused the same immutable key';
  exception when unique_violation then null;
  end;
  insert into sectalk_private.st_v7_tenant_key_versions(workspace,version,custody,provider_ref,wrapped) values
    (tenant,2,'byok','second','external_v2_'||repeat('e',43)||'_'||repeat('f',43)),
    (tenant,3,'managed',null,repeat('z',80)),
    (outsider,1,'byok','legacy',repeat('z',80));
end $$;
select 'passed: exclusive provider key pin across tenants and rotations with legacy compatibility' as result;
rollback;
