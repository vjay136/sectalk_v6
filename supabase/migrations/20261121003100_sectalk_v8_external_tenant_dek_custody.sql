begin;
alter table sectalk_private.st_v7_artifact_envelopes
  drop constraint st_v7_artifact_envelopes_wrapped_dek_check,
  add constraint st_v7_artifact_envelopes_wrapped_dek_check check(length(wrapped_dek) between 80 and 2048 and wrapped_dek ~ '^[A-Za-z0-9_-]+$');
alter table sectalk_private.st_v8_channel_payloads
  drop constraint st_v8_channel_payloads_wrapped_dek_check,
  add constraint st_v8_channel_payloads_wrapped_dek_check check(length(wrapped_dek) between 80 and 2048 and wrapped_dek ~ '^[A-Za-z0-9_-]+$');

-- The stable fingerprint pins a distinct immutable provider key. A different
-- workspace or rotation cannot register the same provider key a second time.
-- The remainder of the marker binds that fingerprint to the exact key version.
create unique index st_v8_external_tenant_key_unique_pin
  on sectalk_private.st_v7_tenant_key_versions(left(wrapped,55))
  where custody='byok' and wrapped ~ '^external_v2_[A-Za-z0-9_-]{43}_[A-Za-z0-9_-]{43}$';
commit;
