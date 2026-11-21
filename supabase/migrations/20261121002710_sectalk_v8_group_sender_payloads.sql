begin;

alter table sectalk_private.st_group_messages drop constraint st_group_messages_payload_check;
alter table sectalk_private.st_group_messages add constraint st_group_messages_payload_check
  check (
    (length(payload) between 39 and 5600 and payload ~ '^[A-Za-z0-9_-]+$') or
    (length(payload) between 128 and 12000 and payload ~ '^sk2\.[A-Za-z0-9_-]+$')
  );

commit;
