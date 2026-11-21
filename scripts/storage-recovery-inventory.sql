select json_build_object(
  'bucket',o.bucket_id,'key',o.name,'size',coalesce(o.metadata->>'size',o.metadata->>'contentLength'),
  'contentType',coalesce(o.metadata->>'mimetype','application/octet-stream'),
  'objectVersion',o.version,'owner',o.owner_id
)
from storage.objects o
join storage.buckets b on b.id=o.bucket_id
where not b.public and b.id in ('sectalk-vault','sectalk-chat-files','sectalk-avatars',
  'recordings','sectalk-exports','sectalk-workspace-files','sectalk-encrypted-group-files')
order by o.bucket_id collate "C",o.name collate "C";
