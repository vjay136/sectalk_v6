import {createHash} from 'node:crypto'
import {readFile,readdir,writeFile} from 'node:fs/promises'
import {resolve} from 'node:path'

const migrations=new URL('../supabase/migrations/',import.meta.url)
const pattern=/^(\d{12,14})_([a-z0-9_]+)\.sql$/i
const preflight=`-- SecTalk by Eagle Security
-- Install once on a fresh Supabase database with psql -v ON_ERROR_STOP=1.
-- Auth templates, SMTP and provider credentials are configured separately.

begin;
do $sectalk_fresh_install$
begin
  if to_regclass('auth.users') is null or to_regclass('storage.objects') is null then
    raise exception 'SecTalk requires an initialized Supabase project.';
  end if;
  if to_regnamespace('sectalk_private') is not null or to_regclass('public.st_profiles') is not null then
    raise exception 'Use a fresh Supabase project. This database already contains SecTalk.';
  end if;
  if to_regclass('supabase_migrations.schema_migrations') is not null then
    if exists(select 1 from supabase_migrations.schema_migrations) then
      raise exception 'Use a fresh Supabase project. This database already has application migrations.';
    end if;
  end if;
end
$sectalk_fresh_install$;

create schema if not exists supabase_migrations;
create table if not exists supabase_migrations.schema_migrations (
  version text primary key,
  name text,
  statements text[]
);
alter table supabase_migrations.schema_migrations add column if not exists name text;
alter table supabase_migrations.schema_migrations add column if not exists statements text[];
alter table supabase_migrations.schema_migrations enable row level security;
revoke all on supabase_migrations.schema_migrations from public, anon, authenticated, service_role;
commit;`
const output=process.argv[2]

try{
  if(!output||process.argv.length!==3)throw new Error('Provide the path for a new Supabase schema bundle.')
  const files=(await readdir(migrations,{withFileTypes:true})).filter(entry=>entry.isFile()&&entry.name.endsWith('.sql'))
    .map(entry=>entry.name).sort()
  if(!files.length||files.some(name=>!pattern.test(name))||new Set(files.map(name=>name.match(pattern)[1])).size!==files.length){
    throw new Error('Every migration needs a unique timestamped filename.')
  }
  const sections=await Promise.all(files.map(async name=>{
    const source=(await readFile(new URL(name,migrations),'utf8')).replace(/\r\n/g,'\n').trimEnd()
    if(!source)throw new Error('Empty migration: '+name)
    const [,version,description]=name.match(pattern)
    const leadingTransaction=/^\s*(?:--[^\n]*\n\s*)*begin;\s*(?=\n|$)/i.test(source)
    const trailingTransaction=/\ncommit;$/i.test(source)
    if(leadingTransaction!==trailingTransaction)throw new Error('Unexpected migration transaction boundary: '+name)
    const body=leadingTransaction?source.replace(/\ncommit;$/i,''):'begin;\n'+source
    return '-- Migration '+name+'\n'+body+'\n\n'+
      `insert into supabase_migrations.schema_migrations(version,name) values('${version}','${description}');\ncommit;\n`
  }))
  const bundle=preflight+'\n\n'+sections.join('\n')
  await writeFile(resolve(output),bundle,{encoding:'utf8',mode:0o600,flag:'wx'})
  console.log(JSON.stringify({migrations:files.length,sha256:createHash('sha256').update(bundle).digest('hex')}))
}catch(error){
  console.error(error?.code==='EEXIST'?'Choose a new output path. The schema bundle already exists.':error.message)
  process.exitCode=1
}
