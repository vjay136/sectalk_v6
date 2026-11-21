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

function upgradeManifest(files){
  const values=files.map(name=>{
    const [,version,description]=name.match(pattern)
    return `('${version}','${description}')`
  })
  return `-- SecTalk by Eagle Security
-- Upgrade one existing Supabase database with psql -v ON_ERROR_STOP=1.
-- Run the entire file in one connection. The exact migration prefix is checked before every change.

create temporary table sectalk_expected_migrations(version text primary key, name text not null);
insert into pg_temp.sectalk_expected_migrations(version,name) values
${values.join(',\n')};`
}

function verifyUpgradePrefix(previous){
  return `
lock table supabase_migrations.schema_migrations in share row exclusive mode;
do $sectalk_upgrade_preflight$
begin
  if to_regclass('auth.users') is null or to_regclass('storage.objects') is null
    or to_regclass('public.st_profiles') is null then
    raise exception 'SecTalk requires an initialized Supabase project with SecTalk installed.';
  end if;
  if exists (
    select 1
    from (select version,name from pg_temp.sectalk_expected_migrations where version <= '${previous}') expected
    full join supabase_migrations.schema_migrations actual using(version)
    where expected.version is null or actual.version is null or expected.name is distinct from actual.name
  ) then
    raise exception 'SecTalk migration history differs from the required prefix through ${previous}.';
  end if;
end
$sectalk_upgrade_preflight$;
`
}

const [output,mode,baseline,...extra]=process.argv.slice(2)

try{
  if(!output||extra.length||(mode!==undefined&&(mode!=='--after'||!baseline))){
    throw new Error('Usage: node scripts/build-supabase-schema.mjs OUTPUT [--after MIGRATION_VERSION]')
  }
  const files=(await readdir(migrations,{withFileTypes:true})).filter(entry=>entry.isFile()&&entry.name.endsWith('.sql'))
    .map(entry=>entry.name).sort()
  if(!files.length||files.some(name=>!pattern.test(name))||new Set(files.map(name=>name.match(pattern)[1])).size!==files.length){
    throw new Error('Every migration needs a unique timestamped filename.')
  }
  const start=baseline===undefined?0:files.findIndex(name=>name.match(pattern)[1]===baseline)+1
  if(baseline!==undefined&&(!start||start===files.length)){
    throw new Error('The baseline must be a repository migration version with newer migrations available.')
  }
  const sections=await Promise.all(files.slice(start).map(async (name,index)=>{
    const source=(await readFile(new URL(name,migrations),'utf8')).replace(/\r\n/g,'\n').trimEnd()
    if(!source)throw new Error('Empty migration: '+name)
    const [,version,description]=name.match(pattern)
    const leadingTransaction=/^\s*(?:--[^\n]*\n\s*)*begin;\s*(?=\n|$)/i.test(source)
    const trailingTransaction=/\ncommit;$/i.test(source)
    if(leadingTransaction!==trailingTransaction)throw new Error('Unexpected migration transaction boundary: '+name)
    let body=leadingTransaction?source.replace(/\ncommit;$/i,''):'begin;\n'+source
    if(start){
      const previous=files[start+index-1].match(pattern)[1]
      body=body.replace(/^(\s*(?:--[^\n]*\n\s*)*begin;)/i,`$1\n${verifyUpgradePrefix(previous)}`)
    }
    return '-- Migration '+name+'\n'+body+'\n\n'+
      `insert into supabase_migrations.schema_migrations(version,name) values('${version}','${description}');\ncommit;\n`
  }))
  const header=start?upgradeManifest(files):preflight
  const cleanup=start?'\ndrop table pg_temp.sectalk_expected_migrations;\n':''
  const bundle=header+'\n\n'+sections.join('\n')+cleanup
  await writeFile(resolve(output),bundle,{encoding:'utf8',mode:0o600,flag:'wx'})
  console.log(JSON.stringify({migrations:sections.length,...(start?{after:baseline}:{}),sha256:createHash('sha256').update(bundle).digest('hex')}))
}catch(error){
  console.error(error?.code==='EEXIST'?'Choose a new output path. The schema bundle already exists.':error.message)
  process.exitCode=1
}
