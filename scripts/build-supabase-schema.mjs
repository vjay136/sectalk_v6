import {createHash} from 'node:crypto'
import {readFile,readdir,writeFile} from 'node:fs/promises'
import {resolve} from 'node:path'

const migrations=new URL('../supabase/migrations/',import.meta.url)
const pattern=/^(\d{12,14})_[a-z0-9_]+\.sql$/i
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
    return '-- Migration '+name+'\n'+source+'\n'
  }))
  const header='-- SecTalk by Eagle Security\n-- Install once in a fresh Supabase project using its PostgreSQL SQL runner.\n'+
    '-- Provision SMTP, Auth URL settings, templates and external provider credentials separately.\n\n'
  const bundle=header+sections.join('\n')
  await writeFile(resolve(output),bundle,{encoding:'utf8',mode:0o600,flag:'wx'})
  console.log(JSON.stringify({migrations:files.length,sha256:createHash('sha256').update(bundle).digest('hex')}))
}catch(error){
  console.error(error?.code==='EEXIST'?'Choose a new output path. The schema bundle already exists.':error.message)
  process.exitCode=1
}
