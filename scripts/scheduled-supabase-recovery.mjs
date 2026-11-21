import {spawn} from 'node:child_process'
import {mkdtemp} from 'node:fs/promises'
import {isAbsolute,join} from 'node:path'
import {fileURLToPath} from 'node:url'

const recover=fileURLToPath(new URL('./supabase-recovery.mjs',import.meta.url))
const settings=process.env
const run=(program,args=[],env=settings)=>new Promise((done,failed)=>{
  const child=spawn(program,args,{env,stdio:'inherit',windowsHide:true})
  child.on('error',()=>failed(new Error('The recovery runner could not start a tool.')))
  child.on('close',code=>code===0?done():failed(new Error('A scheduled recovery step failed.')))
})
function configured(name) {
  if (!settings[name]||!isAbsolute(settings[name])) throw new Error('A protected recovery runner path is missing.')
  return settings[name]
}

try {
  const root=configured('SECTALK_DR_ARCHIVE_ROOT')
  const freeze=configured('SECTALK_DR_FREEZE_HOOK')
  const release=configured('SECTALK_DR_RELEASE_HOOK')
  const prepare=configured('SECTALK_DR_TARGET_HOOK')
  const assertions=configured('SECTALK_DR_ASSERTIONS')
  const source=settings.SECTALK_DR_SOURCE_LIBPQ_SERVICE
  const target=settings.SECTALK_DR_TARGET_CONTAINER
  if (!source||!target) throw new Error('Set the read-source libpq service and disposable recovery target.')
  const generation=await mkdtemp(join(root,'dr-generation-'))
  const archive=join(generation,'project')
  try {
    await run(freeze)
    await run(process.execPath,[recover,'capture','--archive',archive,'--source-service',source],{...settings,SECTALK_DR_SOURCE_FROZEN:'yes'})
  } finally {
    await run(release)
  }
  await run(prepare)
  await run(process.execPath,[recover,'verify','--archive',archive,'--target-container',target,'--assert',assertions])
} catch(error) {
  console.error(error.message)
  process.exitCode=1
}
