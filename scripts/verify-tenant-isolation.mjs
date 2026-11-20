import { spawnSync } from 'node:child_process'
import { readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'

const fixtureRoot = fileURLToPath(new URL('..', import.meta.url))
const app = new URL(process.env.SECTALK_STORAGE_TEST_APP ?? '')
const backend = new URL(process.env.SECTALK_STORAGE_TEST_URL ?? '')
if (app.hostname !== '127.0.0.1' || backend.origin !== 'http://127.0.0.1:55321') {
  throw new Error('Tenant isolation fixtures require the disposable loopback QA services.')
}
const check = await fetch(new URL('/api/health', app), { signal: AbortSignal.timeout(10000) })
const state = await check.json()
if (!check.ok || state.status !== 'configured' || !String(state.version).startsWith('6.')) {
  throw new Error('The QA app must be a configured SecTalk v6 candidate.')
}

const database = [
  'v2-database', 'v5-database', 'v6-workspace-context-database', 'v6-tenant-operations-database',
  'v6-tenant-metadata-cache-database', 'v6-workspace-admin-overview-database', 'v6-workspace-room-reports-database',
]
const browser = [
  'workspace-context', 'tenant-operations', 'workspace-admin-overview', 'workspace-file-duplicates',
  'workspace-file-access-history', 'room-files-and-calls', 'workspace-room-reports',
  'workspace-integrations', 'workspace-feature-controls',
]
function run(file, command, args, input) {
  console.log('Tenant isolation: ' + file)
  const result = spawnSync(command, args, {
    cwd: fixtureRoot, input, encoding: 'utf8', stdio: [input ? 'pipe' : 'inherit', 'inherit', 'inherit'],
    windowsHide: true,
  })
  if (result.error) throw result.error
  if (result.status !== 0) throw new Error(file + ' did not pass.')
}
for (const suite of database) {
  const file = 'tests/' + suite + '.sql'
  const sql = readFileSync(new URL('../' + file, import.meta.url), 'utf8')
  run(file, 'docker', ['exec', '-i', 'supabase_db_v4-auth-qa', 'psql', '-X', '-q', '-v', 'ON_ERROR_STOP=1',
    '-U', 'postgres', '-d', 'postgres'], sql)
}
for (const suite of browser) {
  const file = 'tests/' + suite + '.e2e.mjs'
  run(file, process.execPath, [file])
}
console.log('Tenant isolation verified across ' + database.length + ' database and ' + browser.length + ' browser suites.')
