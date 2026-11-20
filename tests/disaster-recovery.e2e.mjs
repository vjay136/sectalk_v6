import assert from 'node:assert/strict'
import { execFileSync } from 'node:child_process'
import { randomBytes } from 'node:crypto'
import { appendFile, mkdtemp, readFile, rmdir, unlink, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { setTimeout as delay } from 'node:timers/promises'

const container = 'sectalk-dr-qa-' + randomBytes(5).toString('hex')
const directory = await mkdtemp(join(tmpdir(), 'sectalk-dr-'))
const archive = join(directory, 'backup')
const assertions = join(directory, 'assert.sql')
const script = fileURLToPath(new URL('../scripts/disaster-recovery.mjs', import.meta.url))

function docker(args, options = {}) {
  return execFileSync('docker', args, { encoding: 'utf8', windowsHide: true, timeout: 30_000, ...options })
}

function query(database, sql) {
  return docker(['exec', '-i', container, 'psql', '-X', '-U', 'postgres', '-d', database,
    '--quiet', '--tuples-only', '--no-align', '--set=ON_ERROR_STOP=1'], { input: sql }).trim()
}

function run(operation, details) {
  return execFileSync(process.execPath, [script, operation, '--container', container,
    '--archive', archive, ...details], { encoding: 'utf8', windowsHide: true, timeout: 30_000 })
}

let started = false
try {
  docker(['run', '--rm', '--detach', '--network=none', '--pull=never', '--name', container,
    '--label', 'com.sectalk.dr.disposable=true', '-e', 'POSTGRES_HOST_AUTH_METHOD=trust', 'postgres:17.6-alpine'])
  started = true
  for (let i = 0; ; i += 1) {
    try {
      // The temporary initialization server listens on its Unix socket only.
      docker(['exec', container, 'pg_isready', '-q', '-h', '127.0.0.1', '-U', 'postgres'])
      break
    } catch (error) {
      if (i === 59) throw error
      await delay(500)
    }
  }
  query('postgres', `
    CREATE ROLE sectalk_dr_reader NOLOGIN;
    CREATE DATABASE sectalk_dr_fixture WITH TEMPLATE=template0;
    CREATE DATABASE sectalk_restore_smoke WITH TEMPLATE=template0;
    CREATE DATABASE sectalk_restore_badcheck WITH TEMPLATE=template0;
    CREATE DATABASE sectalk_restore_tampered WITH TEMPLATE=template0;
  `)
  query('sectalk_dr_fixture', `
    CREATE TABLE public.workspace_data(id integer PRIMARY KEY, label text NOT NULL);
    INSERT INTO public.workspace_data VALUES (1, 'Synthetic test data'), (2, 'Synthetic restricted data');
    ALTER TABLE public.workspace_data ENABLE ROW LEVEL SECURITY;
    CREATE POLICY workspace_fixture_read ON public.workspace_data FOR SELECT TO sectalk_dr_reader USING (id = 1);
    GRANT SELECT ON public.workspace_data TO sectalk_dr_reader;
  `)
  await writeFile(assertions, `
    SET LOCAL ROLE sectalk_dr_reader;
    DO $$ BEGIN
      IF (SELECT label FROM public.workspace_data WHERE id = 1) IS DISTINCT FROM 'Synthetic test data'
        OR EXISTS(SELECT FROM public.workspace_data WHERE id = 2)
        OR NOT EXISTS(SELECT FROM pg_catalog.pg_policy WHERE polname = 'workspace_fixture_read')
        OR NOT (SELECT relrowsecurity FROM pg_catalog.pg_class WHERE oid = 'public.workspace_data'::regclass)
      THEN RAISE EXCEPTION 'restored row or RLS is missing'; END IF;
    END $$;
  `)

  const saved = JSON.parse(run('backup', ['--database', 'sectalk_dr_fixture']))
  assert.equal(saved.status, 'backup_created')
  const verified = JSON.parse(run('verify', ['--database', 'sectalk_restore_smoke', '--assert', assertions]))
  assert.equal(verified.status, 'restore_verified')
  assert.equal(verified.sha256, saved.sha256)
  assert.equal(JSON.parse(await readFile(join(archive, 'manifest.json'), 'utf8')).bytes, saved.bytes)
  assert.throws(() => run('verify', ['--database', 'sectalk_dr_fixture', '--assert', assertions]),
    { stderr: /target database must be named sectalk_restore/ })
  assert.throws(() => run('verify', ['--database', 'sectalk_restore_smoke', '--assert', assertions]),
    { stderr: /restore database is not empty/ })
  const unsafeAssertion = join(directory, 'write.sql')
  await writeFile(unsafeAssertion, 'DELETE FROM public.workspace_data;')
  assert.throws(() => run('verify', ['--database', 'sectalk_restore_badcheck', '--assert', unsafeAssertion]),
    { stderr: /exited with status/ })
  assert.equal(query('sectalk_restore_badcheck', 'SELECT count(*) FROM public.workspace_data;'), '2')
  await appendFile(join(archive, 'database.pgdump'), 'fixture damage')
  assert.throws(() => run('verify', ['--database', 'sectalk_restore_tampered', '--assert', assertions]),
    { stderr: /did not match its integrity manifest/ })
  assert.equal(query('sectalk_restore_tampered', "SELECT to_regclass('public.workspace_data') IS NULL;"), 't')
  console.log('Passed backup, transactional restore, restored rows and RLS checks, target protection, read-only assertions and checksum rejection.')
} finally {
  try {
    if (started) docker(['stop', container])
  } finally {
    await Promise.allSettled([assertions, join(directory, 'write.sql'), join(archive, 'manifest.json'),
      join(archive, 'database.pgdump')].map(path => unlink(path)))
    await rmdir(archive).catch(() => {})
    await rmdir(directory)
  }
}
