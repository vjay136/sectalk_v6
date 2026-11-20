import { spawn } from 'node:child_process'
import { createHash } from 'node:crypto'
import { createReadStream, createWriteStream } from 'node:fs'
import { lstat, mkdir, readFile, realpath, rmdir, unlink, writeFile } from 'node:fs/promises'
import { basename, dirname, isAbsolute, join, relative, resolve } from 'node:path'
import { pipeline } from 'node:stream/promises'
import { fileURLToPath } from 'node:url'
import { parseArgs } from 'node:util'

const archiveName = 'database.pgdump'
const manifestName = 'manifest.json'
const repository = await realpath(fileURLToPath(new URL('../', import.meta.url)))
const namePattern = /^[a-zA-Z0-9_-]{1,63}$/
const restoreNamePattern = /^sectalk_restore_[a-z0-9_]{1,47}$/
const clock = () => new Date().toISOString()

function reject(message) {
  throw new Error(message)
}

function databaseName(value) {
  if (!namePattern.test(value ?? '')) reject('Provide an explicit database name.')
  return value
}

function isInside(parent, path) {
  const local = relative(parent, path)
  return local === '' || (!isAbsolute(local) && local !== '..' && !local.startsWith('../') && !local.startsWith('..\\'))
}

function processResult(command, args, { input, output, env = process.env } = {}) {
  return new Promise((done, failed) => {
    const child = spawn(command, args, { env, windowsHide: true, stdio: ['pipe', 'pipe', 'ignore'] })
    const completion = new Promise((resolveProcess, rejectProcess) => {
      child.once('error', () => rejectProcess(new Error(`Could not start ${command}. Check the client installation.`)))
      child.once('close', code => {
        if (code === 0) resolveProcess()
        else rejectProcess(new Error(`${command} exited with status ${code ?? 'signal'} during recovery.`))
      })
    })
    let text = ''
    const capture = output ? pipeline(child.stdout, output) : (async () => {
      child.stdout.setEncoding('utf8')
      for await (const chunk of child.stdout) text = (text + chunk).slice(-65536)
    })()
    const stdin = input ? pipeline(input, child.stdin) : (child.stdin.end(), Promise.resolve())
    child.stdin.on('error', () => {})
    Promise.allSettled([completion, capture, stdin]).then(([code, out, incoming]) => {
      if (code.status === 'rejected') failed(code.reason)
      else if (out.status === 'rejected' || incoming.status === 'rejected') failed(new Error('Could not stream the recovery artifact.'))
      else done(text.trim())
    })
  })
}

async function disposableContainer(name) {
  if (!/^sectalk-dr-[a-z0-9-]{1,42}$/.test(name)) reject('Specify a dedicated sectalk-dr-* disposable container.')
  const label = await processResult('docker', ['inspect', '--type=container', '--format',
    '{{index .Config.Labels "com.sectalk.dr.disposable"}}/{{.HostConfig.NetworkMode}}', name])
  if (label !== 'true/none') reject('The disposable database container must carry the SecTalk label and have networking disabled.')
}

function runTool(target, command, args, io) {
  if (target.container) {
    return processResult('docker', ['exec', '-i', target.container, command, '--no-password',
      '--host=/var/run/postgresql', '--username=postgres', '--dbname=' + target.database, ...args], io)
  }
  const env = { ...process.env, PGCONNECT_TIMEOUT: '10' }
  if (target.service) {
    return processResult(command, ['--no-password', '--dbname=service=' + target.service, ...args], { ...io, env })
  }
  // A connection service, host address override, or inherited SSL proxy must not redirect this writer.
  for (const key of Object.keys(env)) {
    if (key.toUpperCase().startsWith('PG') && !['PGPASSFILE', 'PGCONNECT_TIMEOUT'].includes(key.toUpperCase())) delete env[key]
  }
  return processResult(command, ['--no-password', '--dbname=' + target.database, '--host=127.0.0.1',
    '--port=' + target.port, '--username=' + target.user, ...args], { ...io, env })
}

async function digest(path) {
  let bytes = 0
  const sha256 = createHash('sha256')
  for await (const block of createReadStream(path)) {
    sha256.update(block)
    bytes += block.length
  }
  return { bytes, sha256: sha256.digest('hex') }
}

async function backup(values) {
  const destination = resolve(values.archive)
  const root = await realpath(dirname(destination))
  if (isInside(repository, root)) reject('Use a restricted backup directory outside the SecTalk checkout.')
  const archive = join(root, basename(destination))
  let source
  if (values.container) {
    if (values.service) reject('Choose a source service or a disposable container.')
    await disposableContainer(values.container)
    source = { container: values.container, database: databaseName(values.database) }
  } else {
    if (!namePattern.test(values.service ?? '') || values.database) reject('Choose an explicit libpq source service.')
    source = { service: values.service }
  }

  const createdAt = clock()
  await mkdir(archive, { mode: 0o700 })
  const dump = join(archive, archiveName)
  const manifest = join(archive, manifestName)
  try {
    await runTool(source, 'pg_dump', ['--format=custom', '--lock-wait-timeout=10000',
      '--no-publications', '--no-subscriptions', '--exclude-table-data=cron.job',
      '--exclude-table-data=cron.job_run_details'], { output: createWriteStream(dump, { mode: 0o600, flags: 'wx' }) })
    const result = await digest(dump)
    if (result.bytes === 0) reject('The database backup was empty.')
    await writeFile(manifest, JSON.stringify({ format: 1, createdAt, ...result }) + '\n', { mode: 0o600, flag: 'wx' })
    console.log(JSON.stringify({ status: 'backup_created', createdAt, ...result }))
  } catch (error) {
    await Promise.allSettled([unlink(dump), unlink(manifest)])
    await rmdir(archive).catch(() => {})
    throw error
  }
}

async function verify(values) {
  if (!restoreNamePattern.test(values.database ?? '')) reject('The target database must be named sectalk_restore_*.')
  if (values.service) reject('Restore verification requires an isolated local target.')
  if (values.container && (values.port || values.user)) reject('Choose a container or an explicit loopback port and user.')
  if (values.container) await disposableContainer(values.container)
  else if (!/^\d{1,5}$/.test(values.port ?? '') || Number(values.port) < 1 || Number(values.port) > 65535 ||
      !namePattern.test(values.user ?? '')) reject('Provide the dedicated loopback database port and role.')
  const target = { container: values.container, database: values.database, port: values.port, user: values.user }

  const dump = join(values.archive, archiveName)
  const manifest = join(values.archive, manifestName)
  const [dumpStat, manifestStat, assertions] = await Promise.all([lstat(dump), lstat(manifest), lstat(values.assert)])
  if (!dumpStat.isFile() || !manifestStat.isFile() || !assertions.isFile() || manifestStat.size > 4096 || assertions.size === 0) {
    reject('Provide a complete backup directory and trusted SQL assertion file.')
  }
  const expected = JSON.parse(await readFile(manifest, 'utf8'))
  const snapshot = await digest(dump)
  if (expected.format !== 1 || expected.bytes !== snapshot.bytes || snapshot.sha256 !== expected.sha256) {
    reject('The archive did not match its integrity manifest.')
  }

  const verifyStarted = performance.now()
  const empty = await runTool(target, 'psql', ['--no-psqlrc', '--tuples-only', '--no-align', '--set=ON_ERROR_STOP=1',
    '--command=select not exists (select from pg_namespace where nspname not in (\'public\',\'information_schema\') and nspname !~ \'^pg_\') and not exists (select from pg_depend where refclassid=\'pg_namespace\'::regclass and refobjid=\'public\'::regnamespace and deptype=\'n\') and (select count(*) from pg_extension)=1;'])
  if (empty !== 't') reject('The restore database is not empty. Use a fresh database created from template0.')
  await runTool(target, 'pg_restore', ['--exit-on-error', '--single-transaction'], { input: createReadStream(dump) })
  await runTool(target, 'psql', ['--no-psqlrc', '--set=ON_ERROR_STOP=1',
    '--command=begin read only;', '--file=-', '--command=rollback;'], { input: createReadStream(values.assert) })
  console.log(JSON.stringify({ status: 'restore_verified', finishedAt: clock(),
    durationMs: Math.round(performance.now() - verifyStarted), ...snapshot }))
}

async function main() {
  const [operation, ...args] = process.argv.slice(2)
  if (operation !== 'backup' && operation !== 'verify') {
    reject('Use backup or verify. See docs/DISASTER_RECOVERY.md for the required arguments.')
  }
  const { values } = parseArgs({ args, options: {
    archive: { type: 'string' }, service: { type: 'string' }, container: { type: 'string' },
    database: { type: 'string' }, port: { type: 'string' }, user: { type: 'string' }, assert: { type: 'string' },
  } })
  if (!values.archive || (operation === 'verify' && !values.assert)) reject('Provide --archive and, for verification, --assert.')
  if (operation === 'backup' && (values.assert || values.port || values.user)) reject('Use only backup source options.')
  await (operation === 'backup' ? backup(values) : verify(values))
}

try {
  await main()
} catch (error) {
  // System exceptions can include private filesystem paths or invalid caller arguments.
  console.error(error && (error.code || error instanceof SyntaxError) ? 'The recovery job could not read or write its inputs.' : error.message)
  process.exitCode = 1
}
