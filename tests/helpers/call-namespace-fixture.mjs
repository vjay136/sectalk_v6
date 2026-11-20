// Run with "start" or "stop" on a Docker Desktop host. Start the app and auth separately.
import { spawn, execFileSync } from 'node:child_process'
import { globSync } from 'node:fs'
import { createConnection, createServer } from 'node:net'
import { fileURLToPath } from 'node:url'

const prefix = 'sectalk-v6-direct-'
const networks = [['a','172.29.241'],['b','172.29.242']]
const containers = ['browser-a','browser-b','gateway','turn']
const browserImage = 'mcr.microsoft.com/playwright:v1.64.1-noble'
const action = process.argv[2]

function docker(...args) {
  execFileSync('docker',args,{stdio:'inherit'})
}

function start() {
  const mount = 'type=bind,source='+fileURLToPath(import.meta.url)+',target=/fixture.mjs,readonly'
  for (const [side,subnet] of networks) docker('network','create','--internal','--subnet',subnet+'.0/24',prefix+side)
  docker('run','-d','--name',prefix+'turn','--network',prefix+'a','--ip','172.29.241.10','--network-alias','call-turn',
    'coturn/coturn:4.18.0-r0','-n','--listening-ip=0.0.0.0','--relay-ip=172.29.241.10','--realm=call-turn',
    '--use-auth-secret','--static-auth-secret=direct-namespace-local-fixture','--no-tls','--min-port=49185','--max-port=49215',
    '--relay-threads=1','--user-quota=4','--total-quota=12','--denied-peer-ip=0.0.0.0-255.255.255.255',
    '--allowed-peer-ip=172.29.241.10','--no-multicast-peers','--no-cli','--cli-password=fixture-local-only','--log-file=stdout')
  docker('network','connect','--ip','172.29.242.10','--alias','call-turn',prefix+'b',prefix+'turn')
  docker('restart',prefix+'turn')
  docker('run','-d','--name',prefix+'gateway','--network','bridge','-p','127.0.0.1:3493:3493/tcp',
    '-p','127.0.0.1:3494:3494/tcp','--mount',mount,'node:24-alpine','node','/fixture.mjs','gateway')
  for (const [side,subnet] of networks) {
    docker('network','connect','--ip',subnet+'.11','--alias','call-gateway',prefix+side,prefix+'gateway')
    docker('run','-d','--name',prefix+'browser-'+side,'--network',prefix+side,'--ip',subnet+'.20',
      '--shm-size=512m','--mount',mount,browserImage,'node','/fixture.mjs',subnet+'.20')
  }
}

function stop() {
  docker('rm','-f',...containers.map(name=>prefix+name))
  docker('network','rm',...networks.map(([side])=>prefix+side))
}

function forward(address, port, host, target) {
  createServer(client => {
    const upstream = createConnection({ host, port: target })
    client.on('error', () => upstream.destroy())
    upstream.on('error', () => client.destroy())
    client.pipe(upstream).pipe(client)
  }).listen(port, address)
}

if (action === 'start') {
  start()
} else if (action === 'stop') {
  stop()
} else if (action === 'gateway') {
  forward('0.0.0.0', 3492, 'host.docker.internal', 3492)
  forward('0.0.0.0', 55321, 'host.docker.internal', 55321)
  forward('0.0.0.0', 3493, '172.29.241.20', 9222)
  forward('0.0.0.0', 3494, '172.29.242.20', 9222)
} else if (networks.some(([,subnet])=>action===subnet+'.20')) {
  forward('127.0.0.1', 3492, 'call-gateway', 3492)
  forward('127.0.0.1', 55321, 'call-gateway', 55321)
  // Chromium keeps DevTools on loopback in headless mode. Expose it only on the private interface.
  forward(action, 9222, '127.0.0.1', 9222)
  const [chrome] = globSync('/ms-playwright/chromium-[0-9]*/chrome-linux*/chrome')
  const browser = spawn(chrome, [
    '--headless', '--no-sandbox', '--no-first-run', '--disable-background-networking',
    '--remote-debugging-port=9222', '--user-data-dir=/tmp/call-fixture-chromium',
    '--use-fake-device-for-media-stream', '--use-fake-ui-for-media-stream', 'about:blank',
  ], { stdio: 'ignore' })
  browser.once('exit', code => process.exit(code ?? 1))
} else {
  throw new Error('Use start or stop to manage the local fixture.')
}
