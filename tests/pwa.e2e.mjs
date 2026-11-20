import assert from 'node:assert/strict'
import { mkdtemp, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { dirname, join, resolve } from 'node:path'

const origin=process.env.SECTALK_AUTH_TEST_APP||'http://127.0.0.1:3484'
assert.equal(new URL(origin).hostname,'127.0.0.1')
const { chromium }=await import(process.env.SECTALK_PLAYWRIGHT_MODULE||'playwright')
const temporary=resolve(tmpdir())
const profile=await mkdtemp(join(temporary,'sectalk-pwa-test-'))
let context
try{
  context=await chromium.launchPersistentContext(profile,{executablePath:process.env.SECTALK_TEST_BROWSER,viewport:{width:390,height:844}})
  const page=await context.newPage()
  await page.goto(origin)
  await page.getByRole('heading',{name:'Sign in to SecTalk'}).waitFor()
  assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth>innerWidth),false)
  const manifest=await page.$eval('link[rel=manifest]',element=>element.href)
  const response=await context.request.get(manifest)
  assert.equal(response.status(),200)
  const data=await response.json()
  assert.equal(data.display,'standalone')
  assert.equal(data.start_url,'/')
  for(const size of [192,512]){
    const icon=data.icons.find(icon=>icon.sizes===size+'x'+size)
    assert.ok(icon)
    const bytes=await (await context.request.get(new URL(icon.src,manifest).href)).body()
    assert.equal(bytes.readUInt32BE(16),size)
    assert.equal(bytes.readUInt32BE(20),size)
  }
  await page.waitForFunction(()=>Boolean(navigator.serviceWorker.controller))
  const session=await context.newCDPSession(page)
  const {installabilityErrors}=await session.send('Page.getInstallabilityErrors')
  assert.deepEqual(installabilityErrors,[])
  const cached=await page.evaluate(async()=>{
    const cache=await caches.open('sectalk-offline-v1')
    return (await cache.keys()).map(request=>new URL(request.url).pathname)
  })
  assert.deepEqual(cached,['/offline.html'])
  await context.setOffline(true)
  await page.goto(origin+'/status')
  await page.getByRole('heading',{name:'SecTalk is offline'}).waitFor()
  await context.setOffline(false)
  await page.getByRole('link',{name:'Try again'}).click()
  await page.getByRole('heading',{name:'Sign in to SecTalk'}).waitFor()
  console.log('Passed mobile viewport, manifest, icon sizes, private-cache exclusion, offline navigation and reconnect.')
}finally{
  await context?.close()
  assert.equal(dirname(resolve(profile)),temporary)
  await rm(profile,{recursive:true,force:true,maxRetries:3})
}
