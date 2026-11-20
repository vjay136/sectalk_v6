import {createHash} from 'node:crypto'
import {readBoundedText} from './request-body'

const publicRangeOrigin='https://api.pwnedpasswords.com'
const loopback=new Set(['localhost','127.0.0.1','[::1]'])
const rangeEntry=/^([A-F0-9]{35}):([0-9]{1,12})$/

function rangeOrigin() {
  const fixture=process.env.SECTALK_TEST_PASSWORD_RANGE_ORIGIN
  if (!fixture || process.env.VERCEL==='1') return publicRangeOrigin
  const app=new URL(process.env.SECTALK_APP_URL??publicRangeOrigin)
  const provider=new URL(fixture)
  if (!loopback.has(app.hostname) || !loopback.has(provider.hostname) || provider.protocol!=='http:' ||
    provider.username || provider.password || provider.pathname!=='/' || provider.search || provider.hash) {
    throw new Error('Password range fixture requires a local app and provider.')
  }
  return provider.origin
}

export async function isBreachedPassword(password:string) {
  const digest=createHash('sha1').update(password,'utf8').digest('hex').toUpperCase()
  const prefix=digest.slice(0,5)
  const suffix=digest.slice(5)
  const response=await fetch(`${rangeOrigin()}/range/${prefix}`,{
    headers:{'Add-Padding':'true',Accept:'text/plain','User-Agent':'SecTalk Password Screening'},
    redirect:'error',cache:'no-store',signal:AbortSignal.timeout(3500),
  })
  if (response.status!==200) throw new Error('Password screening is unavailable.')
  const body=await readBoundedText(response,256*1024)
  if (!body) throw new Error('Password screening returned an empty range.')

  let found=false
  let reported=0
  for (const line of body.trimEnd().split(/\r?\n/)) {
    const entry=rangeEntry.exec(line)
    if (!entry) throw new Error('Password screening returned an invalid range.')
    if (Number(entry[2])===0) continue
    reported++
    if (entry[1]===suffix) found=true
  }
  if (reported===0) throw new Error('Password screening returned no range entries.')
  return found
}
