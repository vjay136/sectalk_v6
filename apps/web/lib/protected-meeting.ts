type Agreement={host:string;roster:string[];keys:Record<string,string>}
type Identity={privateKey:CryptoKey;publicKey:string}
const domain='sectalk-protected-meeting/v1'
const encode=new TextEncoder()

function pack(bytes:Uint8Array) {
  return btoa(String.fromCharCode(...bytes)).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'')
}
function unpack(value:string) {
  return Uint8Array.from(atob(value.replace(/-/g,'+').replace(/_/g,'/').padEnd(Math.ceil(value.length/4)*4,'=')),
    letter=>letter.charCodeAt(0))
}
function context(meeting:string,agreement:Agreement) {
  if (agreement.roster.length<2 || agreement.roster.length>8 || !agreement.roster.includes(agreement.host) ||
    new Set(agreement.roster).size!==agreement.roster.length ||
    !agreement.roster.every(id=>/^[\w-]{87}$/.test(agreement.keys[id] ?? ''))) throw new Error('Protected roster unavailable')
  return encode.encode(JSON.stringify([domain,meeting,agreement.host,agreement.roster.map(id=>[id,agreement.keys[id]])]))
}

export async function meetingIdentity():Promise<Identity> {
  const pair=await crypto.subtle.generateKey({name:'ECDH',namedCurve:'P-256'},false,['deriveBits'])
  return {privateKey:pair.privateKey,publicKey:pack(new Uint8Array(await crypto.subtle.exportKey('raw',pair.publicKey)))}
}

async function wrapKey(identity:Identity,peer:string,recipient:string,transcript:Uint8Array<ArrayBuffer>,usage:'encrypt'|'decrypt') {
  const publicKey=await crypto.subtle.importKey('raw',unpack(peer),{name:'ECDH',namedCurve:'P-256'},false,[])
  const bytes=await crypto.subtle.deriveBits({name:'ECDH',public:publicKey},identity.privateKey,256)
  const shared=await crypto.subtle.importKey('raw',bytes,'HKDF',false,['deriveKey'])
  new Uint8Array(bytes).fill(0)
  return crypto.subtle.deriveKey({name:'HKDF',hash:'SHA-256',salt:await crypto.subtle.digest('SHA-256',transcript),
    info:encode.encode(domain+'/wrap/'+recipient)},shared,{name:'AES-GCM',length:256},false,[usage])
}

export async function wrapMeetingKey(meeting:string,agreement:Agreement,identity:Identity,group:ArrayBuffer) {
  const transcript=context(meeting,agreement)
  if (agreement.keys[agreement.host]!==identity.publicKey) throw new Error('Protected host key changed')
  return Object.fromEntries(await Promise.all(agreement.roster.filter(id=>id!==agreement.host).map(async id=>{
    const iv=crypto.getRandomValues(new Uint8Array(12))
    const key=await wrapKey(identity,agreement.keys[id],id,transcript,'encrypt')
    const sealed=await crypto.subtle.encrypt({name:'AES-GCM',iv,additionalData:transcript},key,group)
    const envelope=new Uint8Array(60)
    envelope.set(iv)
    envelope.set(new Uint8Array(sealed),iv.length)
    return [id,pack(envelope)]
  })))
}

export async function unwrapMeetingKey(meeting:string,agreement:Agreement,identity:Identity,actor:string,envelope:string) {
  const transcript=context(meeting,agreement)
  if (agreement.keys[actor]!==identity.publicKey || !/^[\w-]{80}$/.test(envelope)) throw new Error('Protected envelope unavailable')
  const key=await wrapKey(identity,agreement.keys[agreement.host],actor,transcript,'decrypt')
  const sealed=unpack(envelope)
  return crypto.subtle.decrypt({name:'AES-GCM',iv:sealed.subarray(0,12),additionalData:transcript},key,sealed.subarray(12))
}

export async function meetingCode(meeting:string,agreement:Agreement,group:ArrayBuffer) {
  const key=await crypto.subtle.importKey('raw',group,'HKDF',false,['deriveBits'])
  const salt=await crypto.subtle.digest('SHA-256',context(meeting,agreement))
  const bytes=await crypto.subtle.deriveBits({name:'HKDF',hash:'SHA-256',salt,info:encode.encode(domain+'/verification')},key,48)
  return [...new Uint8Array(bytes)].map(value=>value.toString(16).padStart(2,'0')).join('').toUpperCase().match(/.{4}/g)!.join(' ')
}
