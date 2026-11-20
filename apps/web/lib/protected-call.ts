import type { Call } from './data'

const domain='sectalk-protected-direct-call/v1'
const encode=new TextEncoder()
const maxAttempts=24

function codec(kind:'audio'|'video') {
  const target=kind==='audio'?'audio/opus':'video/vp8'
  return RTCRtpReceiver.getCapabilities(kind)?.codecs.filter(item=>item.mimeType.toLowerCase()===target) ?? []
}

export function protectedCallSupported(video:boolean) {
  return window.isSecureContext && Boolean(crypto.subtle) && typeof Worker!=='undefined' &&
    typeof RTCRtpScriptTransform!=='undefined' && typeof RTCRtpTransceiver!=='undefined' &&
    typeof RTCRtpReceiver!=='undefined' && typeof RTCRtpReceiver.getCapabilities==='function' &&
    typeof RTCRtpTransceiver.prototype.setCodecPreferences==='function' && codec('audio').length>0 &&
    (!video || codec('video').length>0)
}

function publicString(bytes:ArrayBuffer) {
  return btoa(String.fromCharCode(...new Uint8Array(bytes))).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'')
}

export async function protectedCallKeys(call:Call,user:string,publish:(publicKey:string)=>Promise<string|null>,disposed:()=>boolean) {
  if (call.media_protection!==1 || !protectedCallSupported(call.video)) throw new Error('Protected calls are unsupported')
  const pair=await crypto.subtle.generateKey({name:'ECDH',namedCurve:'P-256'},false,['deriveBits'])
  const own=publicString(await crypto.subtle.exportKey('raw',pair.publicKey))
  let other:string|null=null
  for (let attempt=0; !disposed() && !other && attempt<maxAttempts; attempt++) {
    other=await publish(own)
    if (!other) await new Promise(resolve=>window.setTimeout(resolve,500))
  }
  if (disposed() || !other || other===own || !/^[\w-]{87}$/.test(other)) throw new Error('Protected call key unavailable')
  const otherBytes=Uint8Array.from(atob(other.replace(/-/g,'+').replace(/_/g,'/')+'='),letter=>letter.charCodeAt(0))
  const otherKey=await crypto.subtle.importKey('raw',otherBytes,{name:'ECDH',namedCurve:'P-256'},false,[])
  const shared=await crypto.subtle.deriveBits({name:'ECDH',public:otherKey},pair.privateKey,256)
  const secret=await crypto.subtle.importKey('raw',shared,'HKDF',false,['deriveBits','deriveKey'])
  new Uint8Array(shared).fill(0)
  const caller=user===call.caller
  const transcript=JSON.stringify([domain,call.id,call.caller,call.callee,call.video,caller?own:other,caller?other:own])
  const salt=await crypto.subtle.digest('SHA-256',encode.encode(transcript))
  const params=(usage:string)=>({name:'HKDF',hash:'SHA-256',salt,info:encode.encode(domain+'/'+usage)})
  const [send,receive,verification]=await Promise.all([
    crypto.subtle.deriveKey(params(caller?'caller':'callee'),secret,{name:'AES-GCM',length:256},false,['encrypt']),
    crypto.subtle.deriveKey(params(caller?'callee':'caller'),secret,{name:'AES-GCM',length:256},false,['decrypt']),
    crypto.subtle.deriveBits(params('verification'),secret,48),
  ])
  const code=[...new Uint8Array(verification)].map(byte=>byte.toString(16).padStart(2,'0')).join('').toUpperCase().match(/.{4}/g)!.join(' ')
  return {send,receive,code}
}

export function protectedTransports(
  peer:RTCPeerConnection,source:MediaStream,keys:{send:CryptoKey;receive:CryptoKey},
  decoded:(kind:string)=>void,failed:()=>void,
) {
  const worker=new Worker('/protected-call-frames.js')
  worker.onmessage=event=>{
    if (event.data?.type==='decoded') decoded(event.data.kind)
    if (event.data?.type==='error') failed()
  }
  worker.onerror=failed
  const receivers=new Set<RTCRtpReceiver>()
  try {
    for (const track of [...source.getAudioTracks(),...source.getVideoTracks()]) {
      const kind=track.kind==='audio'?'audio':'video'
      const sender=peer.addTrack(track,source)
      const transport=peer.getTransceivers().find(item=>item.sender===sender)
      if (!transport) throw new Error('Protected media transport unavailable')
      transport.setCodecPreferences(codec(kind))
      transport.sender.transform=new RTCRtpScriptTransform(worker,{op:'encrypt',kind,key:keys.send})
      transport.receiver.transform=new RTCRtpScriptTransform(worker,{op:'decrypt',kind,key:keys.receive})
      receivers.add(transport.receiver)
    }
    return {receivers,close:()=>worker.terminate()}
  } catch(error) {
    worker.terminate()
    throw error
  }
}

export function protectedDescription(description:RTCSessionDescriptionInit,video:boolean) {
  const media=[...description.sdp?.matchAll(/^m=([^\r\n]+)/gm) ?? []].map(match=>match[1].split(' ')[0])
  if (media.length!==(video?2:1) || media[0]!=='audio' || (video && media[1]!=='video')) return false
  const codecs=[...description.sdp?.matchAll(/^a=rtpmap:\d+ ([^/\r\n]+)/gm) ?? []].map(match=>match[1].toLowerCase())
  return codecs.includes('opus') && (!video || codecs.includes('vp8')) &&
    codecs.every(item=>item==='opus' || (video && item==='vp8'))
}
