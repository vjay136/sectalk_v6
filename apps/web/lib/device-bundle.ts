export type DeviceBundle = {owner: string; device: string; signing: string; agreement: string}
export type DeviceChallenge = DeviceBundle & {challenge: string; session: string; nonce: string}
const encode = new TextEncoder()
export const deviceBundleContract = {
  key: /^[A-Za-z0-9_-]{87}$/,
  signature: /^[A-Za-z0-9_-]{86}$/,
  uuid: /^[a-f0-9]{8}(-[a-f0-9]{4}){3}-[a-f0-9]{12}$/,
}

export function deviceBundleTranscript(bundle: DeviceBundle) {
  return encode.encode(JSON.stringify(['sectalk-device-bundle-v1',bundle.owner,bundle.device,bundle.signing,bundle.agreement]))
}

export function deviceBindingTranscript(challenge: DeviceChallenge) {
  return encode.encode(JSON.stringify(['sectalk-device-session-v1',challenge.owner,challenge.device,challenge.session,
    challenge.challenge,challenge.nonce,challenge.signing,challenge.agreement]))
}

export function deviceRecoveryTranscript(challenge: DeviceChallenge, request: string) {
  return encode.encode(JSON.stringify(['sectalk-device-recovery-v1',challenge.owner,challenge.device,
    challenge.session,challenge.challenge,challenge.nonce,request]))
}

export function deviceCommandTranscript(owner: string,device: string,nonce: string,at: string) {
  return encode.encode(JSON.stringify(['sectalk-device-command-v1',owner,device,nonce,at]))
}

export function binaryToBase64url(data: ArrayBuffer) {
  return btoa(String.fromCharCode(...new Uint8Array(data))).replaceAll('+','-').replaceAll('/','_').replace(/=+$/,'')
}

export function base64urlToBinary(value: string) {
  return Uint8Array.from(atob(value.replaceAll('-','+').replaceAll('_','/')),letter=>letter.charCodeAt(0))
}
