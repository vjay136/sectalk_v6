const maximumAttempts=250000
const pattern=/^[a-f0-9]{64}$/

export async function solveSignupProof(challenge:string,signal:AbortSignal) {
  if (!pattern.test(challenge)) throw new Error('Invalid signup challenge')
  const encoder=new TextEncoder()
  for (let nonce=0;nonce<maximumAttempts;nonce++) {
    signal.throwIfAborted()
    const digest=new Uint8Array(await crypto.subtle.digest('SHA-256',encoder.encode('sectalk-signup-v1:'+challenge+':'+nonce)))
    if (digest[0]===0&&digest[1]<4) return nonce
  }
  throw new Error('Signup challenge expired')
}
