import { db } from './data'
import { enrollCurrentDevice } from './device-identity'

export async function signInWithAppPassword(email:string,password:string) {
  const signed=await fetch('/api/auth/sign-in',{
    method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({email,password}),cache:'no-store',
  })
  if (!signed.ok) throw Object.assign(new Error('Sign-in failed'),{status:signed.status})
  const {access_token,refresh_token}=await signed.json()
  const result=await db!.auth.setSession({access_token,refresh_token})
  if (result.error) throw result.error
  return result.data
}

export async function verifyAccountCredential(secret: string, hasAuthenticator: boolean) {
  if (hasAuthenticator) {
    const factors=await db!.auth.mfa.listFactors()
    const factorId=factors.data?.totp.find(item=>item.status==='verified')?.id
    if (factors.error || !factorId) throw new Error('Authenticator unavailable')
    const result=await db!.auth.mfa.challengeAndVerify({factorId,code:secret.trim()})
    if (result.error) throw new Error('Authenticator verification failed')
    return
  }
  const account=await db!.auth.getUser()
  const email=account.data.user?.email
  if (account.error || !email) throw new Error('Account verification unavailable')
  const result=await signInWithAppPassword(email,secret)
  if (!result.user||result.user.id!==account.data.user.id) throw new Error('Account verification failed')
  const risk=await db!.rpc('st_v7_login_risk_status')
  if (risk.data==='email') await enrollCurrentDevice({existingOnly:true})
}
