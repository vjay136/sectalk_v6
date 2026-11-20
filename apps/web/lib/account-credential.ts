import { db } from './data'

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
  const result=await db!.auth.signInWithPassword({email,password:secret})
  if (result.error || result.data.user.id!==account.data.user.id) throw new Error('Account verification failed')
}
