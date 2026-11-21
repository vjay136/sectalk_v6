import { confirmationRedirect } from './auth-confirmation-origin.mjs'

export function hostedSignup(env = process.env) {
  return env.VERCEL === '1' && env.VERCEL_ENV !== 'development'
}

export function signupConfiguration(requestUrl, env = process.env) {
  const project = env.NEXT_PUBLIC_SUPABASE_URL?.trim()
  const upstream = env.SECTALK_AUTH_SIGNUP_UPSTREAM?.trim() || project
  const key = env.NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY?.trim()
  const serviceKey = env.SECTALK_SIGNUP_ADMISSION_SERVICE_KEY?.trim() || env.SECTALK_AUTH_RISK_SERVICE_KEY?.trim()
  const redirect = confirmationRedirect(env.SECTALK_APP_URL, requestUrl, hostedSignup(env))
  if (!project || !upstream || !key || !serviceKey || serviceKey === key ||
    serviceKey.startsWith('sb_publishable_') || !redirect) return null
  return {project, upstream, key, serviceKey, redirect}
}
