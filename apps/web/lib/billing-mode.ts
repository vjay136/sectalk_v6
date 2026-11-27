export function billingMode() {
  const mode = process.env.SECTALK_BILLING_MODE
  if (mode === 'free' || mode === 'paid') return mode
  return process.env.VERCEL === '1' ? 'free' : 'paid'
}

export function billingPausedResponse() {
  return Response.json({ error: 'SecTalk is free for everyone. Paid billing is paused.' }, {
    status: 409,
    headers: { 'Cache-Control': 'no-store' },
  })
}
