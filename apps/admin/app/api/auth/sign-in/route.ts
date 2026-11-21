import { POST as signIn } from '../../../../../web/app/api/auth/sign-in/route'

export const runtime = 'nodejs'

export function POST(request: Request) {
  return signIn(request)
}
