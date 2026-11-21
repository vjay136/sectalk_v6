import { disclosureQueue } from '../../../../../../web/lib/disclosure-intake-server'

export const runtime = 'nodejs'

export function POST(request: Request) {
  return disclosureQueue(request)
}
