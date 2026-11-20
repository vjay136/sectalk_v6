import { createClient } from '@supabase/supabase-js'
import { draftMeetingSummary } from '../../../../lib/meeting-summary'

export const runtime = 'nodejs'

const identifier = /^[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$/i
const actions = new Set(['view', 'generate', 'policy', 'opt-in', 'withdraw'])
const headers = { 'Cache-Control': 'private, no-store', Vary: 'Authorization' }
const response = (status: number, error: string) => Response.json({ error }, { status, headers })

export async function POST(request: Request) {
  const token = request.headers.get('Authorization')?.match(/^Bearer (\S+)$/i)?.[1]
  if (!token) return response(401, 'Sign in to open the thread summary.')
  const { NEXT_PUBLIC_SUPABASE_URL: url, NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY: key, SECTALK_FILE_STORAGE_KEY: serviceKey } = process.env
  if (!url || !key || !serviceKey) return response(503, 'Thread summaries are unavailable.')
  const query = new URL(request.url).searchParams
  const room = query.get('room')
  const root = query.get('thread')
  const action = query.get('action')
  const enabled = query.get('enabled')
  if (!room || !identifier.test(room) || !root || !identifier.test(root) || !action || !actions.has(action) ||
    (action === 'policy' && enabled !== 'true' && enabled !== 'false')) {
    return response(400, 'Choose a valid thread summary action.')
  }

  try {
    const auth = { persistSession: false, autoRefreshToken: false }
    const actor = await createClient(url, key, { auth }).auth.getUser(token)
    if (actor.error || !actor.data.user) return response(401, 'Sign in to open the thread summary.')
    const user = actor.data.user.id
    const db = createClient(url, serviceKey, { auth })
    const command = async (operation: string) => {
      const result = await db.rpc('st_v6_room_thread_summary_command', {
        p_room: room, p_root: root, p_actor: user, p_action: operation,
        p_enabled: action === 'policy' ? enabled === 'true' : null,
      })
      if (result.error) throw result.error
      return result.data
    }
    const raw = await command(action === 'generate' ? 'source' : action)
    if (!raw) return response(403, 'Thread summary access is unavailable.')
    const { source, ...state } = raw
    if (action !== 'generate') return Response.json(state, { headers })
    if (typeof state.revision !== 'string' || !Array.isArray(source) || source.length === 0) {
      return response(409, 'There are no eligible posts to summarize yet.')
    }
    const draft = draftMeetingSummary(source, 'en')
    const current = await command('view')
    if (current?.revision !== state.revision) {
      return response(409, 'The eligible posts changed. Generate a new summary.')
    }
    return Response.json({ ...state, draft }, { headers })
  } catch {
    return response(503, 'Thread summaries are unavailable.')
  }
}
