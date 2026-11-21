const uuid = '[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}'
const shape = new RegExp(`^(${uuid})(?:\.(${uuid}))?$`)

export const meetingBindingAttribute = 'sectalk.media.binding'

export function meetingMediaIdentity(actor: string, binding: string) {
  return `${actor}.${binding}`
}

export function parseMeetingMediaIdentity(identity: string) {
  const match = shape.exec(identity)
  return match ? { actor: match[1], binding: match[2] ?? null } : null
}
