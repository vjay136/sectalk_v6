export type InvitationTemplate = { subject: string; body: string }
export const defaultInvitationCopy: InvitationTemplate = {
  subject: 'Your SecTalk workspace invitation',
  body: 'A SecTalk workspace administrator invited you to join. Open this link and sign in with the invited email.',
}

export function renderWorkspaceInvitation(copy: InvitationTemplate | null, organization: string, link: string, expiry: Date) {
  const workspaceName = organization.replace(/[\p{Cc}\u202a-\u202e\u2066-\u2069]/gu, ' ').trim()
  const fill = (value: string) => value.replaceAll('{{organization}}', () => workspaceName)
  const template = copy ?? defaultInvitationCopy
  return {
    subject: fill(template.subject),
    text: [fill(template.body), '', link, '', 'This link can be used once and expires on ' + expiry.toUTCString() + '.'].join('\n'),
  }
}
