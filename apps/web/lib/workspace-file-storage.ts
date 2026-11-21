import { createHash } from 'node:crypto'

export const workspaceFileBucket = 'sectalk-workspace-files'
export const workspaceFileMaximum = 4 * 1024 * 1024
export function workspaceFileReadOnlyMessage(reason: unknown) {
  if (reason === 'offboarding') return 'This workspace is read-only for offboarding.'
  if (reason === 'residency') return 'Workspace writes are paused for migration.'
  return 'This workspace is read-only until payment is restored.'
}
export const workspaceFilePath = (workspace: string, file: string) => workspace + '/' + file
export const roomFilePath = (workspace: string, room: string, file: string) => workspace + '/rooms/' + room + '/' + file
export const digestWorkspaceBytes = (bytes: Buffer) => createHash('sha256').update(bytes).digest('hex')
export const workspaceFileFingerprint = (workspace: string, hash: string) =>
  createHash('sha256').update('workspace-file:' + workspace + ':' + hash).digest('hex')
