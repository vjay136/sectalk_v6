import { createHash } from 'node:crypto'

export const workspaceFileBucket = 'sectalk-workspace-files'
export const workspaceFileMaximum = 4 * 1024 * 1024
export const workspaceFilePath = (workspace: string, file: string) => workspace + '/' + file
export const digestWorkspaceBytes = (bytes: Buffer) => createHash('sha256').update(bytes).digest('hex')
export const workspaceFileFingerprint = (workspace: string, hash: string) =>
  createHash('sha256').update('workspace-file:' + workspace + ':' + hash).digest('hex')
