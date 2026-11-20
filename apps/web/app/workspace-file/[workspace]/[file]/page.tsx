import { notFound } from 'next/navigation'
import { WorkspaceFileDetails } from '../../../../components/workspace-file-details'
import { validFileId } from '../../../../lib/file-download-ticket'

export default async function WorkspaceFilePage({ params }: { params: Promise<{ workspace: string; file: string }> }) {
  const { workspace, file } = await params
  if (!validFileId(workspace) || !validFileId(file)) notFound()
  return <main className="content-page">
    <h1>Workspace file</h1>
    <p><a href="/#workspaces">Open SecTalk</a></p>
    <WorkspaceFileDetails workspace={workspace} file={file}/>
  </main>
}
