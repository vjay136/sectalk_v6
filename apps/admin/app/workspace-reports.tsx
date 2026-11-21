'use client'

import { useState } from 'react'
import { ChannelReportQueue } from '../../web/components/channel-reports'
import { RoomReportQueue } from '../../web/components/room-reports'
import { SectionTabs } from '../../web/components/section-tabs'

type Scope = 'platform' | 'workspace'
type ReportType = 'rooms' | 'channels'

export function WorkspaceReports({platform, workspace}: {platform: boolean; workspace: boolean}) {
  const [scope, setScope] = useState<Scope>(workspace ? 'workspace' : 'platform')
  const [reportType, setReportType] = useState<ReportType>('rooms')
  const selected = platform && workspace ? scope : workspace ? 'workspace' : 'platform'

  return <section aria-label="Room and channel reports">
    <SectionTabs label="Report review scope" value={selected} onChange={setScope} options={[
      ...(workspace ? [['workspace', 'Workspace'] as const] : []),
      ...(platform ? [['platform', 'Platform Safety'] as const] : []),
    ]}/>
    <SectionTabs label="Report types" value={reportType} onChange={setReportType}
      options={ [['rooms','Room reports'],['channels','Channel reports']] }/>
    {reportType === 'rooms' ? <RoomReportQueue key={selected} scope={selected}/> :
      <ChannelReportQueue key={selected} scope={selected}/>}
  </section>
}
