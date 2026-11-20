'use client'

import { useEffect, useState } from 'react'
import { db } from '../lib/data'

type Indicators = { score: number; peakMinuteSend: number; peakHourInvites: number; reviewedFlagWeight: number; sharedApprovedBrowser: boolean }

export function CaseBehaviorPanel({ report }: { report: string }) {
  const [data, setData] = useState<Indicators>()
  const [error, setError] = useState(false)
  useEffect(() => {
    const request = new AbortController()
    void db!.rpc('st_v7_case_sender_behavior', { p_report: report }).abortSignal(request.signal).then(result => {
      if (request.signal.aborted) return
      if (result.error) setError(true)
      else if (result.data) setData(result.data as Indicators)
    })
    return () => request.abort()
  }, [report])

  if (!data && !error) return null
  return <section aria-label="Sender behavior advisory">
    <h3>Sender behavior advisory</h3>
    {error && <p role="alert">Sender behavior could not be verified.</p>}
    {data && <>
      <p>Behavior score {data.score} of 100. Review these indicators alongside the case evidence.</p>
      <dl>
        <dt>Most managed sends in one minute, last 72 hours</dt><dd>{data.peakMinuteSend === 60 ? '60+' : data.peakMinuteSend}</dd>
        <dt>Most contact and workspace invitations in one hour, last 72 hours</dt><dd>{data.peakHourInvites === 24 ? '24+' : data.peakHourInvites}</dd>
        <dt>Reviewed finding weight, last 90 days</dt><dd>{data.reviewedFlagWeight} of 40</dd>
        <dt>New account with an opted-in approved browser match</dt><dd>{data.sharedApprovedBrowser ? 'Match present' : 'No qualifying match'}</dd>
      </dl>
      <p>Recent findings count most. A browser match can occur on a shared browser.</p>
    </>}
  </section>
}
