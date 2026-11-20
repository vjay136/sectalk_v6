'use client'

import { useEffect, useState } from 'react'
import { categories, db } from '../lib/data'
import type { ReportPeriod, SecurityReport } from '../lib/security-report-export'
import { SectionTabs } from './section-tabs'
import styles from './threat-trends.module.css'

export function SecurityReports() {
  const [period, setPeriod] = useState<ReportPeriod>('daily')
  const [result, setResult] = useState<{period: ReportPeriod; report: SecurityReport | null} | null>(null)
  const [downloading, setDownloading] = useState(false)
  const [error, setError] = useState('')

  useEffect(() => {
    const request = new AbortController()
    void db!.rpc('st_v6_security_report', {p_period: period}).abortSignal(request.signal).then(({data, error}) => {
      if (!request.signal.aborted) setResult({period, report: error ? null : data as SecurityReport})
    })
    return () => request.abort()
  }, [period])

  async function download(format: 'csv' | 'pdf') {
    if (downloading) return
    setDownloading(true)
    setError('')
    try {
      let file: Blob
      if (format === 'pdf') {
        const [report, {securityReportPdf}] = await Promise.all([
          db!.rpc('st_v6_security_report', {p_period: period}),
          import('../lib/security-report-export'),
        ])
        if (report.error || !report.data) throw new Error()
        const bytes = new Uint8Array(await securityReportPdf(report.data as SecurityReport))
        file = new Blob([bytes], {type: 'application/octet-stream'})
      } else {
        const {data} = await db!.auth.getSession()
        if (!data.session) throw new Error()
        const query = new URLSearchParams({period, format})
        const response = await fetch('/api/security-reports/export?' + query, {
          headers: {Authorization: 'Bearer ' + data.session.access_token}, cache: 'no-store',
        })
        if (!response.ok) throw new Error()
        file = await response.blob()
      }
      const url = URL.createObjectURL(file)
      const link = document.createElement('a')
      link.href = url
      link.download = 'sectalk-security-report-' + period + '.' + format
      link.click()
      window.setTimeout(() => URL.revokeObjectURL(url), 1000)
    } catch { setError('Could not export this security report.') }
    finally { setDownloading(false) }
  }

  const current = result?.period === period ? result : null
  const report = current?.report
  return <section className="release-section" aria-label="Security reports">
    <h3>Security reports</h3>
    <p>View the last complete UTC day or week. Report counts describe allegations. Staff action counts reflect moderation decisions.</p>
    <SectionTabs label="Security report period" value={period} onChange={next => {setPeriod(next);setError('')}}
      options={[['daily', 'Daily'], ['weekly', 'Weekly']]}/>
    {!current && <p role="status">Loading security report…</p>}
    {current && !report && <p role="alert" className="error">Could not load this report. Verify your staff authenticator.</p>}
    {report && <>
      <div className="actions">
        <button type="button" className="secondary" disabled={downloading} onClick={() => void download('csv')}>Download CSV</button>
        <button type="button" className="secondary" disabled={downloading} onClick={() => void download('pdf')}>Download PDF</button>
      </div>
      <div className={styles.scroll}><table className={styles.table}>
        <caption>{report.period_start} to {report.period_end} UTC (end exclusive)</caption>
        <thead><tr><th scope="col">Category</th><th scope="col">Reports filed</th><th scope="col">With staff action</th></tr></thead>
        <tbody>{report.rows.map(row => <tr key={row.category}>
          <th scope="row">{categories[row.category]}</th>
          <td>{row.reports?.toLocaleString() ?? 'Below threshold'}</td>
          <td>{row.actioned?.toLocaleString() ?? 'Below threshold'}</td>
        </tr>)}</tbody>
      </table></div>
      <p className="muted">Each count requires at least five distinct reporters and five distinct reported accounts. Eligible counts are rounded down to the nearest five.</p>
    </>}
    {error && <p role="alert" className="error">{error}</p>}
  </section>
}
