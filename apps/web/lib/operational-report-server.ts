import { createClient } from '@supabase/supabase-js'
import type { notificationSMTPConfiguration } from './notification-email-server'

const columns = [
  ['operation', 'Operation'],
  ['requests', 'Requests'],
  ['client_errors', 'Client errors'],
  ['server_errors', 'Server errors'],
  ['throttled', 'Throttled'],
  ['unavailable', 'Unavailable'],
  ['peak_in_flight', 'Peak in flight'],
  ['p50_band', 'P50 latency band'],
  ['p95_band', 'P95 latency band'],
] as const
type Column = typeof columns[number][0]
type Row = {operation: string} & Record<Exclude<Column, 'operation'>, number | null>
export type OperationalReport = {cadence: 'daily' | 'weekly'; period_end: string; rows: Row[]}
export type OperationalReportJob = OperationalReport & {id: string; lease: string; email: string}

export function reportCsv(report: OperationalReport) {
  const fields = report.rows.map(row => columns.map(([field]) => {
    const value = row[field]
    if (field === 'operation') {
      if (typeof value !== 'string' || !/^[a-z_]+$/.test(value)) throw new Error('Invalid operation label')
      return value
    }
    if (value === null) return ''
    if (typeof value !== 'number' || !Number.isSafeInteger(value) || value < 0) throw new Error('Invalid aggregate value')
    return String(value)
  }).join(','))
  return [columns.map(([, label]) => label).join(','), ...fields].join('\r\n') + '\r\n'
}

export function reportFilename(report: OperationalReport) {
  return report.cadence === 'weekly' ? 'sectalk-weekly-operational-report.csv' : 'sectalk-daily-operational-report.csv'
}

export async function operationalReportViewer(request: Request) {
  const token = request.headers.get('Authorization')?.match(/^Bearer (\S+)$/i)?.[1]
  const url = process.env.NEXT_PUBLIC_SUPABASE_URL
  const key = process.env.NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY
  if (!token || !url || !key) return null
  const client = createClient(url, key, {
    auth: { persistSession: false, autoRefreshToken: false },
    global: { headers: { Authorization: 'Bearer ' + token } },
  })
  const user = await client.auth.getUser(token)
  return user.error || !user.data.user ? null : client
}

export async function sendOperationalReport(
  configuration: NonNullable<ReturnType<typeof notificationSMTPConfiguration>>, job: OperationalReportJob,
) {
  if (job.email.length > 254 || !/^[^\s@<>,;:"]+@[a-z0-9.-]+\.[a-z0-9-]+$/i.test(job.email)) return false
  const result = await configuration.transport.sendMail({
    from: { address: configuration.from, name: 'SecTalk by Eagle Security' },
    to: { address: job.email, name: '' },
    subject: job.cadence === 'weekly' ? 'Your SecTalk weekly operational report' : 'Your SecTalk daily operational report',
    messageId: '<' + job.id + '@' + new URL(configuration.origin).hostname + '>',
    text: 'Your scheduled SecTalk operations report is attached. It contains aggregate request counts and latency bands. '
      + 'Operations with fewer than ten requests are excluded.\n\nManage your schedule in the SecTalk Safety center.\n'
      + new URL('/', configuration.origin).href,
    attachments: [{ filename: reportFilename(job), content: reportCsv(job), contentType: 'text/csv; charset=utf-8' }],
  })
  return result.accepted.length === 1
}
