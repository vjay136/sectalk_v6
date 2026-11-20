import { PDFDocument, StandardFonts, rgb } from 'pdf-lib'

const labels = {
  harassment: 'Harassment or abuse', threat: 'Threat or stalking', scam: 'Scam or fraud', impersonation: 'Impersonation',
  spam: 'Spam or unwanted solicitation', sexual_content: 'Unwanted nudity or sexual content', other: 'Other concern',
} as const
export type ReportPeriod = 'daily' | 'weekly'
export type SecurityReport = {
  period: ReportPeriod
  period_start: string
  period_end: string
  rows: {category: keyof typeof labels; reports: number | null; actioned: number | null}[]
}

function safeReport(report: SecurityReport) {
  const validCount = (count: number | null) => count === null
    || (Number.isSafeInteger(count) && count >= 5 && count % 5 === 0)
  const date = /^\d{4}-\d{2}-\d{2}$/
  if ((report.period !== 'daily' && report.period !== 'weekly')
    || !date.test(report.period_start) || !date.test(report.period_end) || report.period_start >= report.period_end
    || !Array.isArray(report.rows) || report.rows.length !== Object.keys(labels).length
    || new Set(report.rows.map(row => row.category)).size !== report.rows.length
    || report.rows.some(row => !Object.hasOwn(labels, row.category)
      || !validCount(row.reports) || !validCount(row.actioned)
      || (row.actioned !== null && (row.reports === null || row.actioned > row.reports)))) {
    throw new Error('Invalid security report')
  }
  return report
}

export function securityReportCsv(input: SecurityReport) {
  const report = safeReport(input)
  const header = 'Period,UTC start,UTC end (exclusive),Category,Reports filed,Reports with staff action'
  const lines = report.rows.map(row => [
    report.period, report.period_start, report.period_end, labels[row.category], row.reports, row.actioned,
  ].join(','))
  return [header, ...lines].join('\r\n') + '\r\n'
}

export async function securityReportPdf(input: SecurityReport) {
  const report = safeReport(input)
  const document = await PDFDocument.create()
  document.setTitle('SecTalk security report')
  document.setAuthor('SecTalk')
  document.setSubject('Privacy-suppressed moderation aggregates')
  const page = document.addPage([612, 792])
  const regular = await document.embedFont(StandardFonts.Helvetica)
  const bold = await document.embedFont(StandardFonts.HelveticaBold)
  const ink = rgb(0.07, 0.15, 0.24)
  const muted = rgb(0.27, 0.34, 0.41)
  const accent = rgb(0.02, 0.39, 0.40)
  const line = rgb(0.83, 0.87, 0.90)
  const pale = rgb(0.94, 0.96, 0.97)
  const white = rgb(1, 1, 1)
  const margin = 48
  const width = 516

  page.drawRectangle({x: margin, y: 742, width, height: 3, color: accent})
  page.drawText('SECTALK', {x: margin, y: 714, size: 10, font: bold, color: accent})
  page.drawText('Security report', {x: margin, y: 674, size: 31, font: bold, color: ink})
  const period = report.period === 'daily' ? 'Daily report' : 'Weekly report'
  page.drawText(period + '  |  ' + report.period_start + ' to ' + report.period_end + ' UTC', {
    x: margin, y: 648, size: 12, font: regular, color: muted,
  })
  page.drawText('The end date is exclusive. Counts cover the last completed UTC period.', {
    x: margin, y: 622, size: 10, font: regular, color: muted,
  })

  const headings = ['Category', 'Reports filed', 'With staff action']
  const columns = [margin + 14, 308, 430]
  page.drawRectangle({x: margin, y: 560, width, height: 32, color: ink})
  headings.forEach((text, index) =>
    page.drawText(text, {x: columns[index], y: 571, size: 11, font: bold, color: white}))
  for (const [index, row] of report.rows.entries()) {
    const y = 530 - index * 31
    if (index % 2 === 0) page.drawRectangle({x: margin, y: y - 1, width, height: 31, color: pale})
    page.drawLine({start: {x: margin, y: y - 1}, end: {x: margin + width, y: y - 1}, color: line, thickness: 0.5})
    page.drawText(labels[row.category], {x: columns[0], y: y + 10, size: 11, font: regular, color: ink})
    for (const [column, value] of [row.reports, row.actioned].entries()) {
      page.drawText(value === null ? 'Below threshold' : value.toLocaleString('en-US'), {
        x: columns[column + 1], y: y + 10, size: 10, font: value === null ? regular : bold,
        color: value === null ? muted : ink,
      })
    }
  }

  page.drawRectangle({x: margin, y: 230, width, height: 79, borderColor: line, borderWidth: 0.8})
  page.drawText('How counts are reported', {x: margin + 14, y: 289, size: 11, font: bold, color: ink})
  for (const [index, text] of [
    'Each count requires five distinct reporters and five distinct reported accounts.',
    'Eligible counts are rounded down to the nearest five. Suppressed counts stay blank in CSV.',
    'Reports are allegations. Staff actions include warnings, suspensions, restrictions, and removals.',
  ].entries()) page.drawText(text, {x: margin + 14, y: 272 - index * 13, size: 9.5, font: regular, color: muted})
  page.drawLine({start: {x: margin, y: 66}, end: {x: margin + width, y: 66}, color: line, thickness: 0.75})
  page.drawText('SecTalk Safety center', {x: margin, y: 48, size: 9, font: regular, color: muted})
  page.drawText('1 / 1', {x: margin + width - 20, y: 48, size: 9, font: regular, color: muted})
  return document.save()
}
