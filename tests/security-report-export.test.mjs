import assert from 'node:assert/strict'
import test from 'node:test'
import { PDFDocument, PDFName } from 'pdf-lib'
import { securityReportCsv, securityReportPdf } from '../apps/web/lib/security-report-export.ts'

const report = {
  period: 'daily', period_start: '2026-11-19', period_end: '2026-11-20',
  rows: ['harassment','impersonation','other','scam','sexual_content','spam','threat'].map(category => ({
    category, reports: category === 'threat' ? 10 : null, actioned: category === 'threat' ? 5 : null,
  })),
}

test('CSV and PDF preserve suppressed cells and only accept validated aggregate rows', async () => {
  const csv = securityReportCsv(report)
  assert.match(csv, /daily,2026-11-19,2026-11-20,Threat or stalking,10,5\r\n/)
  assert.match(csv, /daily,2026-11-19,2026-11-20,Unwanted nudity or sexual content,,\r\n/)
  assert.equal(csv.split('\r\n').filter(Boolean).length, 8)
  const pdf = await PDFDocument.load(await securityReportPdf(report))
  assert.equal(pdf.getTitle(), 'SecTalk security report')
  assert.equal(pdf.getPageCount(), 1)
  assert.equal(pdf.catalog.get(PDFName.of('OpenAction')), undefined)
  assert.equal(pdf.getPage(0).node.Annots()?.size() ?? 0, 0)

  const malformed = {...report, rows: [{...report.rows[0], reports: 3}, ...report.rows.slice(1)]}
  assert.throws(() => securityReportCsv(malformed), /Invalid security report/)
  const formula = {...report, rows: [{...report.rows[0], category: '=malicious()'}, ...report.rows.slice(1)]}
  await assert.rejects(securityReportPdf(formula), /Invalid security report/)
})
