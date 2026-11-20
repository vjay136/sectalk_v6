export function previewPdf(width = 600, height = 300) {
  const paint = '0.75 0.15 0.25 rg\n20 20 150 150 re f\n'
  const objects = [
    '<< /Type /Catalog /Pages 2 0 R >>',
    '<< /Type /Pages /Kids [3 0 R] /Count 1 >>',
    `<< /Type /Page /Parent 2 0 R /MediaBox [0 0 ${width} ${height}] /Resources << >> /Contents 4 0 R >>`,
    `<< /Length ${paint.length} >>\nstream\n${paint}endstream`,
  ]
  let result = '%PDF-1.4\n'
  const offsets = objects.map((object, index) => {
    const offset = result.length
    result += `${index + 1} 0 obj\n${object}\nendobj\n`
    return offset
  })
  const xref = result.length
  result += 'xref\n0 5\n0000000000 65535 f \n'
  result += offsets.map(offset => String(offset).padStart(10, '0') + ' 00000 n \n').join('')
  result += `trailer\n<< /Size 5 /Root 1 0 R >>\nstartxref\n${xref}\n%%EOF\n`
  return Buffer.from(result, 'ascii')
}
