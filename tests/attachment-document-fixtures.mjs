import { deflateSync } from 'node:zlib'
import { strToU8, zipSync } from 'fflate'

const relNamespace = 'http://schemas.openxmlformats.org/package/2006/relationships'
const relationship = 'http://schemas.openxmlformats.org/officeDocument/2006/relationships'
const officeFamilies = {
  word: ['word/document.xml', 'wordprocessingml.document', 'wordprocessingml', 'document'],
  excel: ['xl/workbook.xml', 'spreadsheetml.sheet', 'spreadsheetml', 'workbook'],
  powerpoint: ['ppt/presentation.xml', 'presentationml.presentation', 'presentationml', 'presentation'],
}

export function officePackage({ macro = false, external = false, extra = {}, badMain = false, family = 'word' } = {}) {
  const [main, mime, namespace, element] = officeFamilies[family]
  const type = macro ? `application/vnd.ms-${family}.${mime.split('.')[1]}.macroEnabled.main+xml`
    : `application/vnd.openxmlformats-officedocument.${mime}.main+xml`
  const data = {
    '[Content_Types].xml': `<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Override PartName="/${main}" ContentType="${type}"/></Types>`,
    '_rels/.rels': `<Relationships xmlns="${relNamespace}"><Relationship Id="r1" Type="${relationship}/officeDocument" Target="${main}"/></Relationships>`,
    [main]: badMain ? '<invalid/>' : `<${element} xmlns="http://schemas.openxmlformats.org/${namespace}/2006/main"/>`,
    ...extra,
  }
  const [folder, part] = main.split('/')
  if (macro) data[folder + '/vbaProject.bin'] = 'Harmless structural marker with no VBA'
  if (external) data[folder + '/_rels/' + part + '.rels'] =
    `<Relationships xmlns="${relNamespace}"><Relationship Id="r2" Type="${relationship}/hyperlink" TargetMode="External" Target="https://example.invalid/"/></Relationships>`
  return Buffer.from(zipSync(Object.fromEntries(Object.entries(data).map(([name, content]) => [name, strToU8(content)]))))
}

export function pdfWithCompressedLink({ scriptMarker = false } = {}) {
  const chunks = [Buffer.from('%PDF-1.5\n')]
  const offsets = []
  const length = () => chunks.reduce((total, chunk) => total + chunk.length, 0)
  function object(number, data, stream) {
    offsets[number] = length()
    chunks.push(Buffer.from(`${number} 0 obj\n${data}\n`))
    if (stream) chunks.push(Buffer.from('stream\n'), stream, Buffer.from('\nendstream\n'))
    chunks.push(Buffer.from('endobj\n'))
  }
  object(1, '<< /Type /Catalog /Pages 2 0 R >>')
  object(2, '<< /Type /Pages /Count 1 /Kids [3 0 R] >>')
  object(3, '<< /Type /Page /Parent 2 0 R /MediaBox [0 0 200 200] /Resources <<>> /Contents 4 0 R /Annots [5 0 R] >>')
  object(4, '<< /Length 0 >>', Buffer.alloc(0))
  const action = scriptMarker ? '/S /JavaScript' : '/S /URI /URI (https://example.invalid/)'
  const compressed = deflateSync(`5 0 << /Type /Annot /Subtype /Link /Rect [0 0 20 20] /A << ${action} >> >>`)
  object(6, `<< /Type /ObjStm /N 1 /First 4 /Filter /FlateDecode /Length ${compressed.length} >>`, compressed)
  offsets[7] = length()
  const xref = Buffer.alloc(8 * 7)
  xref.writeUInt16BE(65535, 5)
  for (let number = 1; number < 8; number++) {
    xref.writeUInt8(number === 5 ? 2 : 1, number * 7)
    xref.writeUInt32BE(number === 5 ? 6 : offsets[number], number * 7 + 1)
  }
  object(7, `<< /Type /XRef /Size 8 /W [1 4 2] /Root 1 0 R /Length ${xref.length} >>`, xref)
  chunks.push(Buffer.from(`startxref\n${offsets[7]}\n%%EOF\n`))
  return Buffer.concat(chunks)
}
