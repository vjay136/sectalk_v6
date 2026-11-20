export type AttachmentInspectionReason = 'document_macro_marker' | 'script_marker' | 'embedded_document_marker' | 'embedded_link_marker' | 'suspicious_link_format'

const labels: Record<AttachmentInspectionReason, string> = {
  document_macro_marker: 'Macro marker',
  script_marker: 'Script or automatic action marker',
  embedded_document_marker: 'Embedded file or form marker',
  embedded_link_marker: 'External or embedded link marker',
  suspicious_link_format: 'Link with user information or an internationalized domain',
}

export function attachmentInspectionLabel(reason: string | null) {
  return reason && Object.hasOwn(labels, reason) ? labels[reason as AttachmentInspectionReason] : null
}

export function validAttachmentInspectionReason(reason: unknown): reason is AttachmentInspectionReason {
  return typeof reason === 'string' && Object.hasOwn(labels, reason)
}

export function inspectAttachment(filename: string, bytes: Buffer): AttachmentInspectionReason | null {
  if (bytes.length > 4 * 1024 * 1024 || !/\.(pdf|txt)$/i.test(filename)) return null
  const source = bytes.toString('latin1')
  if (/\.pdf$/i.test(filename)) {
    const names = source.replace(/#([0-9a-f]{2})/gi, (_, hex: string) => String.fromCharCode(Number.parseInt(hex, 16)))
    if (/\/(?:JavaScript|JS|Launch|OpenAction|AA)(?=[\x00\s()<>\[\]{}\/%]|$)/.test(names)) return 'script_marker'
    if (/\/(?:EmbeddedFile|EmbeddedFiles|RichMedia|XFA)(?=[\x00\s()<>\[\]{}\/%]|$)/.test(names)) return 'embedded_document_marker'
    if (/\/URI(?=[\x00\s()<>\[\]{}\/%]|$)/.test(names)) return 'embedded_link_marker'
    return null
  }
  if (/\b(?:vbaProject\.bin|sub[ \t]+(?:AutoOpen|Document_Open)[ \t]*\()/i.test(source)) return 'document_macro_marker'
  if (/<script(?=[\s/>])|\bjavascript:/i.test(source)) return 'script_marker'
  let checked = 0
  for (const [origin, authority] of source.matchAll(/https?:\/\/([^\s<>"'`/?#]{1,512})/gi)) {
    if (!authority.includes('@') && !/(?:^|\.)xn--/i.test(authority)) continue
    if (checked++ === 128) break
    try {
      const url = new URL(origin)
      if (url.username || url.password || /(?:^|\.)xn--/i.test(url.hostname)) return 'suspicious_link_format'
    } catch {
      // Ignore malformed snippets without trying to resolve them.
    }
  }
  return null
}
