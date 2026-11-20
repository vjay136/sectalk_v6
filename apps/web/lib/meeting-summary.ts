type TranscriptLine = { line:string; speaker:string }
type Draft = { summary:string[]; actions:string[] }

const maxLines = 160
const maxSentence = 220
const maxItems = 6
const blockedContent = /ignore\s+(?:(?:the|all|any)\s+)?(?:prior|previous|above|instructions)|(?:^|\s)(?:system|assistant|developer|tool|function)\s*:|(?:system|developer)\s+(?:prompt|message|instruction)|prompt\s+injection|pretend\s+to\s+be|disregard.{0,50}(?:instructions|guidelines)|override.{0,50}(?:instructions|policy)|\b(?:execute|run|invoke|call)\s+(?:this|the|a)\s+(?:command|script|tool|function)|<\/?(?:system|assistant|developer|tool|script)\b|\[\/?(?:inst|im_start|im_end)\]|\|(?:im_start|im_end|eot_id)\|/i
const sensitivePatterns = [
  /[\p{L}\p{N}_.+%-]+\s*@\s*[\p{L}\p{N}.-]+\s*\.\s*[\p{L}]{2,}/giu,
  /\b(?:https?:\/\/|www\.)[^\s]+/gi,
  /\b[\p{L}\p{N}_.+%-]+\s*(?:\(at\)|\[at\]| at )\s*[\p{L}\p{N}.-]+\s*(?:\(dot\)|\[dot\]| dot )\s*\p{L}{2,}\b/giu,
  /-----\s*(?:BEGIN|END)\s+(?:(?:OPENSSH|ENCRYPTED|RSA|EC|DSA)\s+)?PRIVATE\s+KEY\s*-----/gi,
  /\b(?:xox[baprs]-|glpat-|npm_|sk_live_|rk_live_|AIza)[a-z0-9_-]{12,}\b/gi,
  /\b(?:\d{1,3}\.){3}\d{1,3}\b/g,
  /\b[\da-f]{8}(?:-[\da-f]{4}){3}-[\da-f]{12}\b/gi,
  /(?:\+?\d[\d().\s-]{6,}\d)/g,
  /\b(?:api[ _-]*key|secret|password|passphrase|token|private[ _-]*key|bearer|ssh\s+rsa|credit card|card number|bank account|routing number|social security|passport|ssn|date of birth|my address|home address|street address|patient|medical record)\b[^.!?\n]*/gi,
  /\b(?:sk|pk)-(?:[a-z0-9_-]{10,})\b|\b(?:AKIA|ASIA)[A-Z0-9]{16}\b|\bgh[pousr]_[a-z0-9]{15,}\b/gi,
  /\beyJ[\w-]+\.eyJ[\w-]+\.[\w-]+\b|\b[a-z0-9+/_=-]{30,}\b/gi,
  /\b\d{1,5}\s+(?:[\p{L}.-]+\s+){1,5}(?:street|st|avenue|ave|road|rd|boulevard|blvd|lane|ln|drive|dr)\b/giu,
  /\b(?:my name is|contact name|first name|last name|full name)\b[^.!?\n]*/gi,
]
const actionPatterns: Record<string,RegExp> = {
  en:/^(?:action item[: ]|(?:i|we) (?:will|should|need to|agreed to) (?!not\b))/i,
  es:/^(?:acción pendiente[: ]|(?:voy a|vamos a|debemos|tenemos que) )/i,
  fr:/^(?:action à suivre[: ]|(?:je vais|nous allons|nous devons) )/i,
  de:/^(?:aufgabe[: ]|(?:ich werde|wir werden|wir müssen|wir sollten) )/i,
  hi:/^(?:कार्य[: ]|(?:मैं|हम) .{3,100}(?:करूँगा|करूंगा|करेंगे|करना है))/u,
}

function redact(raw:string, speakerPatterns:RegExp[]) {
  const normalized=raw.normalize('NFKC').replace(/\p{Cf}/gu,'').replace(/\s+/g,' ').trim()
  if (blockedContent.test(normalized)) return ''
  return [...sensitivePatterns,...speakerPatterns].reduce((line,pattern)=>line.replace(pattern,'[redacted]'),normalized)
}

function prepareSource(source: unknown, language: string) {
  if (!Array.isArray(source) || source.length > maxLines) throw new Error('Unexpected transcript shape')
  const rows: TranscriptLine[] = source.map(item => {
    if (!item || typeof item.line !== 'string' || !item.line.trim() || item.line.length > 1000 ||
        typeof item.speaker !== 'string' || item.speaker.length > 160) throw new Error('Unexpected transcript line')
    return { line: item.line, speaker: item.speaker }
  })
  const speakers = [...new Set(rows.map(row => row.speaker.normalize('NFKC').replace(/\p{Cf}/gu,'')
    .replace(/\s+/g, ' ').trim()).filter(name => name.length >= 2))]
  const speakerPatterns = speakers.map(name => new RegExp('(?<![\\p{L}\\p{N}])' +
    name.replace(/[.*+?^${}()|[\]\\]/g, '\\$&') + '(?![\\p{L}\\p{N}])', 'giu'))
  const candidates: Draft = { summary: [], actions: [] }
  const seen = new Set<string>()
  const actionPattern = Object.hasOwn(actionPatterns, language) ? actionPatterns[language] : undefined
  for (const { line } of rows) {
    const sanitized = redact(line, speakerPatterns)
    if (!sanitized || sanitized.includes('[redacted]')) continue
    for (const sentence of sanitized.split(/(?<=[.!?।])\s+/u)) {
      if (sentence.length < 12 || sentence.length > maxSentence || !/\p{L}/u.test(sentence)) continue
      const normalized = sentence.toLowerCase()
      if (seen.has(normalized)) continue
      seen.add(normalized)
      candidates[actionPattern?.test(sentence) ? 'actions' : 'summary'].push(sentence)
    }
  }
  return candidates
}

function validateDraft(value: unknown, candidates: Draft): Draft {
  if (!value || typeof value !== 'object' || Object.keys(value).length !== 2 ||
      !Object.hasOwn(value, 'summary') || !Object.hasOwn(value, 'actions')) throw new Error('Unexpected summary draft shape')
  const draft = value as Record<'summary' | 'actions', unknown>
  const result: Draft = { summary: [], actions: [] }
  for (const field of ['summary', 'actions'] as const) {
    const items = draft[field]
    if (!Array.isArray(items) || items.length > maxItems) throw new Error('Unexpected summary draft shape')
    const allowed = new Set(candidates[field])
    for (const item of items) {
      if (typeof item !== 'string' || !allowed.delete(item)) throw new Error('Summary contains unsupported text')
      result[field].push(item)
    }
  }
  return result
}

export function draftMeetingSummary(source: unknown, language: string): Draft {
  const candidates = prepareSource(source, language)
  // This pure selector has no instruction parser, model, network, or action executor.
  return validateDraft({
    summary: candidates.summary.slice(0, maxItems),
    actions: candidates.actions.slice(0, maxItems),
  }, candidates)
}
