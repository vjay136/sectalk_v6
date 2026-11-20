type TranscriptLine = { line:string; speaker:string }
type Draft = { summary:string[]; actions:string[] }

const maxLines = 160
const maxSentence = 220
const blockedContent = /ignore\s+(?:the\s+)?(?:prior|previous|all|above)|system\s+prompt|developer\s+message|prompt\s+injection|pretend\s+to\s+be|\b(?:execute|run)\s+(?:this|the)\s+(?:command|script)|<\/?(?:system|assistant|developer|script)\b/i
const sensitivePatterns = [
  /[\w.+-]+@[\w.-]+\.[a-z]{2,}/gi,
  /\b(?:https?:\/\/|www\.)[^\s]+/gi,
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

export function draftMeetingSummary(source:unknown,language:string):Draft {
  if (!Array.isArray(source) || source.length>maxLines) throw new Error('Unexpected transcript shape')
  const rows:TranscriptLine[]=source.map(item=>{
    if (typeof item?.line!=='string' || !item.line.trim() || item.line.length>1000 ||
        typeof item.speaker!=='string' || item.speaker.length>160) throw new Error('Unexpected transcript line')
    return {line:item.line,speaker:item.speaker}
  })
  const speakers=[...new Set(rows.map(row=>row.speaker.normalize('NFKC').replace(/\s+/g,' ').trim()).filter(name=>name.length>=2))]
  const speakerPatterns=speakers.map(name=>new RegExp('(?<![\\p{L}\\p{N}])'+
    name.replace(/[.*+?^${}()|[\]\\]/g,'\\$&')+'(?![\\p{L}\\p{N}])','giu'))
  const summary:string[]=[]
  const actions:string[]=[]
  const seen=new Set<string>()
  for (const {line} of rows) {
    const sanitized=redact(line,speakerPatterns)
    if (!sanitized || sanitized.includes('[redacted]')) continue
    for (const sentence of sanitized.split(/(?<=[.!?।])\s+/u)) {
      if (sentence.length<12 || sentence.length>maxSentence || !/\p{L}/u.test(sentence)) continue
      const normalized=sentence.toLocaleLowerCase()
      if (seen.has(normalized)) continue
      seen.add(normalized)
      const action=actionPatterns[language]?.test(sentence)
      if (action && actions.length<6) actions.push(sentence)
      else if (!action && summary.length<6) summary.push(sentence)
    }
    if (summary.length===6 && actions.length===6) break
  }
  if ([summary,actions].some(items=>items.length>6 ||
      items.some(item=>typeof item!=='string' || !item.trim() || item.length>maxSentence))) {
    throw new Error('Unexpected summary draft shape')
  }
  return {summary,actions}
}
