import { evaluateMessageRisk, isSuspiciousSafetyLink } from './safety.mjs'
import { classifyScamMessage } from './message-scam.mjs'

export function messageSafetyAction(text) {
  const risk = evaluateMessageRisk(text)
  const scam = classifyScamMessage(text)
  const warn = risk.score >= 60 || scam.some(item => item.confidence >= 0.65)
  const hold = risk.score >= 80 && risk.confidence >= 0.7
  const blur = !hold && risk.score >= 60 && risk.reasons.some(reason => reason.category === 'sexual_coercion')
  const defang = risk.reasons.some(reason => reason.category === 'suspicious_link')
  return { risk, scam, level: warn ? 'warning' : 'hint', hold, blur, defang, priority: hold }
}

export function defangSafetyLinks(text) {
  return text.replace(/https?:\/\/[^\s<>"']+/gi, value => isSuspiciousSafetyLink(value)
    ? value.replace(/^https?/i, scheme => scheme.length === 4 ? 'hxxp' : 'hxxps')
      .replace(':', '[:]') .replaceAll('.', '[.]')
    : value)
}
