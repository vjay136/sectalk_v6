export const messageRiskVersion = 'message-rules-1'

export const threatTaxonomy = Object.freeze({
  phishing: 'Phishing',
  credential_harvesting: 'Credential harvesting',
  romance_scam: 'Romance scam',
  investment_scam: 'Investment scam',
  job_scam: 'Job scam',
  delivery_scam: 'Delivery scam',
  tech_support_scam: 'Tech support scam',
  prize_scam: 'Lottery or prize scam',
  payment_fraud: 'Payment fraud',
  impersonation: 'Impersonation or business email compromise',
  suspicious_link: 'Suspicious link',
  malware_link: 'Malware link',
  malicious_file: 'Malicious file',
  social_engineering: 'Social engineering',
  harassment: 'Harassment or abuse',
  threat: 'Threat of harm',
  sexual_coercion: 'Unwanted intimate-content request',
  self_harm: 'Self-harm concern',
  data_exfiltration: 'Data loss or exfiltration',
  spam: 'Spam or mass messaging',
  account_takeover: 'Account takeover',
})

/** @typedef {keyof typeof threatTaxonomy} ThreatCategory */

/**
 * @param {number} value
 * @returns {'info'|'low'|'medium'|'high'|'critical'}
 */
export function threatSeverity(value) {
  if (value >= 90) return 'critical'
  if (value >= 80) return 'high'
  if (value >= 60) return 'medium'
  if (value >= 30) return 'low'
  return 'info'
}

/** @type {ReadonlyArray<{category: ThreatCategory, check: RegExp, score: number, confidence: number, reason: string}>} */
const textRules = [
  {
    category: 'credential_harvesting',
    check: /\b(?:send|share|tell me|forward)\b.{0,45}\b(?:otp|one.time (?:code|password)|verification code|pin|password)\b/i,
    score: 68, confidence: 0.82, reason: 'This message may ask for an account code or credential.',
  },
  {
    category: 'payment_fraud',
    check: /\b(?:gift\s?cards?|wire transfer|crypto wallet|bitcoin|processing fee)\b/i,
    score: 34, confidence: 0.4, reason: 'This message mentions a payment method often used in scams.',
  },
  {
    category: 'harassment',
    check: /\b(?:you are|you're|youre) (?:worthless|a disgusting|a filthy)\b/i,
    score: 61, confidence: 0.66, reason: 'This message may contain targeted harassment.',
  },
  {
    category: 'threat',
    check: /\b(?:i will|i'm going to|i am going to) (?:hurt|find and hurt|expose) you\b/i,
    score: 82, confidence: 0.72, reason: 'This message may contain targeted harassment or a threat.',
  },
  {
    category: 'sexual_coercion',
    check: /\b(?:send|share|show|trade)\b.{0,32}\b(?:nudes?|naked photos?|explicit photos?|intimate pictures?|sex videos?)\b/i,
    score: 62, confidence: 0.72, reason: 'This message may request intimate content. You can report it.',
  },
]

/** @param {string} raw */
function suspiciousLink(raw) {
  try {
    const url = new URL(raw)
    return url.protocol === 'http:' || !!url.username || !!url.password || url.hostname.includes('xn--') ||
      /^(?:bit\.ly|tinyurl\.com|t\.co|is\.gd)$/i.test(url.hostname) ||
      /^\d+\.\d+\.\d+\.\d+$/.test(url.hostname) || url.hostname.startsWith('[')
  } catch {
    return false
  }
}

/**
 * On-device evidence only. Confidence expresses rule strength, not the
 * probability that the sender intended harm. The result proposes no action.
 * @param {string} text
 */
export function evaluateMessageRisk(text) {
  const normalized = text.slice(0, 16000).normalize('NFKC').replace(/[\u200B-\u200F\u2060\uFEFF]/g, '')
    .replace(/[\u2018\u2019]/g, "'").replace(/\s+/g, ' ')
  const urls = normalized.match(/https?:\/\/[^\s<>"']+/gi) ?? []
  /** @type {Array<{category: ThreatCategory, score: number, confidence: number, reason: string}>} */
  const matches = textRules.filter(rule => rule.check.test(normalized))
  if (/\b(?:limited.time offer|claim your prize|guaranteed returns|win big|instant cash)\b/i.test(normalized) &&
    (urls.length > 0 || /\b(?:pay|subscribe|click|contact|forward)\b/i.test(normalized))) {
    matches.push({
      category: 'spam', score: 46, confidence: 0.56,
      reason: 'This message may be spam or a misleading promotion.',
    })
  }
  if (urls.some(suspiciousLink)) {
    matches.push({
      category: 'suspicious_link', score: 32, confidence: 0.46,
      reason: 'This link has characteristics worth checking before opening it.',
    })
  }
  const ranked = [...matches].sort((first, second) => second.score - first.score || second.confidence - first.confidence)
  const strongest = ranked[0]
  // Weaker evidence may corroborate a signal. It cannot turn weak signals
  // into high-severity findings or turn these local checks into a verdict.
  const corroborating = ranked.filter(signal => signal !== strongest && signal.confidence >= 0.4).length
  const cap = strongest?.score >= 80 ? 89 : strongest?.score >= 60 ? 79 : 59
  const score = strongest ? Math.min(cap, strongest.score + Math.min(10, 4 * corroborating)) : 0
  return {
    score,
    confidence: strongest?.confidence ?? 0,
    severity: threatSeverity(score),
    modelVersion: messageRiskVersion,
    reasons: matches.map(({ category, reason }) => ({ category, reason })),
  }
}

/** @param {string} text */
export function riskIndicators(text) {
  return evaluateMessageRisk(text).reasons.map(({ reason }) => reason)
}
