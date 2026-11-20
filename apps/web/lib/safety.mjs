export function riskIndicators(text) {
  const flags = []
  const normalized = text.normalize('NFKC').replace(/[\u200B-\u200F\u2060\uFEFF]/g, '').replace(/\s+/g,' ')
  if (/\b(?:send|share|tell me|forward)\b.{0,45}\b(?:otp|one.time (?:code|password)|verification code|pin|password)\b/i.test(normalized)) {
    flags.push('This message may ask for an account code or credential.')
  }
  if (/\b(?:gift\s?cards?|wire transfer|crypto wallet|bitcoin|processing fee)\b/i.test(normalized)) {
    flags.push('This message mentions a payment method often used in scams.')
  }
  if (/\b(?:you are|you're|youre) (?:worthless|a disgusting|a filthy)\b|\b(?:i will|i'm going to|i am going to) (?:hurt|find and hurt|expose) you\b/i.test(normalized)) {
    flags.push('This message may contain targeted harassment or a threat.')
  }
  if (/\b(?:send|share|show|trade)\b.{0,32}\b(?:nudes?|naked photos?|explicit photos?|intimate pictures?|sex videos?)\b/i.test(normalized)) {
    flags.push('This message may request intimate content. You can report it.')
  }
  const urls = normalized.match(/https?:\/\/[^\s<>"']+/gi) ?? []
  if (/\b(?:limited.time offer|claim your prize|guaranteed returns|win big|instant cash)\b/i.test(normalized) &&
    (urls.length>0 || /\b(?:pay|subscribe|click|contact|forward)\b/i.test(normalized))) {
    flags.push('This message may be spam or a misleading promotion.')
  }
  for (const value of urls) {
    try {
      const url = new URL(value)
      if (url.protocol === 'http:' || url.username || url.password || url.hostname.includes('xn--') ||
        /^(?:bit\.ly|tinyurl\.com|t\.co|is\.gd)$/i.test(url.hostname) ||
        /^\d+\.\d+\.\d+\.\d+$/.test(url.hostname) || url.hostname.startsWith('[')) {
        flags.push('This link has characteristics worth checking before opening it.')
        break
      }
    } catch {
      // Treat malformed URLs as plain message text.
    }
  }
  return flags
}
