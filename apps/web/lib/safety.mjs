export function riskIndicators(text) {
  const flags = []
  if (/\b(?:send|share|tell me|forward)\b.{0,45}\b(?:otp|one.time (?:code|password)|verification code|pin|password)\b/i.test(text)) {
    flags.push('This message may ask for an account code or credential.')
  }
  if (/\b(?:gift\s?cards?|wire transfer|crypto wallet|bitcoin|processing fee)\b/i.test(text)) {
    flags.push('This message mentions a payment method often used in scams.')
  }
  const urls = text.match(/https?:\/\/[^\s<>"']+/gi) ?? []
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
