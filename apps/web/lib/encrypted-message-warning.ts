export function encryptedMessageWarning(text: string): string | null {
  const normalized = text.normalize('NFKC').replace(/\p{Cf}/gu, '').replace(/\s+/g, ' ').toLowerCase()
  const solicits = /\b(?:send|share|give|provide|tell|enter|reply with|confirm)\b[^.!?]{0,70}\b(?:password|one[- ]time code|verification code|recovery phrase|seed phrase|private key)\b/
  if (solicits.test(normalized)) return 'This message may ask for a password, security code, or recovery key.'
  const urgent = /\b(?:immediately|urgent|act now|within \d+ (?:minutes|hours)|last chance)\b/
  const payment = /\b(?:gift cards?|bank transfer|wire transfer|pay in crypto|send bitcoin)\b/
  if (urgent.test(normalized) && payment.test(normalized)) return 'This message may pressure you to send money.'
  return null
}
