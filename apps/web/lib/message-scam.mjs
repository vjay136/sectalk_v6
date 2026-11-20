import { normalizeSafetyMessage } from './safety.mjs'

export const scamClassifierVersion = 'scam-rules-1'

const codeRequest = /(?<!\b(?:never|don't|do not|not|shouldn't) )\b(?:send(?: me| us)?|share|forward|tell me|reply with|enter|type|provide)\b.{0,36}\b(?:one.time (?:code|password)|verification code|security code|otp|password|recovery phrase)\b/i
const paymentRequest = /\b(?:send|wire|transfer) (?:me |us )?(?:money|cash|funds|crypto|bitcoin|\$\d+)|\b(?:pay|cover)\b.{0,28}\b(?:fee|deposit|bill|costs?)\b/i
/** @type {{category: import('./safety.mjs').ThreatCategory, confidence: number, requiresLink: boolean, signals: [RegExp, string][] }[]} */
const rules = [
  {
    category:'phishing', confidence:0.78, requiresLink:true,
    signals:[
      [/\b(?:account (?:is |has been |will be )?(?:locked|suspended|disabled)|unusual (?:activity|sign.in)|verify your (?:account|identity))\b/i, 'It claims there is an account issue or asks for account verification.'],
      [/\b(?:click|open|follow|visit|sign in|log in|verify|confirm|update)\b/i, 'It directs you to act using a link in the message.'],
    ],
  },
  {
    category:'credential_harvesting', confidence:0.84, requiresLink:false,
    signals:[
      [codeRequest, 'It asks for a password, account code, or recovery phrase.'],
    ],
  },
  {
    category:'romance_scam', confidence:0.70, requiresLink:false,
    signals:[
      [/\b(?:i love you|my love|my darling|sweetheart|my soulmate|our future together)\b/i, 'It uses language associated with a close romantic relationship.'],
      [/\b(?:emergency|medical bills?|hospital|plane ticket|flight home|stranded)\b/i, 'It mentions urgent travel, medical costs, or an emergency.'],
      [paymentRequest, 'It asks for money or payment of a fee.'],
    ],
  },
  {
    category:'investment_scam', confidence:0.81, requiresLink:false,
    signals:[
      [/\b(?:invest(?:ment|ing)?|trading|crypto platform|forex)\b/i, 'It promotes an investment or trading opportunity.'],
      [/\b(?:guaranteed (?:returns?|profits?|gains?)|risk.free (?:returns?|profits?|investments?)|double your money|no risk)\b/i, 'It promises returns or claims there is no risk.'],
      [/\b(?:deposit|sign up|join|buy in|send|transfer|pay|start investing)\b/i, 'It urges you to join or commit funds.'],
    ],
  },
  {
    category:'job_scam', confidence:0.78, requiresLink:false,
    signals:[
      [/\b(?:job offer|hiring|recruiter|remote job|work from home|product boosting)\b/i, 'It offers work or claims to be recruiting.'],
      [paymentRequest, 'It asks you to pay a fee or send money in order to proceed.'],
    ],
  },
  {
    category:'delivery_scam', confidence:0.79, requiresLink:true,
    signals:[
      [/\b(?:package|parcel|delivery|shipment)\b/i, 'It presents itself as a delivery notice.'],
      [/\b(?:undeliverable|failed delivery|missed delivery|redelivery|address (?:is )?(?:incomplete|incorrect)|held at (?:the )?(?:depot|post office))\b/i, 'It claims a delivery failed or needs action.'],
      [/\b(?:update|confirm|verify|pay|reschedule)\b/i, 'It asks you to confirm details, act on a delivery, or pay using the link.'],
    ],
  },
  {
    category:'tech_support_scam', confidence:0.82, requiresLink:false,
    signals:[
      [/\b(?:tech support|technical support|support agent|your computer (?:has|is)|(?:computer|device) (?:has been )?(?:infected|compromised))\b/i, 'It claims to offer technical support or reports a device problem.'],
      [/\b(?:(?:give|grant|allow|enable) (?:me |us )?remote access|(?:install|download|open) (?:anydesk|teamviewer|remote support)|pay\b.{0,24}\b(?:support fee|repair fee))\b/i, 'It requests remote access, support software, or a repair payment.'],
    ],
  },
  {
    category:'prize_scam', confidence:0.82, requiresLink:false,
    signals:[
      [/\b(?:(?:you(?:'ve| have)? won|selected for|claim your|collect your) (?:a |the )?(?:prize|lottery|jackpot|sweepstakes)|lottery winner)\b/i, 'It claims you won or can claim a prize.'],
      [paymentRequest, 'It asks you to pay money to receive the prize.'],
    ],
  },
  {
    category:'impersonation', confidence:0.81, requiresLink:false,
    signals:[
      [/\b(?:i(?:'m| am) (?:the |your )?(?:ceo|cfo|boss|manager|finance director)|on behalf of (?:the |your )?(?:ceo|cfo|boss))\b/i, 'It claims authority from an executive or manager.'],
      [/\b(?:(?:change|update|use|new).{0,20}(?:bank details|bank account|payment instructions)|(?:wire|transfer) (?:the )?(?:payment|funds|money)|(?:pay|settle) (?:the |this )?invoice)\b/i, 'It asks for a payment or a change to payment instructions.'],
      [/\b(?:urgent|immediately|confidential|keep this (?:private|between us)|today|do not call|don'?t call)\b/i, 'It combines the request with urgency or secrecy.'],
    ],
  },
]

/** @param {string} text */
function hasWebLink(text) {
  return (text.match(/https?:\/\/[^\s<>"']+/gi) ?? []).some(raw => {
    try { return !!new URL(raw).hostname } catch { return false }
  })
}

/**
 * Inspect bounded, normalized text without requesting URLs or sending data.
 * Confidence describes the rule match strength.
 * @param {string} text
 */
export function classifyScamMessage(text) {
  const normalized = normalizeSafetyMessage(text)
  const linked = hasWebLink(normalized)
  return rules
    .filter(rule => (!rule.requiresLink || linked) && rule.signals.every(([pattern]) => pattern.test(normalized)))
    .map(({category,confidence,signals}) => ({
      category, confidence, reasons:signals.map(([,reason]) => reason), modelVersion:scamClassifierVersion,
    }))
    .sort((a,b) => b.confidence-a.confidence)
}
