const marker = /\[\[st:([^\[\]|\s]{1,32})\|([^\[\]|\s]{1,32})\]\]/gu
const emojiSequence = /^[\p{Extended_Pictographic}\p{Regional_Indicator}\p{Emoji_Modifier}\u200d\ufe0f\u20e3\u{e0020}-\u{e007f}0-9#*]+$/u

export function EmojiText({ value }: { value:string }) {
  const parts = value.split(marker)
  return <>{parts.map((part,index)=>{
    if(index%3===0) return part
    if(index%3===2) return null
    const badge=parts[index+1]
    if(!emojiSequence.test(part)||!emojiSequence.test(badge)) return '[[st:'+part+'|'+badge+']]'
    return <span className="custom-emoji" key={index} role="img" aria-label={part+' with '+badge}>
      <span aria-hidden="true">{part}</span><small aria-hidden="true">{badge}</small>
    </span>
  })}</>
}
