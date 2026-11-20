export const voiceSampleRate=16000
export const maxVoiceBytes=voiceSampleRate*2*30

export function voiceWaveform(pcm:Uint8Array) {
  const samples=new DataView(pcm.buffer,pcm.byteOffset,pcm.byteLength)
  const count=pcm.byteLength/2
  return Array.from({length:24},(_,index)=>{
    const start=Math.floor(index*count/24)
    const end=Math.floor((index+1)*count/24)
    let peak=0
    for(let frame=start;frame<end;frame++) peak=Math.max(peak,Math.abs(samples.getInt16(frame*2,true)))
    return Math.min(100,Math.round(peak/327.68))
  })
}

export function voiceWave(pcm:Uint8Array) {
  const wave=new Uint8Array(44+pcm.length)
  const view=new DataView(wave.buffer)
  const ascii=(offset:number,value:string)=>wave.set(new TextEncoder().encode(value),offset)
  ascii(0,'RIFF')
  view.setUint32(4,36+pcm.length,true)
  ascii(8,'WAVEfmt ')
  view.setUint32(16,16,true)
  view.setUint16(20,1,true)
  view.setUint16(22,1,true)
  view.setUint32(24,voiceSampleRate,true)
  view.setUint32(28,voiceSampleRate*2,true)
  view.setUint16(32,2,true)
  view.setUint16(34,16,true)
  ascii(36,'data')
  view.setUint32(40,pcm.length,true)
  wave.set(pcm,44)
  return wave
}
