class VoiceNotePcm extends AudioWorkletProcessor {
  constructor() {
    super()
    this.bytes=new ArrayBuffer(sampleRate*30*2)
    this.samples=new DataView(this.bytes)
    this.offset=0
    this.done=false
    this.port.onmessage=event=>{if(event.data==='stop') this.finish()}
  }

  finish() {
    if(this.done) return
    this.done=true
    const audio=this.bytes.slice(0,this.offset)
    this.port.postMessage(audio,[audio])
  }

  process(inputs) {
    const audio=inputs[0]?.[0]
    if(this.done || !audio) return !this.done
    for (const sample of audio) {
      this.samples.setInt16(this.offset,Math.max(-1,Math.min(1,sample))*32767,true)
      this.offset+=2
      if(this.offset===this.bytes.byteLength) {this.finish();return false}
    }
    return true
  }
}

registerProcessor('voice-note-pcm',VoiceNotePcm)
