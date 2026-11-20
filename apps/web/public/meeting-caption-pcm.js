class MeetingCaptionPcm extends AudioWorkletProcessor {
  constructor() {
    super()
    this.reset()
  }

  reset() {
    this.buffer = new ArrayBuffer(sampleRate * 4 * 2)
    this.samples = new DataView(this.buffer)
    this.offset = 0
    this.peak = 0
  }

  process(inputs) {
    const channel = inputs[0]?.[0]
    if (!channel) return true
    for (const value of channel) {
      const sample = Math.max(-1, Math.min(1,value))
      this.peak = Math.max(this.peak,Math.abs(sample))
      this.samples.setInt16(this.offset,sample*32767,true)
      this.offset += 2
      if (this.offset===this.buffer.byteLength) {
        if (this.peak>0.008) this.port.postMessage(this.buffer,[this.buffer])
        this.reset()
      }
    }
    return true
  }
}

registerProcessor('meeting-caption-pcm',MeetingCaptionPcm)
