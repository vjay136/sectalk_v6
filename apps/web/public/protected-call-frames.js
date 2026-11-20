// SecTalk v1 direct-call encoding. The codec prefix is authenticated and used by RTP packetization.
const version=1
let counter=0n
const replayWindow=512n

function nonce(sequence) {
  const result=new Uint8Array(12)
  new DataView(result.buffer).setBigUint64(4,sequence)
  return result
}

function prefixLength(data,kind) {
  if (kind==='audio') return 1
  return (data[0]&1)===0 ? 10 : 3
}

self.onrtctransform=event=>{
  const {readable,writable,options}=event.transformer
  const {op,kind,key}=options
  const encrypt=op==='encrypt'
  const marker=kind==='audio'?1:2
  let highest=0n
  const seen=new Set()
  let announced=false
  readable.pipeThrough(new TransformStream({
    async transform(frame,controller) {
      const data=new Uint8Array(frame.data)
      const prefix=prefixLength(data,kind)
      const start=prefix+10
      if (data.length<=prefix) return
      if (encrypt) {
        if (counter>=0xffffffffffffffffn) { self.postMessage({type:'error'}); return }
        const sequence=++counter
        const header=new Uint8Array(start)
        header.set(data.subarray(0,prefix))
        header[prefix]=version
        header[prefix+1]=marker
        new DataView(header.buffer).setBigUint64(prefix+2,sequence)
        const encrypted=await crypto.subtle.encrypt({name:'AES-GCM',iv:nonce(sequence),additionalData:header},key,data.subarray(prefix))
        const result=new Uint8Array(header.length+encrypted.byteLength)
        result.set(header)
        result.set(new Uint8Array(encrypted),header.length)
        frame.data=result.buffer
        controller.enqueue(frame)
        return
      }
      if (data.length<=start+16 || data[prefix]!==version || data[prefix+1]!==marker) return
      const sequence=new DataView(data.buffer).getBigUint64(prefix+2)
      if (sequence===0n || sequence+replayWindow<=highest || seen.has(sequence)) return
      try {
        const decrypted=await crypto.subtle.decrypt({name:'AES-GCM',iv:nonce(sequence),additionalData:data.subarray(0,start)},key,data.subarray(start))
        if (sequence>highest) {
          highest=sequence
          for (const previous of seen) if (previous+replayWindow<=highest) seen.delete(previous)
        }
        seen.add(sequence)
        const result=new Uint8Array(prefix+decrypted.byteLength)
        result.set(data.subarray(0,prefix))
        result.set(new Uint8Array(decrypted),prefix)
        frame.data=result.buffer
        controller.enqueue(frame)
        if (!announced) {
          announced=true
          self.postMessage({type:'decoded',kind})
        }
      } catch {
        // Invalid frames are dropped without a plaintext or compatibility path.
      }
    },
  })).pipeTo(writable).catch(()=>self.postMessage({type:'error'}))
}
