const extensionMime:Record<string,string>={
  png:'image/png',jpg:'image/jpeg',jpeg:'image/jpeg',webp:'image/webp',gif:'image/gif',pdf:'application/pdf',txt:'text/plain',
}

export function sniffFileType(bytes:Buffer):string|null{
  if(!bytes.length)return null
  if(bytes.length>=45&&bytes.subarray(0,8).equals(Buffer.from([137,80,78,71,13,10,26,10]))&&
    bytes.toString('latin1',12,16)==='IHDR'&&bytes.toString('latin1',bytes.length-8,bytes.length-4)==='IEND')return 'image/png'
  if(bytes.length>=6&&bytes[0]===255&&bytes[1]===216&&bytes[2]===255&&bytes.at(-2)===255&&bytes.at(-1)===217)return 'image/jpeg'
  if(bytes.length>=20&&bytes.toString('latin1',0,4)==='RIFF'&&bytes.readUInt32LE(4)===bytes.length-8&&
    bytes.toString('latin1',8,12)==='WEBP'&&['VP8 ','VP8L','VP8X'].includes(bytes.toString('latin1',12,16)))return 'image/webp'
  if(bytes.length>=14&&['GIF87a','GIF89a'].includes(bytes.toString('latin1',0,6))&&bytes.at(-1)===59)return 'image/gif'
  if(/^%PDF-[12]\.\d/.test(bytes.toString('latin1',0,12))&&/%%EOF[\t\r\n ]*$/.test(bytes.subarray(-1024).toString('latin1')))return 'application/pdf'
  try{
    const text=new TextDecoder('utf-8',{fatal:true}).decode(bytes)
    return /[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f-\u009f]/u.test(text)?null:'text/plain'
  }catch{return null}
}

export function allowedFileType(filename:string,declared:string,bytes:Buffer){
  const extension=filename.toLowerCase().match(/\.([a-z]+)$/)?.[1]
  const expected=extension?extensionMime[extension]:undefined
  if(!expected)return false
  const supplied=declared.trim().toLowerCase().split(';',1)[0]
  if(supplied&&supplied!=='application/octet-stream'&&supplied!==expected)return false
  return sniffFileType(bytes)===expected
}
