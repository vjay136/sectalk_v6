'use client'

import { useState } from 'react'

export function Avatar({ name, tint = 'green', photo, className = '' }: {
  name: string; tint?: string; photo?: string; className?: string
}) {
  const [loadedPhoto, setLoadedPhoto] = useState<string>()
  const initials = name.trim().split(/\s+/).slice(0, 2).map(word => [...word][0]).join('').toUpperCase()
  return <span className={`avatar ${tint} ${className}`} aria-hidden="true">
    {initials || '?'}
    {photo && <img key={photo} src={photo} alt="" width={42} height={42}
      className={loadedPhoto===photo?'loaded':''}
      onLoad={()=>setLoadedPhoto(photo)}
      onError={()=>setLoadedPhoto(previous=>previous===photo?undefined:previous)}/>}
  </span>
}
