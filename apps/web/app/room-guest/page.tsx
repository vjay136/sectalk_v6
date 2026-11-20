import type { Metadata } from 'next'
import { GuestRoom } from '../../components/guest-room'

export const metadata:Metadata={title:'Guest room · SecTalk',robots:{index:false,follow:false}}

export default function RoomGuestPage() {
  return <GuestRoom/>
}
