import type { Metadata } from 'next'
import { GuestMeeting } from '../../components/guest-meeting'

export const metadata:Metadata={
  title:'Guest meeting · SecTalk',
  robots:{index:false,follow:false},
}

export default function MeetingGuestPage() {
  return <GuestMeeting/>
}
