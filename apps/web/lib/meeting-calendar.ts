type CalendarMeeting={id:string;title:string;starts_at:string;ends_at:string}
const meetingId=/^[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$/i

export function meetingFromQuery(query:string){
  const value=new URLSearchParams(query).get('meeting')
  return value&&meetingId.test(value)?value:null
}

export function meetingLink(origin:string,id:string){
  const url=new URL('/',origin)
  url.searchParams.set('meeting',id)
  return url.href
}

function calendarTime(value:string|Date){
  return new Date(value).toISOString().replace(/[-:]/g,'').replace(/\.\d{3}Z$/,'Z')
}

function calendarText(value:string){
  return value.replace(/\\/g,'\\\\').replace(/\r\n|\r|\n/g,'\\n').replace(/[,;]/g,match=>'\\'+match)
    .replace(/[\u0000-\u0008\u000b-\u001f\u007f]/g,'')
}

function fold(line:string){
  const encoder=new TextEncoder()
  let output=''
  let length=0
  for(const character of line){
    const bytes=encoder.encode(character).length
    if(length+bytes>75){output+='\r\n ';length=1}
    output+=character
    length+=bytes
  }
  return output
}

export function meetingCalendar(meetings:CalendarMeeting[],origin:string,now=new Date()){
  const stamp=calendarTime(now)
  const host=new URL(origin).hostname
  return ['BEGIN:VCALENDAR','VERSION:2.0','PRODID:-//Eagle Security//SecTalk Meetings//EN','CALSCALE:GREGORIAN',
    ...meetings.flatMap(meeting=>{
      const link=meetingLink(origin,meeting.id)
      return ['BEGIN:VEVENT','UID:'+meeting.id+'@'+host,'DTSTAMP:'+stamp,'DTSTART:'+calendarTime(meeting.starts_at),
        'DTEND:'+calendarTime(meeting.ends_at),'SUMMARY:'+calendarText(meeting.title),
        'URL:'+link,'DESCRIPTION:'+calendarText('Join in SecTalk: '+link),'END:VEVENT']
    }),'END:VCALENDAR',''].map(fold).join('\r\n')
}
