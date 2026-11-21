export function isReportTicket(value: unknown): value is string {
  return typeof value==='string' && /^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/i.test(value)
}

export function ReportTicket({ id }: { id: string }) {
  return <small>Ticket <code style={{overflowWrap:'anywhere'}}>{id}</code></small>
}

const dateTime=new Intl.DateTimeFormat(undefined,{dateStyle:'medium',timeStyle:'short'})

export function ReportTime({value}:{value:string}) {
  return <time dateTime={value}>{dateTime.format(new Date(value))}</time>
}
