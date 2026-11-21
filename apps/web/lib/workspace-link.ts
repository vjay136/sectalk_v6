const workspaceId=/^[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$/i
const ssoLinkKey='sectalk.workspace-sign-in-link.v1'

export function workspaceLink(search:string):{id:string|null}|null {
  const values=new URLSearchParams(search).getAll('workspace')
  if(!values.length)return null
  return {id:values.length===1&&workspaceId.test(values[0])?values[0].toLowerCase():null}
}

export function clearWorkspaceLink() {
  const url=new URL(window.location.href)
  if(!url.searchParams.has('workspace'))return
  url.searchParams.delete('workspace')
  window.history.replaceState(window.history.state,'',url.pathname+url.search+url.hash)
}

export function rememberWorkspaceSsoLink(search:string) {
  try {
    const link=workspaceLink(search)
    if(link)sessionStorage.setItem(ssoLinkKey,new URLSearchParams({workspace:link.id??''}).toString())
    else sessionStorage.removeItem(ssoLinkKey)
  }catch{/* The workspace switcher remains available. */}
}

export function takeWorkspaceSsoLink() {
  try {
    const link=workspaceLink(sessionStorage.getItem(ssoLinkKey)??'')
    sessionStorage.removeItem(ssoLinkKey)
    if(link)return '/?'+new URLSearchParams({workspace:link.id??''}).toString()
  }catch{/* Continue with normal sign-in. */}
  return '/'
}
