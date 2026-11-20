const inviteKey='sectalk.workspace-invite.v1'
const validToken=/^[0-9a-f]{48}$/

export function rememberWorkspaceInvite(token:string){
  if(!validToken.test(token))return false
  try{sessionStorage.setItem(inviteKey,token);return true}
  catch{return false}
}

export function pendingWorkspaceInvite(){
  try{
    const token=sessionStorage.getItem(inviteKey)
    return token&&validToken.test(token)?token:null
  }catch{return null}
}

export function clearWorkspaceInvite(){
  try{sessionStorage.removeItem(inviteKey)}catch{/* The invitation remains single-use on the server. */}
}
