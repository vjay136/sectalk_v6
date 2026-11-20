export type ReputationLinkProof = { challenge: string; owner: string; device: string; session: string; alias: string; signing: string }

export function reputationLinkTranscript(proof: ReputationLinkProof) {
  return new TextEncoder().encode(JSON.stringify(['sectalk-approved-browser-link-v1', proof.challenge,
    proof.owner, proof.device, proof.session, proof.alias, proof.signing]))
}
