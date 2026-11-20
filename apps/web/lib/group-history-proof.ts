const encoder=new TextEncoder()

export type GroupHistoryEnvelope={epoch:number;sealed:string;ephemeral:string}
export type GroupHistoryProof={nonce:string;group:string;source:string;target:string}

export function groupHistoryTranscript(proof:GroupHistoryProof,envelopes:GroupHistoryEnvelope[]){
  return encoder.encode(JSON.stringify(['sectalk-group-history-v1',proof.nonce,proof.group,proof.source,proof.target,
    envelopes.map(envelope=>[envelope.epoch,envelope.ephemeral,envelope.sealed])]))
}
