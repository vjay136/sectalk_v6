import { randomUUID } from 'node:crypto'

const uuid = /^[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$/i

export function workerAcquisitionId(request: Request) {
  const provided = request.headers.get('Idempotency-Key')
  return provided === null ? randomUUID() : uuid.test(provided) ? provided : null
}
