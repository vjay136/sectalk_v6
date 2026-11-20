import {argon2,randomBytes} from 'node:crypto'
import {promisify} from 'node:util'

const derive=promisify(argon2)
const memory=19456
const passes=2
const parallelism=1
const base64=value=>value.toString('base64').replace(/=+$/,'')

export async function signupPasswordHash(password) {
  const message=Buffer.from(password,'utf8')
  const nonce=randomBytes(16)
  try {
    const hash=await derive('argon2id',{message,nonce,memory,passes,parallelism,tagLength:32})
    try {
      return `$argon2id$v=19$m=${memory},t=${passes},p=${parallelism}$${base64(nonce)}$${base64(hash)}`
    } finally {
      hash.fill(0)
    }
  } finally {
    message.fill(0)
  }
}
