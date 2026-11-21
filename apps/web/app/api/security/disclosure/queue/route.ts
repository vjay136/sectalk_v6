import {disclosureQueue} from '../../../../../lib/disclosure-intake-server'
export const runtime='nodejs'
export async function POST(request:Request) {return disclosureQueue(request)}
