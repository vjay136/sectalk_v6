import {submitDisclosure} from '../../../../lib/disclosure-intake-server'
export const runtime='nodejs'
export async function POST(request:Request) {return submitDisclosure(request)}
