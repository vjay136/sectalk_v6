import { OperatorConsole } from './operator-console'
import { freeFeatureCoverage } from '../lib/feature-coverage'

export default async function Page() {
  return <OperatorConsole features={await freeFeatureCoverage()}/>
}
