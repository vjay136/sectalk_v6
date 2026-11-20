import { evaluateImpersonationRules, impersonationFixtureVersion } from '../apps/web/lib/impersonation-rule-evaluation.mjs'
import { impersonationRuleVersions } from '../apps/web/lib/impersonation.mjs'

const [active, shadow] = process.argv.length > 2 ? process.argv.slice(2) : impersonationRuleVersions
console.log(JSON.stringify({ corpus: impersonationFixtureVersion, active, shadow,
  metrics: evaluateImpersonationRules(active, shadow) }, null, 2))
