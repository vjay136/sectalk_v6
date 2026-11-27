import { readFile } from 'node:fs/promises'
import { resolve } from 'node:path'

export type FeatureCoverage = { id: string; name: string; role: string; surface: string; signal: string; implemented: boolean }

const optional = new Set(['AUTH-05', 'ORG-08', 'ORG-09', 'SEC-04', 'PLAT-13'])

export async function freeFeatureCoverage(): Promise<FeatureCoverage[]> {
  const matrix = await readFile(resolve(process.cwd(), '../../docs/FEATURE_MATRIX.md'), 'utf8')
  const features = matrix.split(/\r?\n/).flatMap(line => {
    if (!/^\| [A-Z]+-\d{2} \| /.test(line)) return []
    const [, id, name, role, surface, , signal, , status] = line.split(/(?<!\\)\|/).map(value => value.trim())
    if (optional.has(id)) return []
    return [{ id, name, role, surface, signal, implemented: status === 'DONE' }]
  })
  if (features.length !== 234 || new Set(features.map(item => item.id)).size !== features.length) {
    throw new Error('The SecTalk Free feature inventory is incomplete')
  }
  return features
}
