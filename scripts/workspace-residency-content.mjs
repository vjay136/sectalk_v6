import { createHash } from 'node:crypto'
import { pathToFileURL } from 'node:url'
import { parseArgs } from 'node:util'
import { residencyDatabaseOrigins, request } from './workspace-residency-files.mjs'

const uuid = /^[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$/
const digest = /^[0-9a-f]{64}$/

async function rpc(origin, rpcName, auth, body) {
  const response = await request(origin, '/rest/v1/rpc/' + rpcName, {
    method: 'POST',
    headers: { ...auth, 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  })
  if (!response.ok) {
    await response.body?.cancel()
    throw new Error(`Transfer RPC ${rpcName} refused the request (${response.status}).`)
  }
  return response.json()
}

export async function stageWorkspaceContent({ sourceDatabase, sourceProject, sourceKey, sourceSession,
  targetDatabase, targetProject, targetKey, cell, installationNonce, workspace, approval }) {
  const [source, target] = residencyDatabaseOrigins(sourceDatabase, targetDatabase, sourceProject, targetProject)
  if (source === target || ![cell, installationNonce, workspace, approval].every(value => uuid.test(value ?? '')) ||
    !/^[a-z0-9-]{1,80}$/.test(sourceProject ?? '') || ![sourceKey, sourceSession, targetKey].every(key => typeof key === 'string' && key) ||
    new Set([sourceKey, sourceSession, targetKey]).size !== 3 || sourceKey.startsWith('sb_secret_') || targetKey.startsWith('sb_publishable_') ||
    (source.startsWith('https:') && !sourceKey.startsWith('sb_publishable_'))) {
    throw new Error('Supply the exact source approval, separate target installation and scoped credentials for both projects.')
  }
  const sourceAuth = { apikey: sourceKey, Authorization: 'Bearer ' + sourceSession }
  const targetAuth = targetKey.startsWith('sb_secret_') ? { apikey: targetKey } : { apikey: targetKey, Authorization: 'Bearer ' + targetKey }
  const status = await rpc(source, 'st_v8_offboarding_content', sourceAuth, { p_workspace: workspace })
  if (status?.role !== 'owner' || status.id !== approval || !digest.test(status.manifestSha256 ?? '') ||
    !Number.isInteger(status.records) || status.records < 1 || status.records > 500 || !(Date.parse(status.expiresAt) > Date.now())) {
    throw new Error('The requested source manifest is not a current owner-approved export.')
  }

  const records = []
  while (records.length < status.records) {
    const after = records.length
    const page = await rpc(source, 'st_v8_offboarding_content', sourceAuth, {
      p_workspace: workspace, p_id: approval, p_confirmation: workspace, p_action: 'page', p_after: after,
    })
    const end = Math.min(after + 25, status.records)
    if (page?.id !== approval || page.manifestSha256 !== status.manifestSha256 ||
      page.next !== (end < status.records ? end : null) || page.records?.length !== end - after) {
      throw new Error('The source manifest changed while reading its pages.')
    }
    for (const record of page.records) {
      if (record.position !== records.length + 1 || typeof record.json !== 'string' ||
        createHash('sha256').update(record.json).digest('hex') !== record.sha256) {
        throw new Error('An approved source record was missing, reordered or changed.')
      }
      records.push(record)
    }
  }

  // Recheck current approval and both source roles before starting the target transaction.
  const final = await rpc(source, 'st_v8_offboarding_content', sourceAuth, { p_workspace: workspace })
  if (final?.role !== 'owner' || final.id !== approval || final.manifestSha256 !== status.manifestSha256 ||
    final.records !== status.records || !(Date.parse(final.expiresAt) > Date.now())) {
    throw new Error('The source approval expired or changed before transfer.')
  }
  const lastPage = await rpc(source, 'st_v8_offboarding_content', sourceAuth, {
    p_workspace: workspace, p_id: approval, p_confirmation: workspace,
    p_action: 'page', p_after: Math.floor((records.length - 1) / 25) * 25,
  })
  if (lastPage?.id !== approval || lastPage.manifestSha256 !== status.manifestSha256) {
    throw new Error('The source approval could not be confirmed before transfer.')
  }
  const receipt = await rpc(target, 'st_v8_stage_residency_content', targetAuth, {
    p_cell: cell, p_nonce: installationNonce, p_source: sourceProject,
    p_workspace: workspace, p_approval: approval, p_records: records,
  })
  if (receipt?.manifestSha256 !== status.manifestSha256 || receipt.count !== records.length || typeof receipt.staged !== 'boolean') {
    throw new Error('The target did not confirm the approved manifest.')
  }
  return receipt
}

if (process.argv[1] && pathToFileURL(process.argv[1]).href === import.meta.url) {
  try {
    const { values } = parseArgs({ options: {
      workspace: { type: 'string' }, approval: { type: 'string' }, cell: { type: 'string' },
    } })
    const receipt = await stageWorkspaceContent({ ...values,
      sourceDatabase: process.env.SECTALK_RESIDENCY_SOURCE_DATABASE, sourceProject: process.env.SECTALK_RESIDENCY_SOURCE_PROJECT,
      sourceKey: process.env.SECTALK_RESIDENCY_SOURCE_PUBLIC_KEY, sourceSession: process.env.SECTALK_RESIDENCY_SOURCE_SESSION,
      targetDatabase: process.env.SECTALK_RESIDENCY_TARGET_DATABASE, targetKey: process.env.SECTALK_RESIDENCY_TARGET_KEY,
      targetProject: process.env.SECTALK_RESIDENCY_TARGET_PROJECT,
      installationNonce: process.env.SECTALK_RESIDENCY_INSTALLATION_NONCE,
    })
    console.log(JSON.stringify(receipt))
  } catch (error) {
    console.error(error.message)
    process.exitCode = 1
  }
}
