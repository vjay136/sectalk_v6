function records(value) {
  if (typeof value !== 'string' || value.length > 4096) return null
  try {
    const parsed = JSON.parse(value)
    return Array.isArray(parsed) && parsed.length > 0 && parsed.length <= 32 ? parsed : null
  } catch {
    return null
  }
}

export function cloudTrailKeyMaterialEvidence(details) {
  if (details == null) return []
  if (typeof details !== 'object' || Array.isArray(details)) return null
  const storeTypes = [details.keyStoreType,details.customKeyStoreType].filter(type => type !== undefined)
  if (storeTypes.some(type => type !== 'AWS_CLOUDHSM')
    || 'xksKeyId' in details || 'XksKeyId' in details || 'externalKeyId' in details) return null

  const {customKeyStoreId,clusterId,backingKeys,backingKeysDeletionStatus} = details
  if (storeTypes.length === 0 && customKeyStoreId === undefined && clusterId === undefined
    && backingKeys === undefined && backingKeysDeletionStatus === undefined) return []
  if (typeof customKeyStoreId !== 'string' || !/^cks-[A-Za-z0-9]+$/.test(customKeyStoreId)
    || typeof clusterId !== 'string' || !/^cluster-[A-Za-z0-9]+$/.test(clusterId)) return null

  const keys = records(backingKeys)
  const results = records(backingKeysDeletionStatus)
  if (!keys || !results || keys.length !== results.length) return null
  const ids = keys.map(entry => entry?.backingKeyId)
  if (ids.some(id => typeof id !== 'string' || !id || id.length > 256) || new Set(ids).size !== ids.length) return null
  const deleted = new Set()
  for (const result of results) {
    const id = result?.backingKeyId
    if (result?.deletionStatus !== 'SUCCESS' || !ids.includes(id) || deleted.has(id)) return null
    deleted.add(id)
  }
  return [customKeyStoreId,clusterId,ids.sort()]
}
