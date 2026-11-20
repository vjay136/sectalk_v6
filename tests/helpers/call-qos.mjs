import assert from 'node:assert/strict'
import { setTimeout as delay } from 'node:timers/promises'

export function watchCallQos(page, mode) {
  const observed = new Map()
  page.on('response', response => {
    if (!response.url().endsWith('/rpc/st_v6_report_call_qos')) return
    const payload = response.request().postDataJSON()
    if (payload.p_mode === mode) {
      const item = { payload, response }
      if (!observed.has(payload.p_metric)) observed.set(payload.p_metric, item)
      observed.set(payload.p_metric + ':' + payload.p_bucket, item)
    }
  })
  return async function sample(metric, bucket, requireAccepted = true) {
    const key = bucket ? metric + ':' + bucket : metric
    const deadline = Date.now() + 15_000
    while (!observed.has(key) && Date.now() < deadline) await delay(50)
    assert.ok(observed.has(key), 'Missing ' + mode + ' ' + key + ' quality sample')
    const { payload, response } = observed.get(key)
    assert.deepEqual(Object.keys(payload).sort(), ['p_bucket', 'p_device', 'p_metric', 'p_mode', 'p_resource'])
    assert.equal(response.status(), 200)
    if (requireAccepted) assert.equal(await response.json(), true)
    return payload.p_bucket
  }
}
