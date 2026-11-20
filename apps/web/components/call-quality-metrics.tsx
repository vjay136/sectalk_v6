type Rate = { sampled: number; positive: number; percent: number }
export type CallQuality = { through: string; metrics: Record<string, number>; rates?: Record<string, Rate> }

const modes = [['direct', 'Direct calls'], ['meeting', 'Meetings']] as const
const labels = [
  ['setup:fast', 'Connected in under 2 seconds'],
  ['setup:moderate', 'Connected in 2 to under 5 seconds'],
  ['setup:slow', 'Connected in 5 seconds or more'],
  ['setup:failed', 'Connection setup failed'],
  ['relay:relayed', 'Relay used'],
  ['relay:non_relayed', 'Connection without relay'],
  ['recovery:recovered', 'Connection recovered'],
  ['recovery:failed', 'Connection recovery failed'],
  ['mos:below_2', 'Audio MOS proxy below 2'],
  ['mos:2_to_3', 'Audio MOS proxy from 2 to under 3'],
  ['mos:3_to_4', 'Audio MOS proxy from 3 to under 4'],
  ['mos:4_or_more', 'Audio MOS proxy of 4 or above'],
] as const
const rates = [
  ['join', 'Join success', 'connected', 'started'],
  ['relay', 'TURN relay use', 'relayed', 'measured routes'],
  ['ice_restart', 'Application ICE restart rate', 'restart requested', 'connected caller sessions'],
] as const

export function CallQualityMetrics({ quality }: { quality: CallQuality }) {
  return <section className="release-section" aria-labelledby="call-quality-title">
    <h3 id="call-quality-title">Call quality</h3>
    <p>Counts use completed UTC days before <time dateTime={quality.through}>{quality.through}</time>. Each daily outcome needs at least ten samples from five accounts and is rounded down to the nearest ten.</p>
    <p>Rates are rounded down to ten-point bands. ICE restarts count direct-call restart offers. Reconnects are counted separately. The audio Mean Opinion Score (MOS) proxy uses packet loss, jitter, and round-trip time with heuristic penalties and the ITU rating-to-MOS mapping. It estimates network conditions on a 1 to 4.5 scale.</p>
    {modes.map(([mode, title]) => {
      const counts = labels.flatMap(([key, label]) => {
        const count = quality.metrics[mode + ':' + key]
        return count === undefined ? [] : [{ key, label, count }]
      })
      return <section key={mode} aria-label={title}>
        <h4>{title}</h4>
        {quality.rates && <dl className="release-row" aria-label={title + ' quality rates'}>
          {rates.filter(([key]) => key !== 'ice_restart' || mode === 'direct').map(([key, label, positive, denominator]) => {
            const rate = quality.rates?.[mode + ':' + key]
            return <div className="release-board-item" key={key}>
              <dt>{label}</dt><dd>{rate ? `${rate.percent}% · ${rate.positive.toLocaleString()} ${positive} / ${rate.sampled.toLocaleString()} ${denominator}` : 'Below reporting threshold'}</dd>
            </div>
          })}
        </dl>}
        {counts.length > 0 ? <dl className="release-row" aria-label={title + ' quality counts'}>
          {counts.map(({ key, label, count }) => <div className="release-board-item" key={key}>
            <dt>{label}</dt><dd>{count.toLocaleString()}</dd>
          </div>)}
        </dl> : <p>Below reporting threshold</p>}
      </section>
    })}
  </section>
}
