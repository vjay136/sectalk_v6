import type { ReactNode } from 'react'

export function CountBadge({count}: {count: number}) {
  return count > 0 ? <span className="tab-count" aria-hidden="true">{count > 99 ? '99+' : count}</span> : null
}

export function SectionTabs<T extends string>({ label, value, onChange, options, inline = false }: {
  label: string
  value: T
  onChange: (value: T) => void
  options: ReadonlyArray<readonly [T, ReactNode]>
  inline?: boolean
}) {
  return <div className={'tabs release-tabs section-tabs'+(inline?'':' portrait-tabs')} role="group" aria-label={label}>
    {options.map(([id, name]) => <button key={id} type="button"
      aria-pressed={value === id} className={value === id ? 'active' : ''}
      onClick={() => onChange(id)}>{name}</button>)}
  </div>
}
